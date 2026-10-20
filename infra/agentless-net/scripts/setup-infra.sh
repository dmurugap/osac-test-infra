#!/usr/bin/env bash
#
# Install prerequisites and cache the SNO snapshot flavor.
# Idempotent — safe to re-run.
#
set -euo pipefail

MGMT_IMAGE="${MGMT_IMAGE:-quay.io/osac-project/cluster-flavors:sno-4-22}"
FLAVOR_NAME="sno-4-22"
CLUSTER_TOOL_REPO="${CLUSTER_TOOL_REPO:-https://github.com/osac-project/cluster-tool.git}"
CLUSTER_TOOL_REF="${CLUSTER_TOOL_REF:-main}"
CLUSTER_TOOL_DIR="${CLUSTER_TOOL_DIR:-/opt/cluster-tool}"
CLUSTER_TOOL_BIN="${CLUSTER_TOOL_BIN:-/usr/local/bin/cluster-tool}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"

info() { echo "==> $*"; }

install_client_tools() {
    # oc, helm, and the osac CLI are required by later targets. Reuse the
    # pinned installers in machine-init rather than a second copy.
    if ! command -v jq >/dev/null 2>&1; then
        dnf install -y jq
    fi
    local init="${REPO_ROOT}/scripts/machine-init.sh"
    if [[ ! -f "${init}" ]]; then
        echo "ERROR: ${init} not found; cannot install oc, helm, and osac" >&2
        exit 1
    fi
    if (( EUID != 0 )); then
        echo "ERROR: setup-infra must run as root to install oc, helm, and osac" >&2
        exit 1
    fi
    "${init}" oc helm osac
}

install_cluster_tool() {
    if [[ -x "${CLUSTER_TOOL_BIN}" ]]; then
        info "cluster-tool already installed at ${CLUSTER_TOOL_BIN}"
    else
        info "Installing cluster-tool from ${CLUSTER_TOOL_REPO}@${CLUSTER_TOOL_REF}"
        if ! command -v git >/dev/null 2>&1; then
            dnf install -y git
        fi
        if ! command -v python3 >/dev/null 2>&1; then
            dnf install -y python3
        fi
        if [[ ! -d "${CLUSTER_TOOL_DIR}/.git" ]]; then
            rm -rf "${CLUSTER_TOOL_DIR}"
            git clone --branch "${CLUSTER_TOOL_REF}" --depth 1 "${CLUSTER_TOOL_REPO}" "${CLUSTER_TOOL_DIR}"
        fi
        install -m 0755 "${CLUSTER_TOOL_DIR}/cluster-tool" "${CLUSTER_TOOL_BIN}"
    fi
    # sudo secure_path does not include /usr/local/bin.
    if [[ "${CLUSTER_TOOL_BIN}" != /usr/bin/cluster-tool ]]; then
        ln -sfn "${CLUSTER_TOOL_BIN}" /usr/bin/cluster-tool
    fi
    if ! "${CLUSTER_TOOL_BIN}" servers 2>/dev/null | grep -q "local"; then
        info "Setting up cluster-tool local server..."
        "${CLUSTER_TOOL_BIN}" connect local --host local --data-path /var/lib/cluster-tool
        sudo "${CLUSTER_TOOL_BIN}" setup client
    else
        info "cluster-tool already configured"
    fi
}

stage_registry_auth() {
    local pull_secret="${OSAC_PULL_SECRET_PATH:-/root/pull-secret}"
    if [[ ! -f "${pull_secret}" ]]; then
        info "No pull secret at ${pull_secret}; flavor pull uses existing registry credentials"
        return 0
    fi
    info "Staging registry credentials for the private flavor image"
    mkdir -p /root/.docker /root/.config/containers
    install -m 600 "${pull_secret}" /root/.docker/config.json
    install -m 600 "${pull_secret}" /root/.config/containers/auth.json
    if [[ "${HOME}" != /root ]]; then
        mkdir -p "${HOME}/.docker" "${HOME}/.config/containers"
        install -m 600 "${pull_secret}" "${HOME}/.docker/config.json"
        install -m 600 "${pull_secret}" "${HOME}/.config/containers/auth.json"
    fi
}

# ---------- Docker (needed by containerlab) ----------

if ! command -v docker &>/dev/null; then
    info "Installing Docker..."
    dnf install -y dnf-plugins-core
    dnf config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo
    dnf install -y docker-ce docker-ce-cli containerd.io
    systemctl enable --now docker
else
    info "Docker already installed"
fi

# ---------- Containerlab ----------

if ! command -v containerlab &>/dev/null; then
    info "Installing containerlab..."
    bash -c "$(curl -sL https://get.containerlab.dev)"
else
    info "Containerlab already installed"
fi

# ---------- KVM / libvirt ----------

if ! command -v virsh &>/dev/null; then
    info "Installing libvirt/KVM..."
    dnf install -y qemu-kvm libvirt virt-install
    systemctl enable --now libvirtd
else
    info "libvirt already installed"
fi

# ---------- Ansible ----------

if ! command -v ansible-playbook &>/dev/null; then
    info "Installing Ansible..."
    dnf install -y ansible-core
fi

# ---------- oc, helm, osac CLI, cluster-tool ----------

install_client_tools
install_cluster_tool

# ---------- Other tools ----------

for tool in sshpass envsubst jq; do
    if ! command -v "$tool" &>/dev/null; then
        info "Installing ${tool}..."
        dnf install -y "$tool" || pip3 install "$tool" 2>/dev/null || true
    fi
done

# ---------- Docker iptables workaround ----------
#
# Docker sets the iptables FORWARD chain policy to DROP.
# Libvirt creates NAT rules in nftables, but iptables and nftables are
# evaluated independently — Docker's DROP overrides libvirt's ACCEPT,
# leaving VMs with no internet access.

if iptables -S FORWARD 2>/dev/null | grep -q "\-P FORWARD DROP"; then
    if ! iptables -C FORWARD -s 192.168.0.0/16 -j ACCEPT 2>/dev/null; then
        info "Adding iptables FORWARD rules for libvirt VMs..."
        iptables -I FORWARD -s 192.168.0.0/16 -j ACCEPT
        iptables -I FORWARD -d 192.168.0.0/16 -j ACCEPT
        iptables -I FORWARD -s 10.0.0.0/8 -j ACCEPT
        iptables -I FORWARD -d 10.0.0.0/8 -j ACCEPT
    fi
fi

# ---------- Pull snapshot flavor ----------

stage_registry_auth
if "${CLUSTER_TOOL_BIN}" flavors 2>/dev/null | grep -q "$FLAVOR_NAME"; then
    info "Snapshot flavor '${FLAVOR_NAME}' already cached"
else
    info "Pulling snapshot flavor '${FLAVOR_NAME}'..."
    "${CLUSTER_TOOL_BIN}" pull "$MGMT_IMAGE"
fi

info "setup-infra complete."
