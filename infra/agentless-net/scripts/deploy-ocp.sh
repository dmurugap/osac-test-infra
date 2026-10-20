#!/usr/bin/env bash
#
# Boot SNO from snapshot via cluster-tool and fix DNS forwarding.
# Corresponds to setup-lab.sh steps 3-5.
# Idempotent — safe to re-run.
#
set -euo pipefail

MGMT_CLONE_NAME="${MGMT_CLONE_NAME:-agentless-lab-mgmt}"
PULL_SECRET="${OSAC_PULL_SECRET_PATH:-/root/pull-secret}"

MGMT_VM_NAME="test-infra-cluster-${MGMT_CLONE_NAME}-master-0"
MGMT_LIBVIRT_NET="test-infra-net-${MGMT_CLONE_NAME}"
CLUSTER_DOMAIN="test-infra-cluster-${MGMT_CLONE_NAME}.redhat.com"
KUBECONFIG="$HOME/.kube/${MGMT_CLONE_NAME}.kubeconfig"

info() { echo "==> $*"; }

# ---------- step 3: boot mgmt-server ----------

if virsh dominfo "$MGMT_VM_NAME" &>/dev/null; then
    info "mgmt-server already running — skipping boot"
else
    info "Booting mgmt-server (this may take several minutes)..."
    cluster-tool boot --flavor sno-4-22 --name "$MGMT_CLONE_NAME" --pull-secret "$PULL_SECRET"
fi

# ---------- step 4: resolve management network ----------

MGMT_CIDR=$(cluster-tool list 2>/dev/null | awk -v name="$MGMT_CLONE_NAME" '$1==name{print $3}')
MGMT_PREFIX=$(echo "$MGMT_CIDR" | cut -d. -f1-3)
MGMT_GW="${MGMT_PREFIX}.1"
MGMT_BRIDGE=$(virsh net-info "$MGMT_LIBVIRT_NET" | awk '/^Bridge:/{print $2}')

info "Management network: ${MGMT_CIDR} on bridge ${MGMT_BRIDGE}"

# Export for later scripts (deploy-fabric needs these)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cat > "${SCRIPT_DIR}/../.mgmt-network" <<EOF
MGMT_CIDR=${MGMT_CIDR}
MGMT_PREFIX=${MGMT_PREFIX}
MGMT_GW=${MGMT_GW}
MGMT_BRIDGE=${MGMT_BRIDGE}
MGMT_VM_NAME=${MGMT_VM_NAME}
MGMT_LIBVIRT_NET=${MGMT_LIBVIRT_NET}
CLUSTER_DOMAIN=${CLUSTER_DOMAIN}
KUBECONFIG=${KUBECONFIG}
EOF

# ---------- step 5a: fix DNS forwarding (layer 1) ----------
#
# cluster-tool creates the libvirt network with localOnly='yes' on the
# mgmt cluster's domain, which prevents libvirt dnsmasq from forwarding
# *.hosted.<domain> queries to upstream. Flip to localOnly='no'.

DNSMASQ_CONF="/var/lib/libvirt/dnsmasq/${MGMT_LIBVIRT_NET}.conf"

if grep -q "^local=/" "$DNSMASQ_CONF" 2>/dev/null; then
    info "Fixing DNS forwarding (layer 1: localOnly)..."
    NET_XML=$(mktemp)
    virsh net-dumpxml "$MGMT_LIBVIRT_NET" > "$NET_XML"
    sed -i "s/localOnly='yes'/localOnly='no'/" "$NET_XML"
    virsh net-define "$NET_XML"
    rm -f "$NET_XML"
    sed -i '/^local=/d' "$DNSMASQ_CONF"
    if [ -f "/var/run/libvirt/network/${MGMT_LIBVIRT_NET}.pid" ]; then
        xargs kill < "/var/run/libvirt/network/${MGMT_LIBVIRT_NET}.pid" 2>/dev/null || true
        sleep 1
        DNSMASQ_BRIDGE=$(virsh net-info "$MGMT_LIBVIRT_NET" 2>/dev/null | awk '/^Bridge:/{print $2}')
        DNSMASQ_INTERFACE="$DNSMASQ_BRIDGE" /usr/sbin/dnsmasq \
            --conf-file="$DNSMASQ_CONF" --leasefile-ro \
            --dhcp-script=/usr/libexec/libvirt_leaseshelper
        pgrep -f "dnsmasq.*${MGMT_LIBVIRT_NET}" > "/var/run/libvirt/network/${MGMT_LIBVIRT_NET}.pid"
    fi
else
    info "DNS forwarding (layer 1) already fixed — skipping"
fi

# ---------- step 5b: resolve the API on the hypervisor ----------
#
# cluster-tool publishes the API through HAProxy on this host. NetworkManager
# on RHEL does not use libvirt's dnsmasq unless it is told to, so the API
# name can fail to resolve even after localOnly is flipped. Point the cluster
# domain at this host's address. AGENTLESS_NET_API_DNS_IP overrides the
# detected source address when HAProxy is bound somewhere else.

ensure_hypervisor_api_dns() {
    local api_name="api.${CLUSTER_DOMAIN}"
    local desired_ip="${AGENTLESS_NET_API_DNS_IP:-}"
    local current=""
    if [[ -z "${desired_ip}" ]]; then
        desired_ip=$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for (i = 1; i <= NF; i++) if ($i == "src") { print $(i + 1); exit }}')
    fi
    if [[ ! "${desired_ip}" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
        echo "ERROR: could not determine an IPv4 address for ${api_name}" >&2
        exit 1
    fi
    current=$(getent hosts "${api_name}" | awk '$1 ~ /^[0-9.]+$/ { print $1; exit }' || true)
    if [[ "${current}" == "${desired_ip}" ]]; then
        info "API name ${api_name} already resolves to the hypervisor"
        return 0
    fi
    if ! command -v systemctl >/dev/null 2>&1 || ! systemctl is-active NetworkManager >/dev/null 2>&1; then
        echo "ERROR: ${api_name} resolves to '${current:-nothing}', expected ${desired_ip}, and NetworkManager is not active" >&2
        exit 1
    fi
    info "Pointing ${CLUSTER_DOMAIN} at the hypervisor via NetworkManager dnsmasq"
    mkdir -p /etc/NetworkManager/conf.d /etc/NetworkManager/dnsmasq.d
    printf '%s\n' '[main]' 'dns=dnsmasq' > /etc/NetworkManager/conf.d/cluster-tool-dns.conf
    printf 'address=/%s/%s\n' "${CLUSTER_DOMAIN}" "${desired_ip}" > "/etc/NetworkManager/dnsmasq.d/cluster-${MGMT_CLONE_NAME}.conf"
    systemctl restart NetworkManager
    local _
    for _ in 1 2 3 4 5 6 7 8 9 10; do
        current=$(getent hosts "${api_name}" | awk '$1 ~ /^[0-9.]+$/ { print $1; exit }' || true)
        [[ "${current}" == "${desired_ip}" ]] && return 0
        sleep 2
    done
    echo "ERROR: ${api_name} resolved to '${current:-nothing}' after NetworkManager restart; expected ${desired_ip}" >&2
    exit 1
}

ensure_hypervisor_api_dns

# ---------- step 5c: enable IP forwarding on management VM ----------
#
# MetalLB announces kube-apiserver VIPs on the management network.
# The kernel must forward packets from the management NIC into OVN.

info "Enabling IP forwarding on management VM..."
KUBECONFIG="$KUBECONFIG" oc debug node/"$(KUBECONFIG="$KUBECONFIG" oc get node -o jsonpath='{.items[0].metadata.name}')" \
    -- chroot /host bash -c '
    if [ "$(sysctl -n net.ipv4.ip_forward)" = "0" ]; then
        sysctl -w net.ipv4.ip_forward=1
    else
        echo "ip_forward already enabled"
    fi
' 2>&1 | tail -3

info "deploy-ocp complete."
