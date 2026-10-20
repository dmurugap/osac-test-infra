#!/usr/bin/env bash
#
# Install OSAC on the management cluster for the agentless-net lab.
# Clones the osac mono-repo and installs profile caas-ci with the
# schema-valid overlays in ../values. Agentless settings that Helm
# rejects are patched onto the cluster-fulfillment-ig ConfigMap after
# install. Corresponds to setup-lab.sh steps 7-10.
# Idempotent — safe to re-run.
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INFRA_DIR="${SCRIPT_DIR}/.."

# shellcheck source=/dev/null
source "${INFRA_DIR}/.mgmt-network"

OSAC_NAMESPACE="${OSAC_NAMESPACE:-osac-e2e-ci}"
OSAC_PROFILE="${OSAC_PROFILE:-caas-ci}"
OSAC_REPO="${OSAC_REPO:-https://github.com/osac-project/osac.git}"
OSAC_BRANCH="${OSAC_BRANCH:-main}"
OSAC_DIR="/opt/osac"
INSTALLER_DIR="${OSAC_DIR}/osac-installer"
INSTANCE_OVERLAY="${INFRA_DIR}/values/instance-overlay.yaml"
INFRA_OVERLAY="${INFRA_DIR}/values/infra-overlay.yaml"
FULFILLMENT_ENV="${INFRA_DIR}/values/fulfillment-ig.env"
DNS_CREDS="${DNS_CREDENTIALS_PATH:-${INFRA_DIR}/config}"
SSH_PRIVATE_KEY="${SSH_PRIVATE_KEY_PATH:-${HOME}/.ssh/id_rsa}"

export KUBECONFIG

info() { echo "==> $*"; }

# ---------- clone osac mono-repo ----------

if [ -d "$OSAC_DIR" ]; then
    info "osac mono-repo already cloned at ${OSAC_DIR}"
    git -C "$OSAC_DIR" fetch origin
    git -C "$OSAC_DIR" checkout "$OSAC_BRANCH"
    git -C "$OSAC_DIR" pull --ff-only || true
else
    info "Cloning osac mono-repo (${OSAC_REPO} @ ${OSAC_BRANCH})..."
    git clone --branch "$OSAC_BRANCH" "$OSAC_REPO" "$OSAC_DIR"
fi

AAP_LICENSE="${AAP_LICENSE_PATH:-/root/aap-license.zip}"

ensure_provisioning_cr() {
    if ! KUBECONFIG="$KUBECONFIG" oc get crd provisionings.metal3.io >/dev/null 2>&1; then
        echo "ERROR: Metal3 Provisioning CRD is not installed." >&2
        echo "caas-ci enables bmf.metal3, and the OSAC pre-install hook rejects a missing Provisioning CR." >&2
        exit 1
    fi
    if KUBECONFIG="$KUBECONFIG" oc get provisioning provisioning-configuration >/dev/null 2>&1; then
        info "Provisioning CR present; ensuring watchAllNamespaces"
        KUBECONFIG="$KUBECONFIG" oc patch provisioning provisioning-configuration --type merge \
            -p '{"spec":{"watchAllNamespaces":true,"provisioningNetwork":"Disabled"}}'
        return 0
    fi
    info "Creating Provisioning CR"
    KUBECONFIG="$KUBECONFIG" oc apply -f - <<'EOF'
apiVersion: metal3.io/v1alpha1
kind: Provisioning
metadata:
  name: provisioning-configuration
spec:
  provisioningNetwork: Disabled
  watchAllNamespaces: true
EOF
}

patch_fulfillment_configmap() {
    local patch
    patch=$(FULFILLMENT_ENV_FILE="${FULFILLMENT_ENV}" python3 - <<'PY'
import json, os, pathlib, re, sys
path = pathlib.Path(os.environ["FULFILLMENT_ENV_FILE"])
data = {}
key_re = re.compile(r"^[A-Z][A-Z0-9_]*$")
val_re = re.compile(r"^[A-Za-z0-9._:/-]+$")
for raw in path.read_text().splitlines():
    line = raw.strip()
    if not line or line.startswith("#"):
        continue
    if "=" not in line:
        sys.exit(f"invalid fulfillment config line: {line}")
    key, value = line.split("=", 1)
    value = os.environ.get(key, value)
    if not key_re.match(key) or not val_re.match(value):
        sys.exit(f"refusing fulfillment config entry: {key}")
    data[key] = value
if not data:
    sys.exit("fulfillment config is empty")
print(json.dumps({"data": data}))
print("config keys: " + " ".join(sorted(data)), file=sys.stderr)
PY
    )
    info "Patching cluster-fulfillment-ig ConfigMap with agentless settings Helm rejects"
    KUBECONFIG="$KUBECONFIG" oc patch configmap cluster-fulfillment-ig -n "$OSAC_NAMESPACE" --type merge -p "${patch}"
}

# ---------- step 8: install OSAC ----------

if KUBECONFIG="$KUBECONFIG" oc get deploy/fulfillment-grpc-server -n "$OSAC_NAMESPACE" 2>/dev/null | grep -q "1/1"; then
    info "OSAC already running — skipping install"
else
    info "Installing OSAC infra and instance (profile ${OSAC_PROFILE})..."
    infra_extra=()
    if [[ "${AGENTLESS_NET_KAFKA:-false}" != "true" ]]; then
        infra_extra+=(INFRA_VALUES_EXTRA="-f ${INFRA_OVERLAY}")
    fi
    (
        cd "${INSTALLER_DIR}"
        KUBECONFIG="$KUBECONFIG" make install-infra \
            PLATFORM=openshift \
            PROFILE="${OSAC_PROFILE}" \
            NS="${OSAC_NAMESPACE}" \
            "${infra_extra[@]}"
        ensure_provisioning_cr
        KUBECONFIG="$KUBECONFIG" make install-osac \
            PLATFORM=openshift \
            PROFILE="${OSAC_PROFILE}" \
            NS="${OSAC_NAMESPACE}" \
            AAP_LICENSE_FILE="${AAP_LICENSE}" \
            INSTANCE_VALUES_EXTRA="-f ${INSTANCE_OVERLAY}"
    )
fi

# ---------- step 9: patch DNS credentials ----------

if [ -f "$DNS_CREDS" ]; then
    info "Patching cluster-fulfillment-ig with DNS credentials..."
    # shellcheck source=/dev/null
    source "$DNS_CREDS"
    KUBECONFIG="$KUBECONFIG" oc patch secret cluster-fulfillment-ig -n "$OSAC_NAMESPACE" --type merge \
        -p "{\"data\":{\"AWS_ACCESS_KEY_ID\":\"$(echo -n "$AWS_ACCESS_KEY_ID" | base64)\",\"AWS_SECRET_ACCESS_KEY\":\"$(echo -n "$AWS_SECRET_ACCESS_KEY" | base64)\"}}"
else
    echo "  WARN: ${DNS_CREDS} not found — DNS (Route 53) will not work."
fi

# ---------- step 9b: patch SSH key ----------

if [ -f "$SSH_PRIVATE_KEY" ]; then
    info "Patching cluster-fulfillment-ig with SSH key..."
    KUBECONFIG="$KUBECONFIG" oc patch secret cluster-fulfillment-ig -n "$OSAC_NAMESPACE" --type merge \
        -p "{\"data\":{\"SERVER_SSH_KEY\":\"$(base64 -w0 < "$SSH_PRIVATE_KEY")\"}}"
else
    echo "  WARN: ${SSH_PRIVATE_KEY} not found — NMState live apply will not work."
fi

# ---------- step 9c: agentless settings Helm will not accept ----------

patch_fulfillment_configmap

# ---------- step 10: validate OSAC ----------

info "Validating OSAC..."
KUBECONFIG="$KUBECONFIG" oc wait deploy/fulfillment-grpc-server -n "$OSAC_NAMESPACE" \
    --for=condition=Available --timeout=300s
KUBECONFIG="$KUBECONFIG" oc wait deploy/osac-operator -n "$OSAC_NAMESPACE" \
    --for=condition=Available --timeout=300s
info "OSAC is running:"
KUBECONFIG="$KUBECONFIG" oc get pods -n "$OSAC_NAMESPACE" --no-headers | \
    awk '{print $3}' | sort | uniq -c | sort -rn

# ---------- step 10b: patch MetalLB to use fabric subnet ----------

info "Patching MetalLB to use fabric subnet..."
KUBECONFIG="$KUBECONFIG" oc patch ipaddresspool caas-address-pool -n metallb-system \
    --type=merge -p '{"spec":{"addresses":["10.0.0.240-10.0.0.250"]}}'
echo "  Pool: 10.0.0.240-10.0.0.250"

info "deploy-osac complete."
