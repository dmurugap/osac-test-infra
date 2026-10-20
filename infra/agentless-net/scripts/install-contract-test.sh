#!/usr/bin/env bash
# Checks the agentless-net install files stay split the way current OSAC requires:
# Helm overlays contain only schema-valid keys, and AGENTLESS_NET_* stays in the
# post-install ConfigMap file.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INFRA_DIR="${SCRIPT_DIR}/.."
pass=0
fail=0

ok() { echo "PASS: $1"; pass=$((pass + 1)); }
bad() { echo "FAIL: $1"; fail=$((fail + 1)); }

instance="${INFRA_DIR}/values/instance-overlay.yaml"
infra="${INFRA_DIR}/values/infra-overlay.yaml"
config="${INFRA_DIR}/values/fulfillment-ig.env"

if [[ -f "${INFRA_DIR}/values-overlay.yaml" ]]; then
    bad "values-overlay.yaml is back; Helm cannot take AGENTLESS_NET_* keys"
else
    ok "legacy values-overlay.yaml is absent"
fi

if grep -vE '^[[:space:]]*#' "${instance}" "${infra}" | grep -q 'AGENTLESS_NET_'; then
    bad "Helm overlays contain AGENTLESS_NET_* keys"
else
    ok "Helm overlays do not contain AGENTLESS_NET_* keys"
fi

for key in \
    NETWORK_CLASS \
    NETWORK_STEPS_COLLECTION \
    k8s_only \
    'fabricManager: ""'
do
    if grep -q "${key}" "${instance}"; then
        ok "instance overlay has ${key}"
    else
        bad "instance overlay missing ${key}"
    fi
done

if awk '/^[[:space:]]*kafka:/{k=1; next} k && /^[^[:space:]#]/{k=0} k && /enabled:[[:space:]]*false/{f=1} END{exit !f}' "${infra}"; then
    ok "infra overlay disables kafka"
else
    bad "infra overlay does not disable kafka"
fi

required=(
    AGENTLESS_NET_VLAN_POOL_START
    AGENTLESS_NET_VLAN_POOL_END
    AGENTLESS_NET_TRUNK_INTERFACE
    AGENTLESS_NET_EXTERNAL_INTERFACE
    AGENTLESS_NET_EXTERNAL_GATEWAY
    AGENTLESS_NET_SUBNET_CIDR
    AGENTLESS_NET_PUBLIC_IP_POOL_START
    AGENTLESS_NET_PUBLIC_IP_POOL_END
    AGENTLESS_NET_DATA_INTERFACE
    AGENTLESS_NET_MGMT_INTERFACE
)
for key in "${required[@]}"; do
    if grep -q "^${key}=" "${config}"; then
        ok "fulfillment config has ${key}"
    else
        bad "fulfillment config missing ${key}"
    fi
done

if grep -q 'values/caas-ci/values.yaml' "${INFRA_DIR}/scripts/deploy-osac.sh"; then
    bad "deploy-osac.sh still merges the removed values/caas-ci/values.yaml"
else
    ok "deploy-osac.sh does not reference values/caas-ci/values.yaml"
fi

if grep -q 'openshift-assisted/cluster-tool' "${INFRA_DIR}/scripts/setup-infra.sh"; then
    bad "setup-infra.sh still downloads cluster-tool from openshift-assisted"
else
    ok "setup-infra.sh does not use the openshift-assisted cluster-tool URL"
fi

if grep -q 'CLUSTER_TOOL_REF="${CLUSTER_TOOL_REF:-[0-9a-f]\{40\}}"$' "${INFRA_DIR}/scripts/setup-infra.sh"; then
    ok "cluster-tool is pinned to a full commit"
else
    bad "cluster-tool default ref is not a full commit SHA"
fi

if grep -q 'git clone --branch' "${INFRA_DIR}/scripts/setup-infra.sh"; then
    bad "setup-infra.sh still clones cluster-tool with git clone --branch"
else
    ok "setup-infra.sh fetches the pinned cluster-tool commit"
fi

if grep -q 'status --porcelain -- cluster-tool' "${INFRA_DIR}/scripts/setup-infra.sh"; then
    ok "cluster-tool install restores a dirty pinned checkout"
else
    bad "cluster-tool install ignores local edits in the pinned checkout"
fi

if grep -q 'cmp -s "${CLUSTER_TOOL_DIR}/cluster-tool" "${CLUSTER_TOOL_BIN}"' "${INFRA_DIR}/scripts/setup-infra.sh"; then
    ok "cluster-tool install compares the binary with the pinned checkout"
else
    bad "cluster-tool install does not compare the binary with the pinned checkout"
fi

if grep -q 'host_type_disposition' "${INFRA_DIR}/scripts/setup-caas.sh"; then
    ok "setup-caas.sh classifies host-type HTTP status"
else
    bad "setup-caas.sh does not classify host-type HTTP status"
fi

echo "${pass} passed, ${fail} failed"
[[ "${fail}" -eq 0 ]]
