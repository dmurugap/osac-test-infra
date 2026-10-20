#!/usr/bin/env bash
# Shared functions for CaaS agent flow logic.
# Sourced by setup-caas.sh (production) and setup-caas-test.sh (tests).

# Resolve the Kubernetes namespace where agents should be created.
# Reads CAAS_AGENT_FLOW and CAAS_CLUSTER_ORDER_NAMESPACE from the
# caller's environment.
# Returns: prints the namespace name; exits 1 if cluster-namespace
# mode is selected but CAAS_CLUSTER_ORDER_NAMESPACE is unset.
resolve_agent_namespace() {
    local flow="${CAAS_AGENT_FLOW:-hot-pool}"
    if [[ "${flow}" == "cluster-namespace" ]]; then
        if [[ -z "${CAAS_CLUSTER_ORDER_NAMESPACE:-}" ]]; then
            return 1
        fi
        echo "${CAAS_CLUSTER_ORDER_NAMESPACE}"
    else
        echo "hardware-inventory"
    fi
}

# Whether agents should be approved by test-infra (hot-pool) or left
# for osac ci_create (cluster-namespace).
# Returns: 0 (true) if agents should be approved, 1 otherwise.
should_approve_agents() {
    local flow="${CAAS_AGENT_FLOW:-hot-pool}"
    [[ "${flow}" != "cluster-namespace" ]]
}

# Validate CAAS_AGENT_FLOW against the known allowlist.
# Returns: 0 on valid, 1 on invalid.
validate_agent_flow() {
    local flow="${CAAS_AGENT_FLOW:-hot-pool}"
    case "${flow}" in
        hot-pool|cluster-namespace) return 0 ;;
        *) return 1 ;;
    esac
}

# Classify POST /api/private/v1/host_types.
# Current OSAC removed the HostType resource, so 404 is not a failed create.
# Prints created, exists, or removed. Returns 1 for any other status.
host_type_disposition() {
    case "${1:-}" in
        200|201) printf '%s\n' created ;;
        409) printf '%s\n' exists ;;
        404) printf '%s\n' removed ;;
        *) return 1 ;;
    esac
}
