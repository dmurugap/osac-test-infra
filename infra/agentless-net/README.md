# CaaS AgentlessNet full install

This directory installs one management SNO, OSAC with the agentless network
backend, a containerlab fabric, and two discovery agents. The GitHub Actions
caller is `.github/workflows/e2e-caas-agentlessnet-full-install-caller.yml`.
It is manual `workflow_dispatch` only. The older
`.github/workflows/e2e-caas-agentless-net-full-install.yml` is unchanged.

## Targets

From this directory, in order:

```text
make setup-infra
make deploy-ocp
make deploy-osac
make deploy-fabric
make setup-caas
make test-e2e
```

`make gather-infra` and `make gather-e2e` collect diagnostics. They are safe to
run after a failed stage.

`setup-caas` and `test-e2e` read `CAAS_AGENT_FLOW`. The default is `hot-pool`.
`cluster-namespace` leaves agent approval to OSAC.

## What changed for current OSAC

| Former failure | Where it is handled |
| --- | --- |
| `cluster-tool` downloaded from `openshift-assisted/cluster-tool` releases, which does not publish that binary | `scripts/setup-infra.sh` checks out a pinned commit of `osac-project/cluster-tool` and installs it on `PATH`, including `/usr/bin` so `sudo` can find it |
| Private flavor image pull had no registry credentials | `scripts/setup-infra.sh` stages the pull secret, when present, for Docker and Podman before `cluster-tool pull`. Copying a flavor cache from another machine is not the default |
| `oc`, Helm, or the `osac` CLI missing on a fresh runner | `scripts/setup-infra.sh` runs `scripts/machine-init.sh oc helm osac` |
| `values/caas-ci/values.yaml` no longer exists | `scripts/deploy-osac.sh` runs `make install-infra` and `make install-osac` with `PLATFORM=openshift`, `PROFILE=caas-ci`, and `NS` |
| `caas-ci` selects CUDN and `ci.steps` | `values/instance-overlay.yaml` selects `k8s_only` and turns expert AAP overrides off so the chart derives `agentless_net` / `agentless_net.steps` |
| Pre-install hook `No Provisioning CR found` while `bmf.metal3` is enabled | `scripts/deploy-osac.sh` creates or patches `provisioning-configuration` with `watchAllNamespaces: true` after infra install and before `install-osac`. The Metal3 CRD must already be on the cluster |
| Helm rejects `AGENTLESS_NET_*` in `aap.instanceGroups.clusterFulfillment.config` | Those keys stay in `values/fulfillment-ig.env`. `deploy-osac.sh` patches ConfigMap `cluster-fulfillment-ig` after install. A same-named environment variable overrides one value |
| `POST /api/private/v1/host_types` returns HTTP 404 | `scripts/setup-caas.sh` continues. Agents are still labeled `osac.openshift.io/resource_class=ci-worker` |
| Hypervisor resolver ignores libvirt DNS | `scripts/deploy-ocp.sh` points the cluster domain at this host through NetworkManager dnsmasq when `api.<cluster-domain>` does not already resolve here. Set `AGENTLESS_NET_API_DNS_IP` when HAProxy is not on the default-route source address |

Kafka is disabled by `values/infra-overlay.yaml` because this suite does not use it and the SNO snapshot does not ship Strimzi. Set `AGENTLESS_NET_KAFKA=true` to install the profile's Kafka. Metering is disabled in the instance overlay because this suite does not use it.

`values/fulfillment-ig.env` follows `agentless-net-lab.clab.yml` (trunk `eth1`, external `eth2`, public pool `192.168.100.10`–`192.168.100.50`). Those are the lab topology, not one hypervisor. The hosted-cluster zone in `values/instance-overlay.yaml` is the shared CI Route 53 zone.

## Not part of this install

These were one-time console steps. `test-e2e` does not use them. `scripts/test-e2e.sh` creates clusters from template `osac.templates.ocp_ci_small` with the `osac` CLI.

- An htpasswd identity provider and a Keycloak user for browser login
- A catalog item. Templates are not catalog items
- Laptop `/etc/hosts` entries for a browser on another machine

The `fabricManager: agentless_net` installer stub is a separate VirtualNetwork baseline. This full install keeps the containerlab fabric and `k8s_only`.

## Checks without a cluster

```text
bash infra/agentless-net/scripts/setup-caas-test.sh
bash infra/agentless-net/scripts/install-contract-test.sh
```

Do not run `setup-infra`, `deploy-ocp`, `deploy-osac`, or `deploy-fabric` against a cluster that is already in use.
