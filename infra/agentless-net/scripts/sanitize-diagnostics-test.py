#!/usr/bin/env python3
"""The diagnostic gate must not accept raw AgentlessNet or host logs."""

from __future__ import annotations

import pathlib
import sys
import tempfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import sanitize_diagnostics as gate  # noqa: E402


def _assert(cond: bool, msg: str) -> None:
    if not cond:
        raise AssertionError(msg)


def _refused(name: str, raw: bytes) -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = pathlib.Path(tmp)
        target = root / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(raw)
        try:
            gate.sanitize_tree(root)
        except SystemExit as exc:
            _assert(exc.code == 1, f"{name} exited {exc.code}, expected refusal")
            return
        published = target.read_bytes()
        _assert(raw not in published, f"{name} raw contents would be uploaded")
        _assert(not gate.forbidden_reasons(published), f"{name} still publishable with secrets")


def test_agentless_net_logs_are_not_uploaded_raw() -> None:
    _refused(
        "agentless-net/net-node-ip-addr.txt",
        b"clab-agentless-net-lab-net-node: inet 10.100.0.15/24\n",
    )


def test_journal_is_not_uploaded_raw() -> None:
    _refused(
        "host/journalctl.log",
        b"Started session for ip-10-0-1-23.ec2.internal token=session-secret\n",
    )


def test_cloud_init_is_not_uploaded_raw() -> None:
    _refused(
        "host/cloud-init.log",
        b"hostname: ip-10-0-1-23.ec2.internal\ninstance-id: i-0123456789abcdef0\n",
    )
    with tempfile.TemporaryDirectory() as tmp:
        root = pathlib.Path(tmp)
        target = root / "host/cloud-init.log"
        target.parent.mkdir(parents=True)
        target.write_bytes(
            b"hostname: ip-10-0-1-23.ec2.internal\ninstance-id: i-0123456789abcdef0\n"
        )
        gate.sanitize_tree(root)
        published = b"".join(path.read_bytes() for path in root.rglob("*") if path.is_file())
        _assert(b"i-0123456789abcdef0" not in published, "instance id would be uploaded")
        _assert(b"ip-10-0-1-23" not in published, "ec2 hostname would be uploaded")


def test_dmesg_is_not_uploaded_raw() -> None:
    _refused(
        "host/dmesg.log",
        b"eth0: assigned 192.168.162.10\n",
    )


def test_node_listing_is_not_uploaded_raw() -> None:
    _refused(
        "agentless-net/cluster-1-nodes.txt",
        b"test-infra-cluster-agentless-lab-mgmt-master-0   Ready   10.0.0.8\n",
    )


def test_hosted_cluster_kubeconfig_is_not_uploaded_raw() -> None:
    _refused(
        "agentless-net/hostedclusters.txt",
        b"api.cluster-1.ecoeng-osac-ci.devcluster.openshift.com\n"
        b"client-key-data: LS0tLS1CRUdJTi\n",
    )


def test_lab_filenames_are_not_uploaded() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = pathlib.Path(tmp)
        first = root / "agentless-net/clab-agentless-net-lab-leaf-1-vlans.txt"
        second = root / "agentless-net/clab-agentless-net-lab-leaf-2-vlans.txt"
        first.parent.mkdir(parents=True)
        first.write_text("vlan 100\n")
        second.write_text("vlan 101\n")
        gate.sanitize_tree(root)
        names = [path.relative_to(root).as_posix() for path in root.rglob("*") if path.is_file()]
        _assert(names, "lab files disappeared")
        for name in names:
            _assert("clab-" not in name, f"lab name remains in {name}")
            _assert(not gate.forbidden_reasons(name.encode()), f"{name} still identifies a lab")


def test_verification_rejects_remaining_findings() -> None:
    samples = {
        "ipv4": b"node 10.1.2.3",
        "ipv6": b"fe80::1",
        "hostname": b"api.cluster-1.example.com",
        "lab": b"clab-agentless-net-lab-leaf-1",
        "instance": b"i-0123456789abcdef0",
        "ec2": b"ip-10-0-1-23",
        "kube": b"client-key-data: abcdef\n",
        "token": b"token=session-secret",
    }
    for name, sample in samples.items():
        _assert(gate.forbidden_reasons(sample), f"{name} would pass verification")
    _assert(not gate.forbidden_reasons(b"15:55:01 bridge domain br_default"), "clock time looks sensitive")


def test_clean_redacted_file_is_publishable() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = pathlib.Path(tmp)
        target = root / "agentless-net/status.txt"
        target.parent.mkdir()
        target.write_text("bridge domain br_default has no address\n")
        gate.sanitize_tree(root)
        _assert(target.read_text() == "bridge domain br_default has no address\n", "clean file changed")


def main() -> None:
    test_agentless_net_logs_are_not_uploaded_raw()
    test_journal_is_not_uploaded_raw()
    test_cloud_init_is_not_uploaded_raw()
    test_dmesg_is_not_uploaded_raw()
    test_node_listing_is_not_uploaded_raw()
    test_hosted_cluster_kubeconfig_is_not_uploaded_raw()
    test_lab_filenames_are_not_uploaded()
    test_verification_rejects_remaining_findings()
    test_clean_redacted_file_is_publishable()
    print("sanitize-diagnostics: ok")


if __name__ == "__main__":
    main()
