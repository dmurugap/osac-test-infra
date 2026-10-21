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
        published = b"".join(path.read_bytes() for path in root.rglob("*") if path.is_file())
        names = " ".join(path.relative_to(root).as_posix() for path in root.rglob("*") if path.is_file())
        _assert(raw not in published, f"{name} raw contents would be uploaded")
        _assert(not gate.forbidden_reasons(published), f"{name} still publishable with secrets")
        _assert(pathlib.Path(name).name not in names or pathlib.Path(name).name in gate._SAFE_FILES, f"{name} identifier remains in {names}")


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
    fake_api_key = ("gh" + "p_") + ("abcdefghij" + "klmnopqrstuvwxyz012345")
    fake_registry_url = "https://" + "user" + ":" + "s3" + "cret" + "@" + "registry.example.com" + "/v2"
    fixture_samples = {
        "ipv4": b"node 10.1.2.3",
        "ipv6": b"fe80::1",
        "hostname": b"api.cluster-1.example.com",
        "lab": b"clab-agentless-net-lab-leaf-1",
        "instance": b"i-0123456789abcdef0",
        "ec2": b"ip-10-0-1-23",
        "kube": b"client-key-data: abcdef\n",
        "token": b"token=session-secret",
        "env": b"QUAY_PASSWORD=x",
        "json": b'{"token": "x"}',
        "json-api-key": b'{"apiKey":"x"}',
        "basic": b"Authorization: Basic YWJj\n",
        "registry": b'{"auth": "YWJj"}',
        "yaml": b"password: supersecret\n",
        "email": b"user@example.com",
        "ssn": b"123-45-6789",
        "card": b"4111-1111-1111-1111",
        "api-key": fake_api_key.encode(),
        "url": fake_registry_url.encode(),
        "session": b"JSESSIONID=abc123session",
        "internal-host": b"master-0.ostest",
    }
    for name, sample in fixture_samples.items():
        _assert(gate.forbidden_reasons(sample), f"{name} would pass verification")
        cleaned = gate.redact_bytes(sample)
        _assert(sample not in cleaned, f"{name} raw value survives redaction")
        _assert(not gate.forbidden_reasons(cleaned), f"{name} remains after redaction: {cleaned!r}")
    _assert(not gate.forbidden_reasons(b"15:55:01 bridge domain br_default"), "clock time looks sensitive")


def test_auth_schemes_stay_intact() -> None:
    cleaned = gate.redact_bytes(b"Authorization: Basic YWJj\nAuthorization: Bearer tok\n")
    _assert(b"Basic [REDACTED]" in cleaned, f"basic scheme changed: {cleaned!r}")
    _assert(b"Bearer [REDACTED]" in cleaned, f"bearer scheme changed: {cleaned!r}")
    _assert(b"YWJj" not in cleaned and b" tok" not in cleaned, f"credential remains: {cleaned!r}")
    _assert(not gate.forbidden_reasons(cleaned), f"redacted auth still forbidden: {cleaned!r}")


def test_cluster_order_names_are_not_uploaded() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = pathlib.Path(tmp)
        target = root / "agentless-net/customer-cluster-nodes.txt"
        other = root / "agentless-net/hostedclusters.txt"
        target.parent.mkdir(parents=True)
        target.write_text("customer-cluster Ready 10.0.0.8\n")
        other.write_text("customer-cluster api.cluster.example.com\n")
        gate.sanitize_tree(root)
        names = [path.relative_to(root).as_posix() for path in root.rglob("*") if path.is_file()]
        published = b"".join(path.read_bytes() for path in root.rglob("*") if path.is_file())
        _assert(names, "cluster-order file disappeared")
        for name in names:
            _assert("customer-cluster" not in name, f"cluster order remains in {name}")
        _assert(b"customer-cluster" not in published, "cluster order remains in the log")
        _assert(b"10.0.0.8" not in published, "node address remains in the log")


def test_inventory_files_drop_bare_identifiers() -> None:
    for filename in ("clusterorders.txt", "hostedclusters.txt"):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            target = root / "agentless-net" / filename
            target.parent.mkdir(parents=True)
            target.write_text("NAME AGE\ncustomer-cluster 5m\nmaster-0.ostest\n")
            gate.sanitize_tree(root)
            published = target.read_bytes()
            _assert(b"customer-cluster" not in published, f"{filename} kept a bare cluster name")
            _assert(b"master-0.ostest" not in published, f"{filename} kept an internal hostname")
            _assert(b"ostest" not in published, f"{filename} kept a hostname label")
            _assert(not gate.forbidden_reasons(published), f"{filename} still publishable with identifiers")
            _assert(b"NAME" in published, f"{filename} dropped the column header")


def test_journal_prose_is_not_a_credential() -> None:
    prose = b"failed to get token: connection refused\n"
    neighbors = b"oauth: public\nx-auth: public\npassword=&\n"
    _assert(not gate.forbidden_reasons(prose), f"journal prose looks secret: {gate.forbidden_reasons(prose)}")
    _assert(not gate.forbidden_reasons(neighbors), f"non-secrets look secret: {gate.forbidden_reasons(neighbors)}")
    _assert(gate.redact_bytes(prose) == prose, "journal prose was redacted")
    quoted = b'password: "x"\n'
    _assert(gate.forbidden_reasons(quoted), "quoted yaml password would pass")
    cleaned = gate.redact_bytes(quoted)
    _assert(b'"x"' not in cleaned, f"quoted password remains: {cleaned!r}")
    _assert(not gate.forbidden_reasons(cleaned), f"quoted password still forbidden: {cleaned!r}")
    with tempfile.TemporaryDirectory() as tmp:
        root = pathlib.Path(tmp)
        target = root / "host/journalctl.log"
        target.parent.mkdir(parents=True)
        target.write_bytes(prose)
        gate.sanitize_tree(root)
        _assert(target.read_bytes() == prose, "journal prose was dropped")


def test_symlinks_are_refused() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = pathlib.Path(tmp) / "stage"
        outside = pathlib.Path(tmp) / "outside.txt"
        root.mkdir()
        (root / "host").mkdir()
        outside.write_text("do-not-touch\n")
        (root / "host/dmesg.log").symlink_to(outside)
        (root / "host/cloud-init.log").symlink_to(root / "missing")
        try:
            gate.sanitize_tree(root)
        except SystemExit as exc:
            _assert(exc.code == 1, f"symlink exited {exc.code}")
            _assert(outside.read_text() == "do-not-touch\n", "symlink target was overwritten")
            return
        raise AssertionError("symlink would be uploaded")


def test_binary_diagnostics_are_refused() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = pathlib.Path(tmp)
        target = root / "host/dmesg.log"
        target.parent.mkdir(parents=True)
        target.write_bytes(b"kernel\x00secret")
        try:
            gate.sanitize_tree(root)
        except SystemExit as exc:
            _assert(exc.code == 1, f"binary file exited {exc.code}")
            return
        raise AssertionError("binary diagnostic would be uploaded")


def test_clean_redacted_file_is_publishable() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = pathlib.Path(tmp)
        target = root / "agentless-net/virsh-list.txt"
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
    test_auth_schemes_stay_intact()
    test_cluster_order_names_are_not_uploaded()
    test_inventory_files_drop_bare_identifiers()
    test_journal_prose_is_not_a_credential()
    test_symlinks_are_refused()
    test_binary_diagnostics_are_refused()
    test_clean_redacted_file_is_publishable()
    print("sanitize-diagnostics: ok")


if __name__ == "__main__":
    main()
