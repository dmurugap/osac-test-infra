#!/usr/bin/env python3
"""Redact a diagnostic staging directory and refuse it when sensitive data remains.

The workflow may upload only a directory that this command has accepted.
"""

from __future__ import annotations

import hashlib
import re
import sys
from pathlib import Path

REDACTED = "[REDACTED]"

# Collector names that do not identify a cluster or customer. Every other
# path component is replaced so cluster-order filenames cannot be uploaded.
_SAFE_DIRS = frozenset({"agentless-net", "host"})
_SAFE_FILES = frozenset(
    {
        "journalctl.log",
        "osac-ephemeral-runner.log",
        "dmesg.log",
        "cloud-init.log",
        "cloud-init-output.log",
        "containerlab-inspect.txt",
        "net-node-ip-addr.txt",
        "net-node-ip-route.txt",
        "net-node-namespaces.txt",
        "net-node-nat.txt",
        "virsh-list.txt",
        "host-1-ifaddr.txt",
        "host-2-ifaddr.txt",
        "osac-pods.txt",
        "agents.txt",
        "clusterorders.txt",
        "hostedclusters.txt",
    }
)
_ORDER_FILE = re.compile(r"^(?P<order>.+)-(?:nodes|clusteroperators|unhealthy-pods)\.txt$")
_GENERATED = re.compile(r"^(?:log|dir)-[0-9a-f]{12}$")

_PEM = re.compile(
    rb"-----BEGIN [A-Z0-9 ]+-----.*?-----END [A-Z0-9 ]+-----",
    re.DOTALL,
)
_KUBE_SECRET = re.compile(
    rb"(?im)^([ \t-]*\"?(?:certificate-authority-data|client-certificate-data|client-key-data|token|password|client-secret|auth|\.dockerconfigjson)\"?:)[ \t]+(?!\")(\S+)"
)
_JSON_SECRET = re.compile(
    rb'(?i)("[A-Za-z0-9_.-]*(?:token|password|secret|auth|key-data|dockerconfigjson)[A-Za-z0-9_.-]*"\s*:\s*)"[^"]*"'
)
_BEARER = re.compile(rb"(?i)\bBearer\s+\S+")
_BASIC = re.compile(rb"(?i)\bBasic\s+\S+")
_AWS_KEY = re.compile(rb"\bAKIA[0-9A-Z]{16}\b")
_API_KEY = re.compile(
    rb"(?i)\b(?:ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|sk-[A-Za-z0-9]{16,}|xox[baprs]-[A-Za-z0-9-]{10,}|(?:api[_-]?key|apikey|access[_-]?key)\s*[:=]\s*\S+)"
)
_ASSIGNMENT = re.compile(
    rb"(?i)([A-Za-z0-9_]*(?:password|token|secret|session)[A-Za-z0-9_]*)=([^\s&]+)"
)
_SESSION = re.compile(rb"(?i)\b((?:JSESSIONID|PHPSESSID|sessionid)\s*[=:]\s*)\S+")
_URL_CREDENTIAL = re.compile(rb"(?i)\b([a-z][a-z0-9+.-]*://)[^/\s:@]+:[^@\s/]+@")
_EMAIL = re.compile(rb"(?i)\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}\b")
_SSN = re.compile(rb"\b\d{3}-\d{2}-\d{4}\b")
_CARD = re.compile(rb"\b(?:\d{4}[ -]){3}\d{4}\b|\b\d{13,19}\b")
_IPV4 = re.compile(
    rb"(?<![0-9])(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)(?:/\d{1,2})?"
)
# Require a hex letter so clock times such as 15:55:01 stay in the journal.
_IPV6 = re.compile(
    rb"(?i)\b(?=[0-9a-f:]*[a-f])(?:[0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}\b"
)
# Two-character labels skip fragments such as "e.g" while still matching
# internal names like master-0.ostest.
_FQDN = re.compile(
    rb"(?i)\b(?:[a-z0-9][a-z0-9-]{0,61}[a-z0-9]\.)+[a-z]{2,}\b"
)
_LAB_NAME = re.compile(rb"\b(?:clab|test-infra)-[A-Za-z0-9._-]+\b")
_INSTANCE_ID = re.compile(rb"\bi-[0-9a-f]{8,17}\b")
_EC2_HOST = re.compile(rb"\bip(?:-\d{1,3}){4}\b")

_REPLACEMENTS = (
    (_PEM, REDACTED.encode()),
    (_URL_CREDENTIAL, lambda m: m.group(1) + REDACTED.encode() + b"@"),
    (_EMAIL, REDACTED.encode()),
    (_JSON_SECRET, lambda m: m.group(1) + b'"' + REDACTED.encode() + b'"'),
    (_KUBE_SECRET, lambda m: m.group(1) + b" " + REDACTED.encode()),
    (_BEARER, b"Bearer " + REDACTED.encode()),
    (_BASIC, b"Basic " + REDACTED.encode()),
    (_AWS_KEY, REDACTED.encode()),
    (_API_KEY, REDACTED.encode()),
    (_SESSION, lambda m: m.group(1) + REDACTED.encode()),
    (_ASSIGNMENT, lambda m: m.group(1) + b"=" + REDACTED.encode()),
    (_SSN, REDACTED.encode()),
    (_CARD, REDACTED.encode()),
    (_IPV4, REDACTED.encode()),
    (_IPV6, REDACTED.encode()),
    (_FQDN, REDACTED.encode()),
    (_LAB_NAME, REDACTED.encode()),
    (_INSTANCE_ID, REDACTED.encode()),
    (_EC2_HOST, REDACTED.encode()),
)

_FORBIDDEN = (
    ("ipv4", _IPV4),
    ("ipv6", _IPV6),
    ("hostname", _FQDN),
    ("lab-name", _LAB_NAME),
    ("instance-id", _INSTANCE_ID),
    ("ec2-host", _EC2_HOST),
    ("email", _EMAIL),
    ("ssn", _SSN),
    ("card", _CARD),
    ("pem", re.compile(rb"-----BEGIN (?:RSA |OPENSSH |EC )?PRIVATE KEY-----|-----BEGIN CERTIFICATE-----")),
    (
        "kubeconfig",
        re.compile(
            rb"(?im)(?:certificate-authority-data|client-certificate-data|client-key-data|token|password|client-secret|auth|\.dockerconfigjson):[ \t]*(?!\[REDACTED\])\S"
        ),
    ),
    (
        "json-secret",
        re.compile(
            rb'(?i)"[A-Za-z0-9_.-]*(?:token|password|secret|auth|key-data|dockerconfigjson)[A-Za-z0-9_.-]*"\s*:\s*"(?!\[REDACTED\])'
        ),
    ),
    ("aws-key", _AWS_KEY),
    ("api-key", _API_KEY),
    ("bearer", re.compile(rb"(?i)\bBearer\s+(?!\[REDACTED\])\S")),
    ("basic", re.compile(rb"(?i)\bBasic\s+(?!\[REDACTED\])\S")),
    (
        "session",
        re.compile(rb"(?i)\b(?:JSESSIONID|PHPSESSID|sessionid)\s*[=:]\s*(?!\[REDACTED\])\S"),
    ),
    (
        "assignment",
        re.compile(
            rb"(?i)[A-Za-z0-9_]*(?:password|token|secret|session)[A-Za-z0-9_]*=(?!\[REDACTED\])\S"
        ),
    ),
    ("url-credential", re.compile(rb"(?i)://[^/\s:@]+:[^@\s/]+@")),
)


def redact_bytes(data: bytes) -> bytes:
    for pattern, replacement in _REPLACEMENTS:
        data = pattern.sub(replacement, data)
    return data


def forbidden_reasons(data: bytes) -> list[str]:
    return [name for name, pattern in _FORBIDDEN if pattern.search(data)]


def _digest_name(prefix: str, text: str) -> str:
    digest = hashlib.sha256(text.encode()).hexdigest()[:12]
    return f"{prefix}-{digest}"


def _dest_for(path: Path, root: Path) -> Path:
    relative = path.relative_to(root)
    parts: list[str] = []
    for index, part in enumerate(relative.parts):
        file_part = index == len(relative.parts) - 1
        if file_part and part in _SAFE_FILES:
            parts.append(part)
        elif not file_part and part in _SAFE_DIRS:
            parts.append(part)
        else:
            parts.append(_digest_name("log" if file_part else "dir", relative.as_posix() if file_part else part))
    return root.joinpath(*parts)


def _path_failures(relative: Path) -> list[str]:
    failures: list[str] = []
    for index, part in enumerate(relative.parts):
        file_part = index == len(relative.parts) - 1
        allowed = part in (_SAFE_FILES if file_part else _SAFE_DIRS) or _GENERATED.fullmatch(part)
        if not allowed:
            failures.append(part)
        elif _GENERATED.fullmatch(part) and forbidden_reasons(part.encode()):
            failures.append(part)
    return failures


def redact_file(data: bytes, filename: str) -> bytes:
    match = _ORDER_FILE.fullmatch(filename)
    if match:
        order = match.group("order").encode()
        if len(order) >= 3:
            data = data.replace(order, REDACTED.encode())
    return redact_bytes(data)


def sanitize_tree(root: Path) -> None:
    failures: list[str] = []
    files = sorted(p for p in root.rglob("*") if p.is_file())
    planned: list[tuple[Path, Path]] = []
    used: set[Path] = set()
    for path in files:
        dest = _dest_for(path, root)
        if dest in used:
            digest = hashlib.sha256(str(path.relative_to(root)).encode()).hexdigest()[:12]
            dest = dest.with_name(f"log-{digest}")
        if dest in used:
            failures.append(f"{path}: redacted name collision")
            continue
        used.add(dest)
        planned.append((path, dest))
    if failures:
        _refuse(failures)

    published: list[tuple[Path, str]] = []
    for path, dest in planned:
        original_name = path.name
        if path != dest:
            dest.parent.mkdir(parents=True, exist_ok=True)
            path.rename(dest)
        published.append((dest, original_name))

    for path, original_name in published:
        relative = path.relative_to(root)
        path_failures = _path_failures(relative)
        if path_failures:
            failures.append(f"{path}: path {', '.join(path_failures)}")
            continue
        raw = path.read_bytes()
        if b"\x00" in raw:
            failures.append(f"{path}: binary file")
            continue
        cleaned = redact_file(raw, original_name)
        path.write_bytes(cleaned)
        reasons = forbidden_reasons(cleaned)
        order = _ORDER_FILE.fullmatch(original_name)
        if order and len(order.group("order")) >= 3 and order.group("order").encode() in cleaned:
            reasons.append("cluster-order")
        if reasons:
            failures.append(f"{path}: {', '.join(reasons)}")
    if failures:
        _refuse(failures)


def _refuse(failures: list[str]) -> None:
    for failure in failures:
        print(f"refusing diagnostic upload: {failure}", file=sys.stderr)
    raise SystemExit(1)


def main(argv: list[str]) -> None:
    if len(argv) != 2:
        print(f"usage: {argv[0]} <staging-directory>", file=sys.stderr)
        raise SystemExit(2)
    root = Path(argv[1])
    if not root.is_dir():
        print(f"refusing diagnostic upload: {root} is not a directory", file=sys.stderr)
        raise SystemExit(1)
    sanitize_tree(root)


if __name__ == "__main__":
    main(sys.argv)
