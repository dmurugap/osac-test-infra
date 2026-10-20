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

_PEM = re.compile(
    rb"-----BEGIN [A-Z0-9 ]+-----.*?-----END [A-Z0-9 ]+-----",
    re.DOTALL,
)
_KUBE_SECRET = re.compile(
    rb"(?im)^([ \t]*(?:certificate-authority-data|client-certificate-data|client-key-data|token|password|client-secret):)[ \t]*\S+"
)
_BEARER = re.compile(rb"(?i)\bBearer\s+\S+")
_AWS_KEY = re.compile(rb"\bAKIA[0-9A-Z]{16}\b")
_ASSIGNMENT = re.compile(rb"(?i)\b(password|token|secret|session)=([^\s&]+)")
_IPV4 = re.compile(
    rb"(?<![0-9])(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)(?:/\d{1,2})?"
)
# Require a hex letter so clock times such as 15:55:01 stay in the journal.
_IPV6 = re.compile(
    rb"(?i)\b(?=[0-9a-f:]*[a-f])(?:[0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}\b"
)
_FQDN = re.compile(
    rb"(?i)\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|net|org|io|dev|local|internal|lan)\b"
)
_LAB_NAME = re.compile(rb"\b(?:clab|test-infra)-[A-Za-z0-9._-]+\b")
_INSTANCE_ID = re.compile(rb"\bi-[0-9a-f]{8,17}\b")
_EC2_HOST = re.compile(rb"\bip(?:-\d{1,3}){4}\b")

_REPLACEMENTS = (
    (_PEM, REDACTED.encode()),
    (_KUBE_SECRET, lambda m: m.group(1) + b" " + REDACTED.encode()),
    (_BEARER, b"Bearer " + REDACTED.encode()),
    (_AWS_KEY, REDACTED.encode()),
    (_ASSIGNMENT, lambda m: m.group(1) + b"=" + REDACTED.encode()),
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
    ("pem", re.compile(rb"-----BEGIN (?:RSA |OPENSSH |EC )?PRIVATE KEY-----|-----BEGIN CERTIFICATE-----")),
    (
        "kubeconfig",
        re.compile(
            rb"(?i)(?:certificate-authority-data|client-certificate-data|client-key-data):[ \t]*(?!\[REDACTED\])\S"
        ),
    ),
    ("aws-key", _AWS_KEY),
    ("bearer", re.compile(rb"(?i)\bBearer\s+(?!\[REDACTED\])\S")),
    ("assignment", re.compile(rb"(?i)\b(?:password|token|secret|session)=(?!\[REDACTED\])\S")),
)


def redact_bytes(data: bytes) -> bytes:
    for pattern, replacement in _REPLACEMENTS:
        data = pattern.sub(replacement, data)
    return data


def forbidden_reasons(data: bytes) -> list[str]:
    return [name for name, pattern in _FORBIDDEN if pattern.search(data)]


def _safe_component(component: str, source: Path) -> str:
    raw = component.encode()
    cleaned = redact_bytes(raw)
    try:
        name = cleaned.decode("utf-8")
    except UnicodeDecodeError:
        name = REDACTED
    name = name.replace("/", "_")
    if name in {"", ".", ".."} or forbidden_reasons(name.encode()):
        digest = hashlib.sha256(str(source).encode()).hexdigest()[:12]
        return f"log-{digest}"
    return name


def _dest_for(path: Path, root: Path) -> Path:
    parts = [_safe_component(part, path) for part in path.relative_to(root).parts]
    return root.joinpath(*parts)


def sanitize_tree(root: Path) -> None:
    failures: list[str] = []
    files = sorted(p for p in root.rglob("*") if p.is_file())
    planned: list[tuple[Path, Path]] = []
    used: set[Path] = set()
    for path in files:
        dest = _dest_for(path, root)
        if dest in used:
            digest = hashlib.sha256(str(path.relative_to(root)).encode()).hexdigest()[:12]
            dest = dest.with_name(f"{digest}-{dest.name}")
        if dest in used:
            failures.append(f"{path}: redacted name collision")
            continue
        used.add(dest)
        planned.append((path, dest))
    if failures:
        _refuse(failures)

    published: list[Path] = []
    for path, dest in planned:
        if path != dest:
            dest.parent.mkdir(parents=True, exist_ok=True)
            path.rename(dest)
        published.append(dest)

    for path in published:
        rel = path.relative_to(root).as_posix().encode()
        path_reasons = forbidden_reasons(rel)
        if path_reasons:
            failures.append(f"{path}: path {', '.join(path_reasons)}")
            continue
        raw = path.read_bytes()
        if b"\x00" in raw:
            failures.append(f"{path}: binary file")
            continue
        cleaned = redact_bytes(raw)
        path.write_bytes(cleaned)
        reasons = forbidden_reasons(cleaned)
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
