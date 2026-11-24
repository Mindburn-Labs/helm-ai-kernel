"""Read checksum files and in-toto subject digests for release asset drift."""

from __future__ import annotations

import base64
import json
import re
from pathlib import Path
from typing import Any


def parse_sha256sums(data: bytes) -> dict[str, str]:
    checksums: dict[str, str] = {}
    for line in data.decode("utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        match = re.match(r"^([0-9a-fA-F]{64}) [ *](.+)$", line)
        if match is None:
            raise ValueError(f"invalid SHA256SUMS line: {line!r}")
        digest, name = match.groups()
        checksums[name] = digest.lower()
    if not checksums:
        raise ValueError("SHA256SUMS has no entries")
    return checksums


def decode_dsse_payload(payload: str) -> dict[str, Any]:
    padded = payload + ("=" * (-len(payload) % 4))
    return json.loads(base64.b64decode(padded).decode("utf-8"))


def slsa_statements_from_bundle(data: bytes) -> list[dict[str, Any]]:
    statements: list[dict[str, Any]] = []
    for line in data.decode("utf-8").splitlines() or [data.decode("utf-8")]:
        if not line.strip():
            continue
        doc = json.loads(line)
        if "subject" in doc:
            statements.append(doc)
            continue
        envelope = doc.get("dsseEnvelope") or doc.get("envelope") or {}
        payload = envelope.get("payload")
        if payload:
            statements.append(decode_dsse_payload(payload))
    if not statements:
        raise ValueError("SLSA bundle has no in-toto statements")
    return statements


def slsa_subject_digests(data: bytes) -> dict[str, str]:
    subjects: dict[str, str] = {}
    for statement in slsa_statements_from_bundle(data):
        for subject in statement.get("subject", []):
            name = Path(str(subject.get("name", ""))).name
            digest = subject.get("digest", {}).get("sha256")
            if not name or not digest:
                continue
            digest = str(digest).lower()
            if name in subjects and subjects[name] != digest:
                raise ValueError(f"conflicting SLSA subject digest for {name}")
            subjects[name] = digest
    if not subjects:
        raise ValueError("SLSA bundle has no sha256 subjects")
    return subjects
