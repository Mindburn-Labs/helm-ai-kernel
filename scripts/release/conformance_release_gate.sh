#!/usr/bin/env bash
set -euo pipefail

REPORT_PATH="${1:-${HELM_CONFORMANCE_REPORT:-artifacts/conformance/conform_report.json}}"

python3 - "$REPORT_PATH" <<'PY'
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
if not path.exists():
    raise SystemExit(f"conformance-release-gate: missing conformance report: {path}")

report = json.loads(path.read_text())
metadata = report.get("metadata") or {}
seeded = metadata.get("seed_baseline") is True
mode = str(metadata.get("evidence_mode") or "").strip().lower()
eligible = metadata.get("release_certification_eligible")

if seeded or mode == "seeded-local-baseline" or eligible is False:
    raise SystemExit(
        "conformance-release-gate: seeded local baseline evidence cannot certify a public release; "
        "run release EvidencePack verification and provide a non-seeded conformance report"
    )
if not report.get("pass", False):
    raise SystemExit("conformance-release-gate: conformance report did not pass")
if not mode:
    raise SystemExit("conformance-release-gate: conformance report missing metadata.evidence_mode")

print(f"conformance-release-gate: accepted {path} evidence_mode={mode}")
PY
