#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

echo "==> HELM Launch Security Gate"

echo "[1/3] Go vulnerability scan"
GOVULNCHECK_VERSION="${GOVULNCHECK_VERSION:-v1.3.0}"
if [[ "${HELM_LAUNCH_SECURITY_USE_INSTALLED_GOVULNCHECK:-0}" == "1" ]] && command -v govulncheck >/dev/null 2>&1; then
  GOVULN_LOG="$(mktemp "${TMPDIR:-/tmp}/helm-govulncheck.XXXXXX")"
  set +e
  bash -c 'cd core && govulncheck ./...' >"$GOVULN_LOG" 2>&1
  status=$?
  set -e
  if [[ "$status" -ne 0 ]]; then
    if [[ "$status" -eq 126 || "$status" -eq 127 || "$status" -eq 134 ]]; then
      echo "installed govulncheck failed to execute; falling back to go run"
      (cd core && go run "golang.org/x/vuln/cmd/govulncheck@${GOVULNCHECK_VERSION}" ./...)
    else
      cat "$GOVULN_LOG"
      exit "$status"
    fi
  else
    cat "$GOVULN_LOG"
  fi
  rm -f "$GOVULN_LOG"
else
  (cd core && go run "golang.org/x/vuln/cmd/govulncheck@${GOVULNCHECK_VERSION}" ./...)
fi

echo "[2/3] High-confidence secret scan"
python3 - "$ROOT" <<'PY'
import os
import pathlib
import re
import subprocess
import sys

root = pathlib.Path(sys.argv[1])
patterns = [
    ("aws_access_key_id", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("github_token", re.compile(r"gh[pousr]_[A-Za-z0-9_]{36,}")),
    ("openai_api_key", re.compile(r"sk-(?:proj-)?[A-Za-z0-9_-]{48,}")),
    ("anthropic_api_key", re.compile(r"sk-ant-[A-Za-z0-9_-]{32,}")),
    ("stripe_live_secret", re.compile(r"sk_live_[A-Za-z0-9]{24,}")),
    ("private_key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----[\s\S]{32,}?-----END (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")),
]
skip_dirs = {
    ".git", "node_modules", "dist", "bin", "target", "build", ".next",
    ".venv", "venv", "__pycache__", "coverage", "tmp",
}
skip_suffixes = {
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".pdf", ".zip",
    ".tar", ".gz", ".tgz", ".mcpb", ".exe", ".db", ".sqlite", ".wasm",
}

files = subprocess.check_output(["git", "ls-files"], cwd=root, text=True).splitlines()
findings = []
for rel in files:
    path = root / rel
    if any(part in skip_dirs for part in pathlib.PurePosixPath(rel).parts):
        continue
    if path.suffix.lower() in skip_suffixes:
        continue
    try:
        data = path.read_text(encoding="utf-8")
    except (UnicodeDecodeError, OSError):
        continue
    for name, pattern in patterns:
        for match in pattern.finditer(data):
            token = match.group(0)
            if name == "aws_access_key_id" and "EXAMPLE" in token:
                continue
            line = data.count("\n", 0, match.start()) + 1
            findings.append(f"{rel}:{line}: {name}")

if findings:
    print("Potential secrets detected:", file=sys.stderr)
    for finding in findings:
        print(f"  {finding}", file=sys.stderr)
    sys.exit(1)
PY

echo "[3/3] SBOM generation and validation"
HELM_VERSION="$(cat VERSION)" bash scripts/ci/generate_sbom.sh >/dev/null
python3 - "$ROOT/sbom.json" <<'PY'
import json
import pathlib
import sys

sbom = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
if sbom.get("bomFormat") != "CycloneDX":
    raise SystemExit("sbom.json is not CycloneDX")
components = sbom.get("components")
if not isinstance(components, list) or not components:
    raise SystemExit("sbom.json has no components")
metadata = sbom.get("metadata", {})
component = metadata.get("component", {})
if component.get("version") != "0.5.0":
    raise SystemExit(f"sbom version mismatch: {component.get('version')}")
PY

echo "✅ Launch security gate passed"
