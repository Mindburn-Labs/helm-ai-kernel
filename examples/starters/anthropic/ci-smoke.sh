#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../../.." && pwd)"
HELM_BIN="${REPO_ROOT}/bin/helm"
TMPDIR_CI=$(mktemp -d)
trap "rm -rf $TMPDIR_CI" EXIT
echo "=== Anthropic Starter CI Smoke ==="
[[ -x "$HELM_BIN" ]] || { echo "FAIL: helm binary not found"; exit 1; }
"$HELM_BIN" init claude "$TMPDIR_CI/test" 2>&1
for f in helm.yaml .env; do [[ -f "$TMPDIR_CI/test/$f" ]] || { echo "FAIL: $f missing"; exit 1; }; done
"$HELM_BIN" doctor --dir "$TMPDIR_CI/test" 2>&1 || true
echo "=== PASS ==="
