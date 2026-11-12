#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
HELM_BIN="${REPO_ROOT}/bin/helm-ai-kernel"
TMPDIR_CI=$(mktemp -d)
trap "rm -rf $TMPDIR_CI" EXIT
echo "=== Codex Starter CI Smoke ==="
[[ -x "$HELM_BIN" ]] || { echo "FAIL: helm binary not found"; exit 1; }
"$HELM_BIN" init codex "$TMPDIR_CI/test" 2>&1
for f in helm.yaml .env.helm.example; do [[ -f "$TMPDIR_CI/test/$f" ]] || { echo "FAIL: $f missing"; exit 1; }; done
(cd "$TMPDIR_CI/test" && "$HELM_BIN" doctor) 2>&1 || true
echo "=== PASS ==="
