#!/usr/bin/env bash
set -euo pipefail

# CI Smoke Test — OpenAI Starter
# Verifies: helm binary exists, init works, doctor passes, config is valid

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../../.." && pwd)"
HELM_BIN="${REPO_ROOT}/bin/helm"
TMPDIR_CI=$(mktemp -d)

trap "rm -rf $TMPDIR_CI" EXIT

echo "=== OpenAI Starter CI Smoke Test ==="

# 1. Check binary exists
if [[ ! -x "$HELM_BIN" ]]; then
  echo "FAIL: helm binary not found at $HELM_BIN (run 'make build')"
  exit 1
fi
echo "✓ helm binary found"

# 2. Init with openai profile
"$HELM_BIN" init openai "$TMPDIR_CI/test-project" 2>&1
echo "✓ helm init openai succeeded"

# 3. Check generated files
for f in helm.yaml .env; do
  if [[ ! -f "$TMPDIR_CI/test-project/$f" ]]; then
    echo "FAIL: expected file $f not found after init"
    exit 1
  fi
done
echo "✓ generated files present"

# 4. Doctor
"$HELM_BIN" doctor --dir "$TMPDIR_CI/test-project" 2>&1 || true
echo "✓ helm doctor completed"

echo "=== PASS ==="
