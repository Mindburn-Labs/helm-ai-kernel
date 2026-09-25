#!/usr/bin/env bash
# Fails when retained public files carry an unfinished-work marker. Covers
# .github and sdk, which tools/verify-presentation.sh does not scan. The
# markers are split so this file does not match itself.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

MARKER_A='TO''DO'
MARKER_B='FIX''ME'
MARKER_C='WI''P'
MARKER_D='coming ''soon'
PATTERN="${MARKER_A}|${MARKER_B}|${MARKER_C}|${MARKER_D}"

set +e
rg -n --hidden -S "$PATTERN" \
  README.md docs .github core sdk deploy tests scripts \
  --glob '!**/node_modules/**' \
  --glob '!**/dist/**' \
  --glob '!**/build/**' \
  --glob '!**/target/**' \
  --glob '!sdk/python/helm_sdk/types_gen.py' \
  --glob '!sdk/python/helm_sdk/generated/**' \
  --glob '!scripts/check_documentation_*.py' \
  --glob '!scripts/sdk/gen.sh' \
  --glob '!core/pkg/buildguard/verify.go' \
  --glob '!core/pkg/crypto/canonical_hardening_test.go'
marker_status=$?
set -e

case "$marker_status" in
  0)
    echo "unfinished marker check failed" >&2
    exit 1
    ;;
  1)
    ;;
  *)
    echo "unfinished marker search failed (rg exited $marker_status)" >&2
    exit "$marker_status"
    ;;
esac
