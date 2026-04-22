#!/bin/bash
# verify-boundary.sh — SHA256-verified boundary consistency check
#
# For COMMERCIAL repo: compares local protected paths against the manifest
# For OSS repo: regenerates manifest and checks for uncommitted drift
#
# Exit 0: boundary verified
# Exit 1: drift detected

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "═══════════════════════════════════════════════════════"
echo "  HELM Repo Boundary Verification (SHA256)"
echo "═══════════════════════════════════════════════════════"
echo ""

# ── Detect which repo we're in ───────────────────────────
LOCK_FILE="$REPO_ROOT/tools/oss.lock"
MANIFEST="$REPO_ROOT/tools/boundary/protected.manifest"

if [ -f "$LOCK_FILE" ]; then
  MODE="commercial"
elif [ -f "$MANIFEST" ]; then
  MODE="oss"
else
  echo "ERROR: Cannot detect repo type."
  echo "  Expected tools/oss.lock (commercial) or tools/boundary/protected.manifest (OSS)."
  exit 1
fi

echo "  Repo: $MODE"
echo "  Root: $REPO_ROOT"

# ── Commercial verification ─────────────────────────────
if [ "$MODE" = "commercial" ]; then
  if [ ! -f "$MANIFEST" ]; then
    echo "  ERROR: tools/boundary/protected.manifest not found."
    echo "  Run 'tools/sync-oss-kernel.sh' first."
    exit 1
  fi

  source "$LOCK_FILE" 2>/dev/null || true
  echo "  Pinned OSS commit: ${OSS_COMMIT:-UNKNOWN}"
  echo "  Manifest hash:     ${MANIFEST_HASH:-UNKNOWN}"
  echo ""

  # Verify manifest hash matches lock
  ACTUAL_MANIFEST_HASH=$(shasum -a 256 "$MANIFEST" | cut -d' ' -f1)
  if [ "${MANIFEST_HASH:-}" != "$ACTUAL_MANIFEST_HASH" ]; then
    echo "  ✗ FAIL: Manifest hash mismatch"
    echo "    Expected: ${MANIFEST_HASH:-NONE}"
    echo "    Actual:   $ACTUAL_MANIFEST_HASH"
    echo "    Run 'tools/sync-oss-kernel.sh' to resync."
    exit 1
  fi
  echo "  ✓ Manifest hash matches oss.lock"

  # Verify each file from manifest
  PASS=0
  FAIL=0
  MISSING=0

  while IFS= read -r line; do
    [[ "$line" =~ ^#.* ]] && continue
    [[ -z "$line" ]] && continue

    expected_hash=$(echo "$line" | awk '{print $1}')
    filepath=$(echo "$line" | awk '{print $2}')

    if [ ! -f "$REPO_ROOT/$filepath" ]; then
      echo "  ✗ MISSING: $filepath"
      MISSING=$((MISSING + 1))
      continue
    fi

    actual_hash=$(shasum -a 256 "$REPO_ROOT/$filepath" | cut -d' ' -f1)
    if [ "$expected_hash" != "$actual_hash" ]; then
      echo "  ✗ MODIFIED: $filepath"
      FAIL=$((FAIL + 1))
    else
      PASS=$((PASS + 1))
    fi
  done < "$MANIFEST"

  # Check for extraneous files in protected paths
  EXTRA=0
  PROTECTED_DIRS=(
    core/pkg/kernel core/pkg/contracts core/pkg/crypto
    core/pkg/evidencepack core/pkg/proofgraph core/pkg/receipts
    core/pkg/verifier core/pkg/connectors/sandbox core/pkg/conformance
    core/pkg/incubator/audit core/pkg/integrations/receipts
    core/pkg/integrations/capgraph core/pkg/integrations/manifest
    core/pkg/api core/pkg/trust/registry core/pkg/guardian
    protocols schemas
  )

  for dir in "${PROTECTED_DIRS[@]}"; do
    if [ -d "$REPO_ROOT/$dir" ]; then
      find "$REPO_ROOT/$dir" -type f | while read -r f; do
        relpath="${f#$REPO_ROOT/}"
        if ! grep -q "  $relpath$" "$MANIFEST"; then
          echo "  ✗ EXTRA: $relpath (not in manifest)"
          EXTRA=$((EXTRA + 1))
        fi
      done
    fi
  done

  echo ""
  echo "═══════════════════════════════════════════════════════"
  echo "  Results: $PASS verified, $FAIL modified, $MISSING missing, $EXTRA extra"
  echo "═══════════════════════════════════════════════════════"

  TOTAL_ERRORS=$((FAIL + MISSING + EXTRA))
  if [ "$TOTAL_ERRORS" -gt 0 ]; then
    echo ""
    echo "BOUNDARY VIOLATION: $TOTAL_ERRORS issues found."
    echo "  Run 'tools/sync-oss-kernel.sh' to resync from OSS."
    exit 1
  fi

  echo ""
  echo "All $PASS protected files verified. ✓"
  exit 0
fi

# ── OSS verification ────────────────────────────────────
if [ "$MODE" = "oss" ]; then
  echo "  Checking manifest against current tree..."
  echo ""

  PASS=0
  FAIL=0
  STALE=0

  while IFS= read -r line; do
    [[ "$line" =~ ^#.* ]] && continue
    [[ -z "$line" ]] && continue

    expected_hash=$(echo "$line" | awk '{print $1}')
    filepath=$(echo "$line" | awk '{print $2}')

    if [ ! -f "$REPO_ROOT/$filepath" ]; then
      echo "  ✗ DELETED: $filepath (in manifest but not on disk)"
      FAIL=$((FAIL + 1))
      continue
    fi

    actual_hash=$(shasum -a 256 "$REPO_ROOT/$filepath" | cut -d' ' -f1)
    if [ "$expected_hash" != "$actual_hash" ]; then
      STALE=$((STALE + 1))
    else
      PASS=$((PASS + 1))
    fi
  done < "$MANIFEST"

  echo ""
  echo "═══════════════════════════════════════════════════════"
  echo "  Results: $PASS current, $STALE stale, $FAIL errors"
  echo "═══════════════════════════════════════════════════════"

  if [ "$FAIL" -gt 0 ]; then
    echo ""
    echo "ERROR: $FAIL files deleted or missing. Regenerate manifest."
    exit 1
  fi

  if [ "$STALE" -gt 0 ]; then
    echo ""
    echo "NOTE: $STALE files changed since last manifest generation."
    echo "  Run 'tools/boundary/generate-manifest.sh' to update."
  fi

  echo ""
  echo "OSS boundary check passed. ✓"
  exit 0
fi
