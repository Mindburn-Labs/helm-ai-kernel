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
LOCK_FILE="$REPO_ROOT/tools/helm-ai-kernel.lock"
MANIFEST="$REPO_ROOT/tools/boundary/protected.manifest"

if [ -f "$LOCK_FILE" ]; then
  MODE="commercial"
elif [ -f "$MANIFEST" ]; then
  MODE="oss"
else
  echo "ERROR: Cannot detect repo type."
  echo "  Expected tools/helm-ai-kernel.lock (commercial) or tools/boundary/protected.manifest (OSS)."
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
  echo "  ✓ Manifest hash matches helm-ai-kernel.lock"

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
  # shellcheck source=tools/boundary/protected-dirs.sh
  source "$SCRIPT_DIR/boundary/protected-dirs.sh"

  for dir in "${PROTECTED_DIRS[@]}"; do
    if [ -d "$REPO_ROOT/$dir" ]; then
      # Redirect rather than pipe: a `find | while` loop runs in a subshell, so
      # every EXTRA increment was discarded and TOTAL_ERRORS never saw one.
      while IFS= read -r f; do
        relpath="${f#$REPO_ROOT/}"
        if ! grep -q "  $relpath$" "$MANIFEST"; then
          echo "  ✗ EXTRA: $relpath (not in manifest)"
          EXTRA=$((EXTRA + 1))
        fi
      done < <(find "$REPO_ROOT/$dir" -type f)
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
  echo "  Regenerating the manifest from the tracked tree and diffing..."
  echo ""

  EXPECTED="$(mktemp)"
  trap 'rm -f "$EXPECTED"' EXIT

  # Generate to a scratch path — the committed manifest is never written here.
  if ! bash "$SCRIPT_DIR/boundary/generate-manifest.sh" "$EXPECTED" >/dev/null; then
    echo "  ✗ FAIL: manifest generation failed (errors above)."
    exit 1
  fi

  # The manifest is built from tracked files, so an untracked file dropped into
  # a protected package would never appear in the diff below — yet `go build`
  # compiles it. Catch that separately rather than widening the manifest, which
  # would make its contents depend on the state of the working directory.
  # shellcheck source=tools/boundary/protected-dirs.sh
  source "$SCRIPT_DIR/boundary/protected-dirs.sh"
  UNTRACKED=$(cd "$REPO_ROOT" && git ls-files --others --exclude-standard -- "${PROTECTED_DIRS[@]}" "${PROTECTED_FILES[@]}")
  if [ -n "$UNTRACKED" ]; then
    echo "  ✗ UNTRACKED files inside the protected surface:"
    while IFS= read -r u; do echo "      $u"; done <<< "$UNTRACKED"
    echo ""
    echo "ERROR: untracked files in protected directories."
    echo "  Commit them (and regenerate the manifest) or remove them."
    exit 1
  fi

  # One diff subsumes three checks the old per-entry loop could not perform
  # together: modified files, deleted files, and — the gap that let a file
  # injected into a protected directory report "boundary check passed" — files
  # present in the protected surface but absent from the manifest.
  if diff -q "$MANIFEST" "$EXPECTED" >/dev/null 2>&1; then
    ENTRIES=$(grep -cv '^#' "$MANIFEST" || true)
    echo "═══════════════════════════════════════════════════════"
    echo "  Results: $ENTRIES entries, manifest matches the tree"
    echo "═══════════════════════════════════════════════════════"
    echo ""
    echo "OSS boundary check passed. ✓"
    exit 0
  fi

  have_paths="$(mktemp)"; want_paths="$(mktemp)"
  have_lines="$(mktemp)"; want_lines="$(mktemp)"
  trap 'rm -f "$EXPECTED" "$have_paths" "$want_paths" "$have_lines" "$want_lines"' EXIT
  grep -v '^#' "$MANIFEST" | sort > "$have_lines"; awk '{print $2}' "$have_lines" | sort > "$have_paths"
  grep -v '^#' "$EXPECTED" | sort > "$want_lines"; awk '{print $2}' "$want_lines" | sort > "$want_paths"

  ADDED=$(comm -13 "$have_paths" "$want_paths" | wc -l | tr -d ' ')
  REMOVED=$(comm -23 "$have_paths" "$want_paths" | wc -l | tr -d ' ')
  IN_BOTH=$(comm -12 "$have_paths" "$want_paths" | wc -l | tr -d ' ')
  IDENTICAL=$(comm -12 "$have_lines" "$want_lines" | wc -l | tr -d ' ')
  CHANGED=$((IN_BOTH - IDENTICAL))

  echo "  Drift against tools/boundary/protected.manifest:"
  echo "    $ADDED added, $REMOVED removed, $CHANGED modified"
  echo ""
  diff -u "$MANIFEST" "$EXPECTED" | head -60
  echo ""
  echo "═══════════════════════════════════════════════════════"
  echo "  Results: manifest does not match the tree"
  echo "═══════════════════════════════════════════════════════"
  echo ""
  echo "ERROR: the protected surface drifted from the manifest."
  echo "  Run 'tools/boundary/generate-manifest.sh' and commit the result."
  exit 1
fi
