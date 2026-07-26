#!/bin/bash
# generate-manifest.sh — Generates the canonical protected.manifest
#
# Usage: generate-manifest.sh [OUTPUT_PATH]
#   OUTPUT_PATH defaults to tools/boundary/protected.manifest. Pass an alternate
#   path to generate without touching the committed manifest — tools/verify-boundary.sh
#   uses this to diff the working tree against the manifest.
#
# The output is a pure function of the tracked contents of PROTECTED_DIRS: the
# same tree yields identical bytes on any machine. Nothing environment-derived —
# timestamps, untracked files, locale-dependent ordering — may enter this file,
# because it is committed and is therefore a merge surface on every branch.
set -euo pipefail

# Deterministic ordering regardless of the caller's locale.
export LC_ALL=C

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"

MANIFEST="${1:-tools/boundary/protected.manifest}"
mkdir -p "$(dirname "$MANIFEST")"

# shellcheck source=tools/boundary/protected-dirs.sh
source "$(dirname "${BASH_SOURCE[0]}")/protected-dirs.sh"

# Fail closed on a missing protected directory. The previous `if [ -d ]` skipped
# it silently, which is how a regeneration could drop hundreds of entries and
# still report success.
missing=()
for dir in "${PROTECTED_DIRS[@]}"; do
  [ -d "$dir" ] || missing+=("$dir")
done
if [ "${#missing[@]}" -gt 0 ]; then
  echo "ERROR: protected directories missing from the working tree:" >&2
  printf '  %s\n' "${missing[@]}" >&2
  echo "Refusing to generate a truncated manifest." >&2
  exit 1
fi

TMP="$(mktemp)"
trap 'rm -f "$TMP"' EXIT

{
  echo "# HELM Protected Manifest"
  echo "# Source: git-tracked files under the protected directories."
  echo "# Regenerate with tools/boundary/generate-manifest.sh; verify with tools/verify-boundary.sh."
  echo "# Format: SHA256  PATH"
  echo "# quantum_posture: boundary manifest only; it records crypto file hashes but is not a cryptographic control."
  echo "#"
  # git ls-files, not find: tracked files only, so untracked build artifacts and
  # editor droppings can never enter the manifest or perturb its contents.
  git ls-files -z -- "${PROTECTED_DIRS[@]}" | sort -z | while IFS= read -r -d '' f; do
    if [ ! -f "$f" ]; then
      echo "ERROR: tracked file absent from the working tree: $f" >&2
      exit 1
    fi
    printf '%s  %s\n' "$(shasum -a 256 "$f" | cut -d' ' -f1)" "$f"
  done
} > "$TMP"

TOTAL=$(grep -cv '^#' "$TMP" || true)
if [ "$TOTAL" -eq 0 ]; then
  echo "ERROR: manifest would contain zero entries." >&2
  exit 1
fi

# Guard against a silent shrink: a regeneration that drops a large fraction of
# the protected surface is a broken environment, not a legitimate deletion.
if [ -f "$MANIFEST" ]; then
  PREV=$(grep -cv '^#' "$MANIFEST" || true)
  if [ "$PREV" -gt 0 ] && [ "$((TOTAL * 10))" -lt "$((PREV * 9))" ]; then
    echo "ERROR: manifest would shrink from $PREV to $TOTAL entries (>10%)." >&2
    echo "Refusing to overwrite. Investigate the working tree first." >&2
    exit 1
  fi
fi

mv "$TMP" "$MANIFEST"
trap - EXIT
echo "Generated $MANIFEST ($TOTAL files)"
