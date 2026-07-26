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

# Resolve both paths before the cd. Resolving BASH_SOURCE afterwards would
# re-interpret a relative invocation against the new directory, so
# `cd tools/boundary && ./generate-manifest.sh` failed to find its own config.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$REPO_ROOT"

# Enumerating tracked files needs a work tree. An exported tree — `git archive`,
# a release tarball, a .git-less build context — would otherwise fail with a bare
# "fatal: not a git repository" from deep inside the pipeline.
if ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  echo "ERROR: this script enumerates git-tracked files and needs a work tree." >&2
  echo "Run it from a clone, not from an exported or archived tree." >&2
  exit 1
fi

MANIFEST="${1:-tools/boundary/protected.manifest}"
mkdir -p "$(dirname "$MANIFEST")"

# shellcheck source=tools/boundary/protected-dirs.sh
source "$SCRIPT_DIR/protected-dirs.sh"

# Fail closed on a missing protected directory. The previous `if [ -d ]` skipped
# it silently, which is how a regeneration could drop hundreds of entries and
# still report success.
missing=()
for dir in "${PROTECTED_DIRS[@]}"; do
  [ -d "$dir" ] || missing+=("$dir")
done
for f in "${PROTECTED_FILES[@]}"; do
  [ -f "$f" ] || missing+=("$f")
done
if [ "${#missing[@]}" -gt 0 ]; then
  echo "ERROR: protected paths missing from the working tree:" >&2
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
  # The manifest is excluded from its own listing — it cannot contain its own hash.
  git ls-files -z -- "${PROTECTED_DIRS[@]}" "${PROTECTED_FILES[@]}" \
      ':!tools/boundary/protected.manifest' \
    | sort -z | while IFS= read -r -d '' f; do
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
# mktemp creates 0600. Moving it over a 0644 file carries that mode across, and
# git tracks only the exec bit, so the tightened mode never shows up in review.
chmod 644 "$MANIFEST"
trap - EXIT
echo "Generated $MANIFEST ($TOTAL files)"
