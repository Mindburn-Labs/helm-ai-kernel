#!/bin/bash
# boundary_test.sh — the boundary gate must fail on every way of breaking it.
#
# Each case mutates the working tree, asserts the gate's exit status, and
# restores. Run from a clean tree: `make test-boundary`.
#
# This exists because the gate previously reported "OSS boundary check passed"
# for a file injected into a protected package, and nothing would have caught
# that regression coming back.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$REPO_ROOT"

VERIFY="tools/verify-boundary.sh"
GENERATE="tools/boundary/generate-manifest.sh"
MANIFEST="tools/boundary/protected.manifest"
DIRS_FILE="tools/boundary/protected-dirs.sh"
PASS=0; FAIL=0

# Every path this test creates and then deletes. It must own all of them: a
# developer with a file of the same name would otherwise have it silently
# overwritten and removed. The $$ suffix makes a collision improbable; the
# check below makes acting on one impossible.
FIX_UNTRACKED="core/pkg/crypto/zz_boundary_test_untracked.$$.go"
FIX_IGNOREDIR="core/pkg/kernel/.gen_tmp"
FIX_IGNORED="$FIX_IGNOREDIR/zz_boundary_test.$$.go"
FIX_TRACKED="core/pkg/crypto/zz_boundary_test_tracked.$$.go"
FIXTURES=("$FIX_UNTRACKED" "$FIX_IGNORED" "$FIX_TRACKED")

if ! git diff --quiet -- "$MANIFEST" "$DIRS_FILE" "$VERIFY" "$GENERATE"; then
  echo "ERROR: boundary files are dirty; run from a clean tree." >&2
  exit 2
fi

# The gate must be green before the first case, or every "fail" assertion below
# proves nothing — it would fail for a reason the test did not create.
if ! bash "$VERIFY" >/dev/null 2>&1; then
  echo "ERROR: the boundary gate is already failing on this tree." >&2
  echo "Run 'bash $VERIFY' to see why, and start from a clean tree." >&2
  exit 2
fi

for p in "${FIXTURES[@]}"; do
  if [ -e "$p" ]; then
    echo "ERROR: $p already exists; this test would overwrite and delete it." >&2
    exit 2
  fi
done
CREATED_IGNOREDIR=0
[ -d "$FIX_IGNOREDIR" ] || CREATED_IGNOREDIR=1

# Assigned later, but declared here so the trap can restore it even if the run is
# interrupted mid-case with the file modified or deleted.
VICTIM=""

cleanup() {
  rm -f "${FIXTURES[@]}"
  [ "$CREATED_IGNOREDIR" = "1" ] && rmdir "$FIX_IGNOREDIR" 2>/dev/null
  git checkout -q -- "$MANIFEST" "$DIRS_FILE" "$VERIFY" "$GENERATE" 2>/dev/null || true
  [ -n "$VICTIM" ] && git checkout -q -- "$VICTIM" 2>/dev/null
  return 0
}
restore() { git checkout -q -- "$MANIFEST" "$DIRS_FILE" "$VERIFY" "$GENERATE" 2>/dev/null || true; }
trap cleanup EXIT

# assert <expected-exit: pass|fail> <description>
assert() {
  local want="$1" desc="$2" got
  bash "$VERIFY" >/dev/null 2>&1 && got=pass || got=fail
  if [ "$got" = "$want" ]; then
    PASS=$((PASS + 1)); printf '  ok    %s\n' "$desc"
  else
    FAIL=$((FAIL + 1)); printf '  FAIL  %s (wanted %s, got %s)\n' "$desc" "$want" "$got"
  fi
}

echo "boundary gate:"
assert pass "clean tree verifies"

# A protected package is Go source; anything else appearing in one is a finding,
# whether git is configured to ignore it or not — the compiler does not care.
echo "package crypto" > "$FIX_UNTRACKED"
assert fail "untracked file in a protected package"
rm -f "$FIX_UNTRACKED"

mkdir -p "$FIX_IGNOREDIR" && echo "package kernel" > "$FIX_IGNORED"
assert fail "gitignored file in a protected package"
rm -f "$FIX_IGNORED"
[ "$CREATED_IGNOREDIR" = "1" ] && rmdir "$FIX_IGNOREDIR" 2>/dev/null

echo "package crypto" > "$FIX_TRACKED"
git add -f "$FIX_TRACKED" 2>/dev/null
assert fail "tracked file added without regenerating the manifest"
git rm -q -f --cached "$FIX_TRACKED" 2>/dev/null
rm -f "$FIX_TRACKED"

# git is the restore mechanism, not a copied backup. A sibling .bak would itself
# be an untracked file in a protected package — a violation this suite asserts
# on, so both cases below used to fail for the wrong reason. And restoring by
# `cp` from a mktemp file gave the recreated file mktemp's 0600, silently
# retightening a protected source file. `git checkout` restores content and mode
# from the index, and works whether the file was modified or deleted.
VICTIM="$(git ls-files core/pkg/crypto | head -1)"
VICTIM_MODE="$(stat -c '%a' "$VICTIM" 2>/dev/null || stat -f '%Lp' "$VICTIM" 2>/dev/null)"
restore_victim() {
  git checkout -q -- "$VICTIM" 2>/dev/null || true
  [ -n "$VICTIM_MODE" ] && chmod "$VICTIM_MODE" "$VICTIM" 2>/dev/null
  return 0
}

echo "// drift" >> "$VICTIM"
assert fail "protected file modified"
restore_victim

rm -f "$VICTIM"
assert fail "protected file deleted"
restore_victim

# The boundary's own configuration is inside the boundary, so narrowing it is a
# visible act rather than a silent one.
sed -i.tmpbak '/^  core\/pkg\/guardian$/d' "$DIRS_FILE" && rm -f "$DIRS_FILE.tmpbak"
assert fail "a directory removed from the protected list"
restore

echo "# tampered" >> "$VERIFY"
assert fail "the verifier itself modified"
restore

echo "generator:"

# The generator no longer sorts: it relies on the git index being stored sorted
# by path, which drops a GNU-only `sort -z`. That is a documented property of the
# index format rather than an accident, but it is load-bearing for determinism,
# so it is asserted rather than assumed.
bash "$GENERATE" /tmp/boundary_sorted.$$ >/dev/null 2>&1
# Check the PATH column. Sorting whole lines would order by hash, which is random
# — the assertion would fail on a correctly sorted manifest.
if grep -v '^#' /tmp/boundary_sorted.$$ | sed 's/^[0-9a-f]\{64\}  //' | LC_ALL=C sort -c 2>/dev/null; then
  PASS=$((PASS + 1)); echo "  ok    manifest entries come out byte-sorted"
else
  FAIL=$((FAIL + 1)); echo "  FAIL  manifest entries are not sorted"
fi
rm -f /tmp/boundary_sorted.$$

bash "$GENERATE" /tmp/boundary_m1.$$ >/dev/null 2>&1
bash "$GENERATE" /tmp/boundary_m2.$$ >/dev/null 2>&1
if cmp -s /tmp/boundary_m1.$$ /tmp/boundary_m2.$$; then
  PASS=$((PASS + 1)); echo "  ok    two generations are byte-identical"
else
  FAIL=$((FAIL + 1)); echo "  FAIL  two generations differ"
fi
rm -f /tmp/boundary_m1.$$ /tmp/boundary_m2.$$

bash "$GENERATE" >/dev/null 2>&1
# GNU stat first: on Linux `stat -f` does not fail, it reports filesystem status,
# so a BSD-first probe never falls through and returns unparseable output.
MODE="$(stat -c '%a' "$MANIFEST" 2>/dev/null || stat -f '%Lp' "$MANIFEST" 2>/dev/null)"
if [ "$MODE" = "644" ]; then
  PASS=$((PASS + 1)); echo "  ok    regeneration leaves the manifest 0644"
else
  FAIL=$((FAIL + 1)); echo "  FAIL  manifest mode is $MODE, wanted 644"
fi
restore

echo ""
echo "$PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
