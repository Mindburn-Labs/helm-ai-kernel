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

if ! git diff --quiet -- "$MANIFEST" "$DIRS_FILE" "$VERIFY" "$GENERATE"; then
  echo "ERROR: boundary files are dirty; run from a clean tree." >&2
  exit 2
fi

restore() { git checkout -q -- "$MANIFEST" "$DIRS_FILE" "$VERIFY" "$GENERATE" 2>/dev/null || true; }
trap restore EXIT

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
echo "package crypto" > core/pkg/crypto/zz_untracked.go
assert fail "untracked file in a protected package"
rm -f core/pkg/crypto/zz_untracked.go

mkdir -p core/pkg/kernel/.gen_tmp && echo "package kernel" > core/pkg/kernel/.gen_tmp/zz.go
assert fail "gitignored file in a protected package"
rm -f core/pkg/kernel/.gen_tmp/zz.go && rmdir core/pkg/kernel/.gen_tmp 2>/dev/null

echo "package crypto" > core/pkg/crypto/zz_tracked.go
git add -f core/pkg/crypto/zz_tracked.go 2>/dev/null
assert fail "tracked file added without regenerating the manifest"
git rm -q -f --cached core/pkg/crypto/zz_tracked.go 2>/dev/null
rm -f core/pkg/crypto/zz_tracked.go

VICTIM="$(git ls-files core/pkg/crypto | head -1)"
cp "$VICTIM" "$VICTIM.bak"
echo "// drift" >> "$VICTIM"
assert fail "protected file modified"
mv "$VICTIM.bak" "$VICTIM"

cp "$VICTIM" /tmp/boundary_victim.$$ && rm -f "$VICTIM"
assert fail "protected file deleted"
cp /tmp/boundary_victim.$$ "$VICTIM" && rm -f /tmp/boundary_victim.$$

# The boundary's own configuration is inside the boundary, so narrowing it is a
# visible act rather than a silent one.
sed -i.tmpbak '/^  core\/pkg\/guardian$/d' "$DIRS_FILE" && rm -f "$DIRS_FILE.tmpbak"
assert fail "a directory removed from the protected list"
restore

echo "# tampered" >> "$VERIFY"
assert fail "the verifier itself modified"
restore

echo "generator:"
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
