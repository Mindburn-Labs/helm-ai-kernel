#!/usr/bin/env bash
# Run every Postgres-gated proof in scripts/ci/postgres-proofs.txt against the
# database in HELM_TEST_POSTGRES_URL, and fail unless each one passed its full
# count. Without a database the proofs skip, and a skip is a failure here.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
MANIFEST="$ROOT/scripts/ci/postgres-proofs.txt"
CHECK="$ROOT/scripts/ci/check_postgres_proofs.py"

if [ -z "${HELM_TEST_POSTGRES_URL:-}" ]; then
    echo "::error::HELM_TEST_POSTGRES_URL is not set; the Postgres proofs cannot run, and skipping them is not a pass"
    exit 2
fi

# Every gated test in the tree is listed, and every listed test still exists.
python3 "$CHECK" discover "$ROOT/core" "$MANIFEST"

LOG="$(mktemp "${TMPDIR:-/tmp}/helm-postgres-proofs.XXXXXX")"
trap 'rm -f "$LOG"' EXIT
status=0
# One go test per (package, count, mode); -p 1 keeps packages off the shared database
# at the same time.
while read -r package count mode tests; do
    race=()
    [ "$mode" = race ] && race=(-race)
    echo "==> go test ${race[*]} -count=$count ./$package -run '^($tests)\$'"
    (cd "$ROOT/core" && go test "${race[@]}" -p 1 -count="$count" -v "./$package" -run "^(${tests})\$") >>"$LOG" 2>&1 || status=1
done < <(python3 - "$MANIFEST" <<'PY'
import sys
from collections import defaultdict
groups = defaultdict(list)
for raw in open(sys.argv[1]):
    fields = raw.split("#", 1)[0].split()
    if fields:
        groups[(fields[0], fields[2], fields[3])].append(fields[1])
for (package, count, mode), tests in sorted(groups.items()):
    print(package, count, mode, "|".join(sorted(tests)))
PY
)
grep -E '^\s*--- (PASS|FAIL|SKIP)|^(ok|FAIL)\s' "$LOG" || true
python3 "$CHECK" verify "$MANIFEST" "$LOG" || status=1
if [ "$status" -ne 0 ]; then
    echo "::group::go test output"
    cat "$LOG"
    echo "::endgroup::"
fi
exit "$status"
