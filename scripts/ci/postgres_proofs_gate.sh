#!/usr/bin/env bash
# The postgres-proofs quality gate: runs every proof in
# scripts/ci/postgres-proofs.txt against a real PostgreSQL 16 inside
# `make check`, so `ci / gate` blocks on them.
#
# With HELM_TEST_POSTGRES_URL set it uses that database. Otherwise it starts a
# disposable PostgreSQL 16 cluster in UTC on a free loopback port and removes
# it on exit. It finds initdb in HELM_PG_BINDIR, /usr/lib/postgresql/16/bin
# (the postgresql-16 package, which install_check_tools.sh ensures on the CI
# runner) or Homebrew's postgresql@16. No PostgreSQL 16 is a failure, never a
# skip.
#
# Before it runs the proofs, two positive controls show that the gate can
# fail: scripts/ci/postgres_proofs.sh must refuse a run without a database,
# and must refuse a Postgres-gated test that the manifest does not list.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PROOFS="$ROOT/scripts/ci/postgres_proofs.sh"
WORK="$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/helm-pg-proofs.XXXXXX")"
BINDIR=""
DATA="$WORK/data"

cleanup() {
    if [ -n "$BINDIR" ] && [ -f "$DATA/postmaster.pid" ]; then
        LC_ALL=C "$BINDIR/pg_ctl" -D "$DATA" -m fast -w stop >/dev/null 2>&1 || true
    fi
    rm -rf -- "$WORK"
}
trap cleanup EXIT

fail() {
    echo "::error::postgres-proofs: $*"
    exit 1
}

# Control 1: no database is a failure, with the runner's own message.
if env -u HELM_TEST_POSTGRES_URL bash "$PROOFS" >"$WORK/no-db.log" 2>&1; then
    cat "$WORK/no-db.log"
    fail "postgres_proofs.sh passed without HELM_TEST_POSTGRES_URL; a run without a database must fail"
fi
grep -q "HELM_TEST_POSTGRES_URL is not set" "$WORK/no-db.log" ||
    { cat "$WORK/no-db.log"; fail "postgres_proofs.sh failed without a database, but not because the database is missing"; }
echo "positive control: postgres_proofs.sh refuses a run without a database"

# Control 2: a Postgres-gated test missing from the manifest is a failure. The
# planted tree has one listed and one unlisted gated test; discovery runs before
# any database use, so the placeholder URL is never dialled.
mkdir -p "$WORK/planted/pkg/planted"
cat >"$WORK/planted/pkg/planted/planted_test.go" <<'GO'
package planted

func TestPlantedListed(t *testing.T) { _ = os.Getenv("HELM_TEST_POSTGRES_URL") }

func TestPlantedUnlisted(t *testing.T) { _ = os.Getenv("HELM_TEST_POSTGRES_URL") }
GO
echo "pkg/planted TestPlantedListed 1 race" >"$WORK/planted.txt"
if HELM_TEST_POSTGRES_URL=postgres://planted.invalid/none HELM_POSTGRES_PROOFS_CORE="$WORK/planted" \
    HELM_POSTGRES_PROOFS_MANIFEST="$WORK/planted.txt" bash "$PROOFS" >"$WORK/unlisted.log" 2>&1; then
    cat "$WORK/unlisted.log"
    fail "postgres_proofs.sh passed with an unlisted Postgres-gated test"
fi
grep -q "pkg/planted TestPlantedUnlisted skips without HELM_TEST_POSTGRES_URL but is not in" "$WORK/unlisted.log" ||
    { cat "$WORK/unlisted.log"; fail "postgres_proofs.sh failed on the planted tree, but did not name the unlisted test"; }
echo "positive control: postgres_proofs.sh refuses an unlisted Postgres-gated test"

if [ -n "${HELM_TEST_POSTGRES_URL:-}" ]; then
    echo "postgres-proofs: using the database in HELM_TEST_POSTGRES_URL"
    bash "$PROOFS"
    exit 0
fi

for candidate in "${HELM_PG_BINDIR:-}" /usr/lib/postgresql/16/bin /opt/homebrew/opt/postgresql@16/bin /usr/local/opt/postgresql@16/bin; do
    if [ -n "$candidate" ] && [ -x "$candidate/initdb" ] && "$candidate/initdb" --version | grep -Eq ' 16(\.|$)'; then
        BINDIR="$candidate"
        break
    fi
done
[ -n "$BINDIR" ] || fail "no PostgreSQL 16 initdb found (HELM_PG_BINDIR, /usr/lib/postgresql/16/bin, Homebrew postgresql@16); install postgresql-16 or set HELM_TEST_POSTGRES_URL"

PORT="$(python3 -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])')"
# LC_ALL=C: a postmaster started without a valid locale refuses to run on macOS.
LC_ALL=C "$BINDIR/initdb" -D "$DATA" -U postgres --auth=trust --no-locale -E UTF8 >"$WORK/initdb.log" 2>&1 ||
    { cat "$WORK/initdb.log"; fail "initdb failed"; }
LC_ALL=C "$BINDIR/pg_ctl" -D "$DATA" -l "$WORK/postgres.log" -w -o \
    "-c port=$PORT -c listen_addresses=127.0.0.1 -c unix_socket_directories='' -c timezone=UTC -c log_timezone=UTC -c fsync=off" \
    start >/dev/null || { cat "$WORK/postgres.log"; fail "the disposable PostgreSQL cluster did not start"; }
LC_ALL=C "$BINDIR/createdb" -h 127.0.0.1 -p "$PORT" -U postgres helm_proofs
echo "postgres-proofs: disposable $("$BINDIR/postgres" --version) cluster on 127.0.0.1:$PORT, TimeZone $("$BINDIR/psql" -h 127.0.0.1 -p "$PORT" -U postgres -d helm_proofs -Atc 'SHOW TimeZone')"

HELM_TEST_POSTGRES_URL="postgres://postgres@127.0.0.1:$PORT/helm_proofs?sslmode=disable" bash "$PROOFS"
