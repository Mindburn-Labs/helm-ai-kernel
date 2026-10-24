#!/usr/bin/env bash
# Provision the exact PostgreSQL major required by postgres_proofs_gate.sh.
# https://www.postgresql.org/download/linux/ubuntu/ documents the signed PGDG
# repository for supported Ubuntu versions whose native packages omit 16.
set -euo pipefail

verify_postgres16() {
    local pg_bindir="$1" pg_binary pg_version
    for pg_binary in initdb postgres; do
        [ -x "$pg_bindir/$pg_binary" ] || { echo "::error::PostgreSQL 16 $pg_binary is missing"; return 1; }
        pg_version="$("$pg_bindir/$pg_binary" --version)"
        echo "$pg_version"
        grep -Eq ' \(PostgreSQL\) 16(\.|$)' <<<"$pg_version" ||
            { echo "::error::$pg_binary is not PostgreSQL 16"; return 1; }
    done
}

# A filesystem root is accepted only by this sourced function for the isolated
# self-tests. The executable entry point always provisions the runner itself.
install_postgres16() (
    set -euo pipefail
    pg_root="${1:-}"
    pg_bindir="$pg_root/usr/lib/postgresql/16/bin"
    [ "$(uname -s)" = Linux ] && [ "$(uname -m)" = x86_64 ] ||
        { echo "::error::PostgreSQL proof setup requires Linux x86_64"; exit 1; }
    # /etc/os-release is the runner's system-owned distribution identity.
    ID= VERSION_CODENAME=
    . "$pg_root/etc/os-release"
    [ "$ID" = ubuntu ] || { echo "::error::PostgreSQL proof setup requires Ubuntu"; exit 1; }
    case "$VERSION_CODENAME" in
        jammy|noble|resolute|stonking) ;;
        *) echo "::error::Unsupported Ubuntu suite: $VERSION_CODENAME"; exit 1 ;;
    esac
    if [ -x "$pg_bindir/initdb" ] && [ -x "$pg_bindir/postgres" ]; then
        verify_postgres16 "$pg_bindir"
        exit 0
    fi
    if ! apt-cache show postgresql-16 >/dev/null 2>&1; then
        : "${RUNNER_TEMP:?RUNNER_TEMP is required}"
        pg_work="$(mktemp -d "${RUNNER_TEMP}/pg16-install.XXXXXX")"
        trap 'rm -rf "$pg_work"' EXIT
        curl -fsSL --retry 5 --retry-all-errors \
            -o "$pg_work/key.asc" https://www.postgresql.org/media/keys/ACCC4CF8.asc
        # Exact official key; fingerprint B97B0AFCAA1A47F044F244A07FCC7D46ACCC4CF8.
        printf '%s  %s\n' 0144068502a1eddd2a0280ede10ef607d1ec592ce819940991203941564e8e76 \
            "$pg_work/key.asc" | sha256sum --check --strict -
        pg_key="$pg_root/usr/share/postgresql-common/pgdg/apt.postgresql.org.asc"
        sudo install -d "$(dirname "$pg_key")" "$pg_root/etc/apt/sources.list.d"
        sudo install -m 0644 "$pg_work/key.asc" "$pg_key"
        cat >"$pg_work/pgdg.sources" <<EOF
Types: deb
URIs: https://apt.postgresql.org/pub/repos/apt
Suites: $VERSION_CODENAME-pgdg
Architectures: amd64
Components: main
Signed-By: $pg_key
EOF
        sudo install -m 0644 "$pg_work/pgdg.sources" "$pg_root/etc/apt/sources.list.d/pgdg.sources"
        sudo apt-get update -qq
    fi
    sudo apt-get install --yes --no-install-recommends postgresql-16
    verify_postgres16 "$pg_bindir"
)

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
    [ "$#" -eq 0 ] || { echo "::error::install_postgres16.sh accepts no arguments"; exit 1; }
    install_postgres16
fi
