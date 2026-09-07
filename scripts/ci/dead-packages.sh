#!/usr/bin/env bash
# Importer-less package census for core/pkg. See check_dead_packages.py.
#
#   scripts/ci/dead-packages.sh                     # text summary, default allowlist
#   scripts/ci/dead-packages.sh --allowlist FILE    # alternative allowlist ('-' disables)
#   scripts/ci/dead-packages.sh --format json       # machine-readable
#
# Exits 1 when an importer-less package is not allowlisted (or an allowlist
# entry is stale), 2 on tooling errors, 0 otherwise.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"
export GOWORK=off
exec python3 scripts/ci/check_dead_packages.py "$@"
