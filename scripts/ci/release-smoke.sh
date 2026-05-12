#!/usr/bin/env bash
# Compatibility wrapper. The maintained release smoke implementation uses
# underscores so Make, docs, and CI have one behavior source.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
exec bash "$ROOT/scripts/ci/release_smoke.sh" "$@"
