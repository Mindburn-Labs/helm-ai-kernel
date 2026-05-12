#!/usr/bin/env bash
# Re-run core tests to surface flakes in nightly/advisory quality profiles.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
COUNT="${QUALITY_FLAKE_COUNT:-10}"
PACKAGES="${QUALITY_FLAKE_PACKAGES:-./pkg/...}"

cd "$ROOT/core"
for run in $(seq 1 "$COUNT"); do
    echo "flake run $run/$COUNT: go test $PACKAGES"
    # shellcheck disable=SC2086
    go test $PACKAGES -count=1
done

echo "Flake detector passed: $COUNT clean run(s)."
