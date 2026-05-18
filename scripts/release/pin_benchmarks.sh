#!/usr/bin/env bash
# Pin the latest benchmark snapshot to a per-release file under
# benchmarks/results/v<version>.json.
#
# Caller: Makefile target `bench-pin`; .github/workflows/release.yml
# `benchmark-pin` job after `make bench-report`.
#
# Reads:  benchmarks/results/latest.json (helm-ai-kernel internal schema produced
#         by `make bench-report`)
# Writes: benchmarks/results/v<version>.json (identical schema, pinned)
set -euo pipefail

VERSION="${1:?usage: pin_benchmarks.sh <version>}"
VERSION="${VERSION#v}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
RESULTS_DIR="$PROJECT_ROOT/benchmarks/results"
LATEST="$RESULTS_DIR/latest.json"
PINNED="$RESULTS_DIR/v${VERSION}.json"

if [ ! -f "$LATEST" ]; then
    echo "::error::benchmarks/results/latest.json missing — run 'make bench-report' first"
    exit 1
fi

mkdir -p "$RESULTS_DIR"
cp "$LATEST" "$PINNED"

echo "pinned $LATEST -> $PINNED"
