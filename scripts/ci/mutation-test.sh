#!/usr/bin/env bash
# Run Go mutation testing with a real thresholded result.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
THRESHOLD="${QUALITY_MUTATION_THRESHOLD:-80}"
PACKAGES="${QUALITY_MUTATION_PACKAGES:-./core/pkg/kernel/...}"
TOOL_VERSION="${QUALITY_MUTATION_TOOL_VERSION:-v0.0.0-20210610104036-6d9217011a00}"
OUT="$(mktemp "${TMPDIR:-/tmp}/helm-mutation.XXXXXX")"
cleanup() {
    rm -f "$OUT"
}
trap cleanup EXIT

if ! command -v go-mutesting >/dev/null 2>&1; then
    echo "Installing go-mutesting@$TOOL_VERSION"
    go install "github.com/zimmski/go-mutesting/cmd/go-mutesting@$TOOL_VERSION"
    export PATH="$PATH:$(go env GOPATH)/bin"
fi

cd "$ROOT"
echo "Running mutation testing: go-mutesting $PACKAGES"
set +e
# shellcheck disable=SC2086
go-mutesting $PACKAGES 2>&1 | tee "$OUT"
MUTATION_STATUS=${PIPESTATUS[0]}
set -e

python3 "$ROOT/scripts/ci/mutation_score.py" "$OUT" "$MUTATION_STATUS" "$THRESHOLD"

echo "Mutation gate passed."
