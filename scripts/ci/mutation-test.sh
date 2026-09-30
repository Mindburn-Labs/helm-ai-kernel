#!/usr/bin/env bash
# Run Go mutation testing with a real thresholded result.
#
# Tool: the maintained avito-tech fork of go-mutesting, pinned by pseudo-version.
# The original zimmski/go-mutesting (last release 2021) panics inside go/types on
# Go 1.25, so the nightly gate never measured anything. The fork prints the same
# summary line, which scripts/ci/mutation_score.py parses.
#
# Scope: core/pkg/firewall, the egress enforcement package (82.5% when this
# landed; about two and a half minutes). The previous default, core/pkg/kernel,
# is mostly code no shipped binary reaches (see scripts/ci/deadcode-allowlist.txt),
# so killing its mutants proved nothing about enforcement.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
THRESHOLD="${QUALITY_MUTATION_THRESHOLD:-80}"
PACKAGES="${QUALITY_MUTATION_PACKAGES:-./core/pkg/firewall/...}"
TOOL_VERSION="${QUALITY_MUTATION_TOOL_VERSION:-v0.0.0-20251226130216-48d0401f00fb}"
TOOL_DIR="${HELM_CI_TOOLS:-$HOME/.cache/helm-ci-tools}/go-mutesting-$TOOL_VERSION"
OUT="$(mktemp "${TMPDIR:-/tmp}/helm-mutation.XXXXXX")"
cleanup() {
    rm -f "$OUT"
}
trap cleanup EXIT

# Always the pinned binary, never whatever go-mutesting is on PATH.
if [ ! -x "$TOOL_DIR/go-mutesting" ]; then
    echo "Installing avito-tech/go-mutesting@$TOOL_VERSION"
    GOTOOLCHAIN=local GOWORK=off GOBIN="$TOOL_DIR" \
        go install "github.com/avito-tech/go-mutesting/cmd/go-mutesting@$TOOL_VERSION"
fi

cd "$ROOT"
echo "Running mutation testing: go-mutesting $PACKAGES"
set +e
# shellcheck disable=SC2086
"$TOOL_DIR/go-mutesting" $PACKAGES 2>&1 | tee "$OUT"
MUTATION_STATUS=${PIPESTATUS[0]}
set -e

python3 "$ROOT/scripts/ci/mutation_score.py" "$OUT" "$MUTATION_STATUS" "$THRESHOLD"

echo "Mutation gate passed."
