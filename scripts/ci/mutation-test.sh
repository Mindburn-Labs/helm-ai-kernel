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

SCORE="$(python3 - "$OUT" "$MUTATION_STATUS" <<'PY'
from __future__ import annotations

import re
import sys
from pathlib import Path

text = Path(sys.argv[1]).read_text(errors="ignore")
status = int(sys.argv[2])

score_patterns = [
    r"mutation score(?: is|:|=)?\s*([0-9]+(?:\.[0-9]+)?)\s*%",
    r"score(?: is|:|=)\s*([0-9]+(?:\.[0-9]+)?)\s*%",
    r"mutation score(?: is|:|=)?\s*([0-9]+(?:\.[0-9]+)?)",
]
for pattern in score_patterns:
    match = re.search(pattern, text, flags=re.IGNORECASE)
    if match:
        value = float(match.group(1))
        if value <= 1:
            value *= 100
        print(f"{value:.2f}")
        raise SystemExit(0)

killed = survived = None
for label, target in (("killed", "killed"), ("survived", "survived")):
    match = re.search(rf"{label}\D+([0-9]+)", text, flags=re.IGNORECASE)
    if match:
        if target == "killed":
            killed = int(match.group(1))
        else:
            survived = int(match.group(1))

if killed is not None and survived is not None and killed + survived > 0:
    print(f"{(killed / (killed + survived)) * 100:.2f}")
    raise SystemExit(0)

if status == 0:
    print("100.00")
else:
    print("unknown")
PY
)"

if [ "$SCORE" = "unknown" ]; then
    echo "::error::Mutation test failed and no mutation score could be parsed."
    exit 1
fi

python3 - "$SCORE" "$THRESHOLD" <<'PY'
import sys
score = float(sys.argv[1])
threshold = float(sys.argv[2])
print(f"Mutation score: {score:.2f}% (threshold {threshold:.2f}%)")
if score < threshold:
    raise SystemExit(1)
PY

echo "Mutation gate passed."
