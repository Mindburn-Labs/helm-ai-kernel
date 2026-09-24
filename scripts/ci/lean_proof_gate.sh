#!/usr/bin/env bash
# Build the Lean proofs, then prove the build can fail.
#
# `lake build` treats `sorry` as a warning, so a gate that only runs the build
# stays green when a theorem is replaced by `sorry`. The lakefile turns warnings
# into errors; this script checks that it still does. A scratch copy of the
# proofs gets one extra theorem closed by `sorry`, and that copy must fail to
# build for exactly that reason. If it builds, the gate has stopped
# discriminating and this script fails.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PROOFS="$ROOT/proofs"
SCRATCH="$(mktemp -d "${TMPDIR:-/tmp}/helm-lean-control.XXXXXX")"
trap 'rm -rf "$SCRATCH"' EXIT

# An axiom is an unproven assumption that no warning reports.
set +e
axioms="$(grep -nE '^[[:space:]]*(axiom|unsafe[[:space:]]+def|@\[implemented_by)' "$PROOFS"/*.lean)"
grep_status=$?
set -e
case "$grep_status" in
    0)
        echo "::error::the Lean proofs declare an axiom or an unsafe definition:"
        echo "$axioms"
        exit 1
        ;;
    1) ;;
    *)
        echo "::error::could not scan the Lean sources (grep exited $grep_status)"
        exit 2
        ;;
esac

echo "lake build: proofs/Lean"
(cd "$PROOFS/Lean" && lake build)

echo "control: a theorem closed by sorry must fail the build"
mkdir -p "$SCRATCH/proofs"
cp "$PROOFS"/*.lean "$SCRATCH/proofs/"
mkdir -p "$SCRATCH/proofs/Lean"
cp "$PROOFS/Lean/lakefile.lean" "$PROOFS/Lean/lean-toolchain" "$SCRATCH/proofs/Lean/"
printf '\ntheorem helmLeanGateControl : False := by\n  sorry\n' >>"$SCRATCH/proofs/EffectPermitSoundness.lean"

set +e
(cd "$SCRATCH/proofs/Lean" && lake build) >"$SCRATCH/control.log" 2>&1
control_status=$?
set -e
cat "$SCRATCH/control.log"
if [ "$control_status" -eq 0 ]; then
    echo "::error::lake build accepted a theorem closed by sorry; the Lean gate cannot fail"
    exit 1
fi
if ! grep -q "declaration uses 'sorry'" "$SCRATCH/control.log"; then
    echo "::error::the sorry control failed for a different reason (exit $control_status); the gate was not exercised"
    exit 1
fi
echo "control rejected as expected (exit $control_status)"
echo "Lean proof gate passed"
