#!/usr/bin/env bash
# HELM AI Kernel v0.1 — Use Case Runner
# Runs each use case's tests and counts it as passed only if tests actually ran.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
CORE_DIR="$PROJECT_ROOT/core"
OUTPUT_DIR="$PROJECT_ROOT/artifacts/usecases"

mkdir -p "$OUTPUT_DIR"

PASS=0
FAIL=0
TOTAL=0
TESTS=0

# passed_tests LOG prints how many top-level tests passed in a `go test -v`
# log, and fails if any package selected no tests. `go test -run X` exits 0
# when X matches nothing, so the exit status alone cannot tell a passing use
# case from one that ran zero tests.
passed_tests() {
    local log="$1"
    if grep -q 'no tests to run' "$log"; then
        return 1
    fi
    grep -c '^--- PASS: ' "$log" || true
}

run_uc() {
    local id="$1"
    local name="$2"
    local cmd="$3"
    local log="$OUTPUT_DIR/${id}.log"
    local ran
    TOTAL=$((TOTAL + 1))
    echo -n "  $id: $name ... "
    if ! eval "$cmd" >"$log" 2>&1; then
        echo "❌ FAIL (see $log)"
        FAIL=$((FAIL + 1))
        return
    fi
    if ! ran="$(passed_tests "$log")" || [ "$ran" -eq 0 ]; then
        echo "❌ FAIL: no tests ran (see $log)"
        FAIL=$((FAIL + 1))
        return
    fi
    echo "✅ PASS ($ran tests)"
    PASS=$((PASS + 1))
    TESTS=$((TESTS + ran))
}

echo "HELM Use Case Runner"
echo "═══════════════════"
echo ""

# Positive control: a use case whose -run pattern matches no test must fail.
# If the runner counts it as passed, every PASS below is meaningless, so stop
# before reporting anything.
echo "Self-test (this control must fail):"
run_uc "CONTROL" "empty test selection" \
    "cd $CORE_DIR && go test ./pkg/manifest -run '^TestCrucibleControlMatchesNoTest\$' -v"
if [ "$FAIL" -ne 1 ] || [ "$PASS" -ne 0 ]; then
    echo "crucible self-test failed: a use case that ran no tests was not rejected" >&2
    exit 2
fi
PASS=0
FAIL=0
TOTAL=0
echo ""

# UC-001: PEP Allow (tool call args validation succeeds)
run_uc "UC-001" "PEP Allow" \
    "cd $CORE_DIR && go test ./pkg/manifest -run TestValidateAndCanonicalizeToolArgs -v"

# UC-002: PEP Fail-Closed (unknown, missing and mistyped fields rejected)
run_uc "UC-002" "PEP Fail-Closed" \
    "cd $CORE_DIR && go test ./pkg/manifest -run 'TestValidateAndCanonicalizeToolArgs_(UnknownField|MissingRequired|TypeMismatch)\$' -v"

# UC-003: Approval Ceremony (timelock + hold)
run_uc "UC-003" "Approval Ceremony" \
    "cd $CORE_DIR && go test ./pkg/escalation/ceremony/... -v"

# UC-004 (WASM Transform) and UC-005 (WASM Exhaustion) are retired (T-02).
# Their tests never ran a WASM module: TestWASI_* is arithmetic over
# pkg/runtime/budget, and TestWASISandbox accepted "not yet implemented" as a
# pass. No module can run: WASISandbox.Run always fails in resolvePackToWasm,
# and NewWASISandbox has no caller in a shipped binary (it is on
# scripts/ci/deadcode-allowlist.txt). A use case can return when the sandbox
# executes a module on a shipped path, proven by a looping and an allocating
# .wasm fixture.

# UC-006: Idempotency (receipt-based dedup)
run_uc "UC-006" "Idempotency" \
    "cd $CORE_DIR && go test ./pkg/executor -v"

# UC-007: EvidencePack Export (pack create/verify: round trip, determinism,
# unmanifested entries and unsigned packs refused)
run_uc "UC-007" "EvidencePack Export" \
    "cd $CORE_DIR && go test ./cmd/helm-ai-kernel -run '^(TestExportAndVerify_RoundTrip|TestExportPack_Deterministic|TestVerifyPackRejectsUnmanifestedFile|TestPackVerifyCLIRejectsUnsignedIntegrityOnlyPack|TestPackCreateEmbedsTransparencySTHFromDataDir)\$' -v"

# UC-008: EvidencePack Replay (the tape package behind `helm-ai-kernel replay`:
# manifest hash integrity, corrupted hashes, tape misses, blocked network)
run_uc "UC-008" "EvidencePack Replay" \
    "cd $CORE_DIR && go test ./pkg/tape -v"

# UC-009: Output Drift Detection
run_uc "UC-009" "Output Drift" \
    "cd $CORE_DIR && go test ./pkg/manifest -run TestValidateToolOutput_DriftDetected -v"

# UC-010: Trust Rotation Replay
run_uc "UC-010" "Trust Rotation" \
    "cd $CORE_DIR && go test ./pkg/trust/registry/... -v"

# UC-011 (Island Mode) was a `go build` and is retired: the island-mode check
# (config.RegionalProfile.IsAllowed) has no production caller, so no use case
# can demonstrate it.

# UC-012: Conformance Gates
run_uc "UC-012" "Conformance Gates" \
    "cd $CORE_DIR && go test ./pkg/conform/... -v"

echo ""
echo "═══════════════════"
echo "Results: $PASS passed, $FAIL failed (of $TOTAL); $TESTS tests executed"

if [ "$FAIL" -gt 0 ]; then
    exit 1
fi
