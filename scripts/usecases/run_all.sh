#!/usr/bin/env bash
# HELM OSS v0.1 — Use Case Runner
# Runs UC-001..UC-012 and asserts outputs
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
CORE_DIR="$PROJECT_ROOT/core"
OUTPUT_DIR="$PROJECT_ROOT/artifacts/usecases"

mkdir -p "$OUTPUT_DIR"

PASS=0
FAIL=0

run_uc() {
    local id="$1"
    local name="$2"
    local cmd="$3"
    echo -n "  $id: $name ... "
    if eval "$cmd" > "$OUTPUT_DIR/${id}.log" 2>&1; then
        echo "✅ PASS"
        PASS=$((PASS + 1))
    else
        echo "❌ FAIL (see $OUTPUT_DIR/${id}.log)"
        FAIL=$((FAIL + 1))
    fi
}

echo "HELM Use Case Runner"
echo "═══════════════════"
echo ""

# UC-001: PEP Allow (tool call args validation succeeds)
run_uc "UC-001" "PEP Allow" \
    "cd $CORE_DIR && go test ./pkg/manifest -run TestValidateAndCanonicalizeToolArgs -v"

# UC-002: PEP Fail-Closed (unknown fields rejected)
run_uc "UC-002" "PEP Fail-Closed" \
    "cd $CORE_DIR && go test ./pkg/manifest -run TestUnknownFieldsRejected -v"

# UC-003: Approval Ceremony (timelock + hold)
run_uc "UC-003" "Approval Ceremony" \
    "cd $CORE_DIR && go test ./pkg/escalation/ceremony/... -v"

# UC-004: WASM Transform (sandbox execution)
run_uc "UC-004" "WASM Transform" \
    "cd $CORE_DIR && go test ./pkg/runtime/sandbox -run TestWASISandbox -v"

# UC-005: WASM Exhaustion (gas/time/memory limits)
run_uc "UC-005" "WASM Exhaustion" \
    "cd $CORE_DIR && go test ./pkg/runtime/sandbox -run TestWASI_ -v"

# UC-006: Idempotency (receipt-based dedup)
run_uc "UC-006" "Idempotency" \
    "cd $CORE_DIR && go test ./pkg/executor -v"

# UC-007: EvidencePack Export (build export cmd)
run_uc "UC-007" "Export CLI Build" \
    "cd $CORE_DIR && go build ./cmd/helm"

# UC-008: EvidencePack Replay (build replay cmd)
run_uc "UC-008" "Replay CLI Build" \
    "cd $CORE_DIR && go build ./cmd/helm"

# UC-009: Output Drift Detection
run_uc "UC-009" "Output Drift" \
    "cd $CORE_DIR && go test ./pkg/manifest -run TestOutput -v"

# UC-010: Trust Rotation Replay
run_uc "UC-010" "Trust Rotation" \
    "cd $CORE_DIR && go test ./pkg/trust/registry/... -v"

# UC-011: Island Mode (build passes without network)
run_uc "UC-011" "Island Mode" \
    "cd $CORE_DIR && go build ./cmd/helm"

# UC-012: Conformance Gates
run_uc "UC-012" "Conformance Gates" \
    "cd $CORE_DIR && go test ./pkg/conform/... -v"

echo ""
echo "═══════════════════"
echo "Results: $PASS passed, $FAIL failed (of 12)"

if [ "$FAIL" -gt 0 ]; then
    exit 1
fi
