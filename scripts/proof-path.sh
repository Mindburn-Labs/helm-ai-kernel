#!/usr/bin/env bash
# proof-path.sh — End-to-end verification from a clean clone.
#
# This script is the canonical "does HELM work?" gate.
# If it exits 0, the repo is in a ship-worthy state.
#
# Scope note — conformance (steps 6–7): `conform --level L1/L2` exercise the
# conformance gate ENGINE against a deterministic, self-seeded local baseline
# (metadata.evidence_mode="seeded-local-baseline"). That baseline is, by design,
# NOT release-certifiable (release_certification_eligible=false): it seeds
# intentionally-unsigned receipts, so the G1 signature gate fail-closes
# (SIGNATURE_INVALID) and the verdict is "fail" with exit 1. That is the correct
# security posture, not a defect — and no env var (including HELM_SIGNING_KEY_HEX)
# makes the seeded baseline pass. Real release certification requires a
# non-seeded, signed EvidencePack and is gated separately by
# scripts/release/conformance_release_gate.sh. The proof path therefore asserts
# the engine RUNS and emits the expected seeded-local-baseline report — not that
# the local verdict passes.
#
# Usage:
#   bash scripts/proof-path.sh
#
set -euo pipefail

echo "══════════════════════════════════════════"
echo "  HELM Proof Path v$(cat VERSION 2>/dev/null || echo '0.3.0')"
echo "══════════════════════════════════════════"
echo ""

# ── 1. Build ────────────────────────────────
echo "▸ Step 1: Build"
make build
echo "  ✅ Build complete"
echo ""

# ── 2. Onboard ──────────────────────────────
echo "▸ Step 2: Onboard (local setup)"
./bin/helm-ai-kernel onboard --yes
echo "  ✅ Onboard complete"
echo ""

# ── 3. Demo ─────────────────────────────────
echo "▸ Step 3: Demo (starter organization)"
./bin/helm-ai-kernel demo organization --template starter --provider mock
echo "  ✅ Demo complete"
echo ""

# ── 4. Export EvidencePack ──────────────────
echo "▸ Step 4: Export EvidencePack"
./bin/helm-ai-kernel export --evidence ./data/evidence --out evidence.tar
echo "  ✅ Export complete"
echo ""

# ── 5. Verify (offline) ────────────────────
echo "▸ Step 5: Verify EvidencePack (air-gapped safe)"
./bin/helm-ai-kernel verify --bundle evidence.tar
echo "  ✅ Verify complete"
echo ""

# ── 6–7. Conformance gate engine (seeded local baseline) ───────────────────
# See the header scope note: a passing verdict is NOT expected here. We assert
# the engine RAN and emitted a seeded-local-baseline report. A runtime error
# (exit 2) or a missing/non-seeded report is a real failure; a fail-closed
# verdict on the unsigned local baseline (exit 1) is the expected outcome.
run_conform_level() {
    local level="$1" step="$2"
    echo "▸ Step ${step}: Conformance ${level} (gate engine — seeded local baseline)"
    local report rc
    report="$(./bin/helm-ai-kernel conform --level "${level}" --json 2>&1)" && rc=0 || rc=$?
    echo "${report}"
    if [ "${rc}" -eq 2 ]; then
        echo "  ❌ conform ${level} runtime error (exit 2)"
        exit 1
    fi
    if ! grep -q 'seeded-local-baseline' <<<"${report}"; then
        echo "  ❌ conform ${level} did not emit a seeded-local-baseline report"
        exit 1
    fi
    if [ "${rc}" -eq 0 ]; then
        echo "  ✅ ${level} engine ran · verdict PASS (signed release evidence present)"
    else
        echo "  ✅ ${level} engine ran · fail-closed on unsigned local baseline (expected; release cert gated separately)"
    fi
    echo ""
}

run_conform_level L1 6
run_conform_level L2 7

# ── 7. Version coherence ──────────────────
echo "▸ Step 8: Version coherence check"
EXPECTED=$(cat VERSION)
ACTUAL=$(./bin/helm-ai-kernel version 2>/dev/null | head -1 | grep -oE 'v[0-9]+\.[0-9]+\.[0-9]+' || echo "unknown")
if [ "v${EXPECTED}" = "${ACTUAL}" ]; then
    echo "  ✅ Version match: ${ACTUAL}"
else
    echo "  ❌ Version mismatch: expected v${EXPECTED}, got ${ACTUAL}"
    exit 1
fi
echo ""

# ── Done ───────────────────────────────────
echo "══════════════════════════════════════════"
echo "  ✅ Proof Path Complete"
echo "══════════════════════════════════════════"
