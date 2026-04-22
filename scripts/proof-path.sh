#!/usr/bin/env bash
# proof-path.sh — End-to-end verification from a clean clone.
#
# This script is the canonical "does HELM work?" gate.
# If it exits 0, the repo is in a ship-worthy state.
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
./bin/helm onboard --yes
echo "  ✅ Onboard complete"
echo ""

# ── 3. Demo ─────────────────────────────────
echo "▸ Step 3: Demo (starter organization)"
./bin/helm demo organization --template starter --provider mock
echo "  ✅ Demo complete"
echo ""

# ── 4. Export EvidencePack ──────────────────
echo "▸ Step 4: Export EvidencePack"
./bin/helm export --evidence ./data/evidence --out evidence.tar
echo "  ✅ Export complete"
echo ""

# ── 5. Verify (offline) ────────────────────
echo "▸ Step 5: Verify EvidencePack (air-gapped safe)"
./bin/helm verify --bundle evidence.tar
echo "  ✅ Verify complete"
echo ""

# ── 6. Conformance ─────────────────────────
echo "▸ Step 6: Conformance L1"
./bin/helm conform --level L1 --json
echo ""

echo "▸ Step 7: Conformance L2"
./bin/helm conform --level L2 --json
echo ""

# ── 7. Version coherence ──────────────────
echo "▸ Step 8: Version coherence check"
EXPECTED=$(cat VERSION)
ACTUAL=$(./bin/helm version 2>/dev/null | head -1 | grep -oE 'v[0-9]+\.[0-9]+\.[0-9]+' || echo "unknown")
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
