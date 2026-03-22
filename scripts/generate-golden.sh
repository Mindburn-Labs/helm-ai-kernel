#!/usr/bin/env bash
# generate-golden.sh — Generate golden evidence packs for verification testing.
#
# Usage: bash scripts/generate-golden.sh
#
set -euo pipefail

GOLDEN_DIR="artifacts/golden"
mkdir -p "$GOLDEN_DIR"

echo "══════════════════════════════════════════"
echo "  Generating Golden Evidence Pack"
echo "══════════════════════════════════════════"
echo ""

# 1. Build
echo "▸ Building..."
make build
echo ""

# 2. Onboard
echo "▸ Onboarding..."
./bin/helm onboard --yes
echo ""

# 3. Run demo
echo "▸ Running demo (starter organization, mock provider)..."
./bin/helm demo organization --template starter --provider mock
echo ""

# 4. Export
echo "▸ Exporting evidence pack..."
./bin/helm export --evidence ./data/evidence --out "$GOLDEN_DIR/starter-organization.tar"
echo ""

# 5. Verify
echo "▸ Verifying golden pack..."
./bin/helm verify --bundle "$GOLDEN_DIR/starter-organization.tar"
echo ""

# 6. Conformance
echo "▸ Running conformance..."
./bin/helm conform --level L1 --json > "$GOLDEN_DIR/conformance-l1.json" 2>/dev/null || true
./bin/helm conform --level L2 --json > "$GOLDEN_DIR/conformance-l2.json" 2>/dev/null || true
echo ""

echo "══════════════════════════════════════════"
echo "  ✅ Golden pack: $GOLDEN_DIR/starter-organization.tar"
echo "  ✅ L1 report:   $GOLDEN_DIR/conformance-l1.json"
echo "  ✅ L2 report:   $GOLDEN_DIR/conformance-l2.json"
echo "══════════════════════════════════════════"
