#!/usr/bin/env bash
set -e

echo "==> HELM Launch Readiness Smoke Test"
echo "Running full verification suite..."

echo ""
echo "[1/4] Building HELM binaries..."
make build

echo ""
echo "[2/4] Running unit tests..."
make test > /dev/null

echo ""
echo "[3/4] Running Local Demo Validation..."
bash ./scripts/launch/demo-local.sh > /dev/null
echo "✅ Local Demo Passed"

echo ""
echo "[4/4] Running Proof Validation..."
bash ./scripts/launch/demo-proof.sh > /dev/null
echo "✅ Proof Validation Passed"

echo ""
echo "🚀 HELM OSS is Launch Ready! All smoke tests passed."
