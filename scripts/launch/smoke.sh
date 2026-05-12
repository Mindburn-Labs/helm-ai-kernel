#!/usr/bin/env bash
set -e

echo "==> HELM Launch Readiness Smoke Test"
echo "Running full verification suite..."

echo ""
echo "[1/7] Building HELM binaries..."
make build

echo ""
echo "[2/7] Running unit tests..."
make test > /dev/null

echo ""
echo "[3/7] Running Local Demo Validation..."
bash ./scripts/launch/demo-local.sh > /dev/null
echo "✅ Local Demo Passed"

echo ""
echo "[4/7] Running Proof Validation..."
bash ./scripts/launch/demo-proof.sh > /dev/null
echo "✅ Proof Validation Passed"

echo ""
echo "[5/7] Running MCP Wrapper Validation..."
bash ./scripts/launch/demo-mcp.sh > /dev/null
echo "✅ MCP Wrapper Passed"

echo ""
echo "[6/7] Running Local OpenAI Proxy Validation..."
bash ./scripts/launch/demo-openai-proxy.sh > /dev/null
echo "✅ OpenAI Proxy Passed"

echo ""
echo "[7/7] Running Console Validation..."
bash ./scripts/launch/demo-console.sh > /dev/null
echo "✅ Console Passed"

echo ""
echo "🚀 HELM OSS is Launch Ready! All smoke tests passed."
