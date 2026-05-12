#!/usr/bin/env bash
set -e

echo "==> HELM Launch Readiness Smoke Test"
echo "Running full verification suite..."

echo ""
echo "[1/6] Building HELM binaries..."
make build

echo ""
echo "[2/6] Running unit tests..."
make test > /dev/null

echo ""
echo "[3/6] Running Local Demo Validation..."
bash ./scripts/launch/demo-local.sh > /dev/null
echo "✅ Local Demo Passed"

echo ""
echo "[4/6] Running Proof Validation..."
bash ./scripts/launch/demo-proof.sh > /dev/null
echo "✅ Proof Validation Passed"

echo ""
echo "[5/6] Running MCP Wrapper Validation..."
bash ./scripts/launch/demo-mcp.sh > /dev/null
echo "✅ MCP Wrapper Passed"

echo ""
echo "[6/6] Running Local OpenAI Proxy Validation..."
bash ./scripts/launch/demo-openai-proxy.sh > /dev/null
echo "✅ OpenAI Proxy Passed"

echo ""
echo "🚀 HELM OSS is Launch Ready! All smoke tests passed."
