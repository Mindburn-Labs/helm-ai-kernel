#!/usr/bin/env bash
# ==============================================================================
# HELM AI Kernel - Double-Click Console Launcher
# ==============================================================================
# Double-click this file on macOS to build, run, and open the Console instantly!
# ==============================================================================
set -euo pipefail

# Ensure we are executing from the correct repository root
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

PORT=8080
ADMIN_KEY="admin-key"
TENANT_ID="default"
DATA_DIR="$ROOT/data/console-playground"

clear
echo "======================================================================"
echo "   🛡️   HELM AI KERNEL: LAUNCHING INTERACTIVE CONSOLE"
echo "======================================================================"
echo "   This tool will automatically compile, configure, and open the"
echo "   HELM Console UI in your default web browser."
echo "======================================================================"
echo ""

# 1. Check dependencies
echo " ==> Checking environment dependencies..."
if ! command -v go &>/dev/null; then
  echo " [ERROR] Go compiler not found. Please install Go from: https://go.dev/dl/"
  read -p "Press Enter to exit..."
  exit 1
fi

if ! command -v npm &>/dev/null; then
  echo " [ERROR] Node.js & npm not found. Please install Node.js from: https://nodejs.org/"
  read -p "Press Enter to exit..."
  exit 1
fi

# 2. Build Go application and compile console
echo " ==> Compiling kernel engine..."
make build >/dev/null

echo " ==> Building frontend interfaces..."
cd apps/console
npm run build >/dev/null 2>&1
cd "$ROOT"

# 3. Create persistent playground directory
mkdir -p "$DATA_DIR"

# 4. Open default web browser in the background
echo " ==> Starting web browser..."
(
  sleep 1.5
  open "http://127.0.0.1:$PORT/"
) &

# 5. Serve persistent boundary console
echo " ==> Serving HELM boundary live on http://127.0.0.1:$PORT"
echo "     Press [Ctrl + C] in this window to stop the server at any time."
echo "======================================================================"
echo ""

HELM_ADMIN_API_KEY="$ADMIN_KEY" \
./bin/helm-ai-kernel serve \
  --console \
  --console-dir apps/console/dist \
  --policy examples/launch/policies/agent_tool_call_boundary.toml \
  --addr 127.0.0.1 \
  --port "$PORT" \
  --data-dir "$DATA_DIR"
