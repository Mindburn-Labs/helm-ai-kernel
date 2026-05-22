#!/usr/bin/env bash
# ==============================================================================
# HELM AI Kernel Console Persistent Server
# ==============================================================================
# Starts a persistent local HELM AI Kernel boundary serving the console UI,
# and automatically opens it in your default web browser.
# ==============================================================================
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

PORT=8080
ADMIN_KEY="admin-key"
TENANT_ID="default"
DATA_DIR="./data/console-playground"

# Create a clean state directory
mkdir -p "$DATA_DIR"

echo "======================================================================"
echo " 🛡️  HELM AI Kernel: Interactive Console Sandbox"
echo "======================================================================"
echo " ==> Building local Kernel binary & Console assets..."
make build >/dev/null
echo " ==> Assets compiled successfully."
echo ""
echo " ==> Serving HELM AI Kernel Console:"
echo "     • Host Address:  http://127.0.0.1:$PORT"
echo "     • Tenant ID:     $TENANT_ID"
echo "     • Admin API Key: $ADMIN_KEY"
echo "     • Storing state: $DATA_DIR"
echo "======================================================================"
echo ""
echo " ==> Launching browser to console..."

# Start background thread to open default browser after a short delay
(
  sleep 1.2
  TARGET_URL="http://127.0.0.1:$PORT/"
  
  # Detect operating system and open browser
  if [[ "$OSTYPE" == "darwin"* ]]; then
    open "$TARGET_URL"
  elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
    xdg-open "$TARGET_URL" 2>/dev/null || true
  else
    echo " ==> Please open: $TARGET_URL in your browser."
  fi
) &

# Persistent server execution
HELM_ADMIN_API_KEY="$ADMIN_KEY" \
./bin/helm-ai-kernel serve \
  --console \
  --console-dir apps/console/dist \
  --policy examples/launch/policies/agent_tool_call_boundary.toml \
  --addr 127.0.0.1 \
  --port "$PORT" \
  --data-dir "$DATA_DIR"
