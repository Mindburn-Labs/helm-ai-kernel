#!/usr/bin/env bash
set -euo pipefail

# First Governed Call — OpenAI via HELM MCP
# Requires: helm mcp serve running on localhost:8080

BASE_URL="${HELM_BASE_URL:-http://localhost:8080}"

echo "→ Sending initialize request..."
SESSION_ID=$(curl -sS -X POST "$BASE_URL/mcp" \
  -H "Content-Type: application/json" \
  -H "MCP-Protocol-Version: 2025-03-26" \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","clientInfo":{"name":"openai-starter"}}}' \
  -D /dev/stderr 2>&1 | grep -i 'mcp-session-id' | cut -d: -f2 | tr -d ' \r' || echo "")

echo "→ Session: ${SESSION_ID:-none}"

echo "→ Listing governed tools..."
curl -sS -X POST "$BASE_URL/mcp" \
  -H "Content-Type: application/json" \
  -H "MCP-Protocol-Version: 2025-03-26" \
  ${SESSION_ID:+-H "MCP-Session-Id: $SESSION_ID"} \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' | python3 -m json.tool 2>/dev/null || cat

echo ""
echo "✓ First governed call complete. Check evidence/receipts/ for the governance receipt."
