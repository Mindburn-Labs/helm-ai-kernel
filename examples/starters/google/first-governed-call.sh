#!/usr/bin/env bash
set -euo pipefail
BASE_URL="${HELM_BASE_URL:-http://localhost:8080}"
echo "→ Initializing MCP session..."
curl -sS -X POST "$BASE_URL/mcp" \
  -H "Content-Type: application/json" \
  -H "MCP-Protocol-Version: 2025-03-26" \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","clientInfo":{"name":"google-starter"}}}'
echo ""
echo "→ Listing governed tools..."
curl -sS -X POST "$BASE_URL/mcp" \
  -H "Content-Type: application/json" \
  -H "MCP-Protocol-Version: 2025-03-26" \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' | python3 -m json.tool 2>/dev/null || cat
echo ""
echo "✓ First governed call complete."
