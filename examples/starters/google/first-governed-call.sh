#!/usr/bin/env bash
set -euo pipefail
BASE_URL="${HELM_BASE_URL:-http://localhost:8080}"
RESPONSE_FILE="$(mktemp)"
cleanup() {
  rm -f "$RESPONSE_FILE"
}
trap cleanup EXIT
pretty_json() {
  python3 -m json.tool "$1" 2>/dev/null || cat "$1"
}
echo "→ Initializing MCP session..."
curl -sS -X POST "$BASE_URL/mcp" \
  -H "Content-Type: application/json" \
  -H "MCP-Protocol-Version: 2025-03-26" \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","clientInfo":{"name":"google-starter"}}}' \
  -o "$RESPONSE_FILE"
cat "$RESPONSE_FILE"
echo ""
echo "→ Listing governed tools..."
curl -sS -X POST "$BASE_URL/mcp" \
  -H "Content-Type: application/json" \
  -H "MCP-Protocol-Version: 2025-03-26" \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' \
  -o "$RESPONSE_FILE"
pretty_json "$RESPONSE_FILE"
echo ""
echo "✓ First governed call complete."
