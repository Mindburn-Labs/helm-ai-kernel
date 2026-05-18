#!/usr/bin/env bash
set -euo pipefail

# First Governed Call — OpenAI via HELM MCP
# Requires: helm-ai-kernel mcp serve running on localhost:8080

BASE_URL="${HELM_BASE_URL:-http://localhost:8080}"
HEADER_FILE="$(mktemp)"
RESPONSE_FILE="$(mktemp)"
cleanup() {
  rm -f "$HEADER_FILE" "$RESPONSE_FILE"
}
trap cleanup EXIT
pretty_json() {
  python3 -m json.tool "$1" 2>/dev/null || cat "$1"
}

echo "→ Sending initialize request..."
curl -sS -X POST "$BASE_URL/mcp" \
  -H "Content-Type: application/json" \
  -H "MCP-Protocol-Version: 2025-03-26" \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","clientInfo":{"name":"openai-starter"}}}' \
  -D "$HEADER_FILE" \
  -o "$RESPONSE_FILE"
SESSION_ID=$(awk 'BEGIN { IGNORECASE = 1 } /^mcp-session-id:/ { value = substr($0, index($0, ":") + 1); gsub(/^[[:space:]]+|[[:space:]\r]+$/, "", value); print value; exit }' "$HEADER_FILE")
cat "$RESPONSE_FILE"

echo "→ Session: ${SESSION_ID:-none}"

echo "→ Listing governed tools..."
curl -sS -X POST "$BASE_URL/mcp" \
  -H "Content-Type: application/json" \
  -H "MCP-Protocol-Version: 2025-03-26" \
  ${SESSION_ID:+-H "MCP-Session-Id: $SESSION_ID"} \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' \
  -o "$RESPONSE_FILE"
pretty_json "$RESPONSE_FILE"

echo ""
echo "✓ First governed call complete. Check evidence/receipts/ for the governance receipt."
