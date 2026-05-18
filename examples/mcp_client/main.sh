#!/usr/bin/env bash
# HELM MCP Client Example
# Demonstrates MCP gateway interaction with governance

set -u

HELM_URL="${HELM_URL:-http://localhost:8080}"
TMP_DIR="$(mktemp -d)"
cleanup() {
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

pretty_json() {
  local file="$1"
  python3 -m json.tool "$file" 2>/dev/null || cat "$file"
}

echo "=== HELM MCP Client Example ==="

echo ""
echo "1. List capabilities:"
if curl -s -o "$TMP_DIR/capabilities.json" "$HELM_URL/mcp/v1/capabilities"; then
  pretty_json "$TMP_DIR/capabilities.json"
else
  echo "(server not running)"
fi

echo ""
echo "2. Execute tool (governed):"
if curl -s -X POST "$HELM_URL/mcp/v1/execute" \
  -H "Content-Type: application/json" \
  -d '{"method": "file_read", "params": {"path": "/tmp/test.txt"}}' \
  -o "$TMP_DIR/execute.json"; then
  pretty_json "$TMP_DIR/execute.json"
else
  echo "(server not running)"
fi

echo ""
echo "3. OpenAI-compatible chat:"
if curl -s -X POST "$HELM_URL/v1/chat/completions" \
  -H "Content-Type: application/json" \
  -d '{"model":"gpt-4","messages":[{"role":"user","content":"hello"}]}' \
  -o "$TMP_DIR/chat.json"; then
  pretty_json "$TMP_DIR/chat.json"
else
  echo "(server not running)"
fi

echo ""
echo "Done."
