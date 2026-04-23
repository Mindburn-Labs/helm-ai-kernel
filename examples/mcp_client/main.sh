#!/bin/bash
# HELM MCP Client Example
# Demonstrates MCP gateway interaction with governance

HELM_URL="${HELM_URL:-http://localhost:8080}"

echo "=== HELM MCP Client Example ==="

echo ""
echo "1. List capabilities:"
curl -s "$HELM_URL/mcp/v1/capabilities" | python3 -m json.tool 2>/dev/null || echo "(server not running)"

echo ""
echo "2. Execute tool (governed):"
curl -s -X POST "$HELM_URL/mcp/v1/execute" \
  -H "Content-Type: application/json" \
  -d '{"method": "file_read", "params": {"path": "/tmp/test.txt"}}' \
  | python3 -m json.tool 2>/dev/null || echo "(server not running)"

echo ""
echo "3. OpenAI-compatible chat:"
curl -s -X POST "$HELM_URL/v1/chat/completions" \
  -H "Content-Type: application/json" \
  -d '{"model":"gpt-4","messages":[{"role":"user","content":"hello"}]}' \
  | python3 -m json.tool 2>/dev/null || echo "(server not running)"

echo ""
echo "Done."
