#!/usr/bin/env bash
set -e

echo "==> HELM Launch Demo: MCP Quarantine"
echo "Demonstrating how HELM wraps an upstream MCP server with a Fail-Closed boundary."
echo ""

make build > /dev/null

FIXTURE_CMD="python3 scripts/launch/mcp-fixture-server.py"

echo "==> 1. Validating local MCP fixture"
python3 scripts/launch/mcp-fixture-server.py --self-test | python3 -c 'import json,sys; payload=json.load(sys.stdin); assert payload["status"] == "ok"; assert payload["tools"][0]["name"] == "local.echo"'

echo "==> 2. Generating Execution-Firewall Wrapper Profile"
PROFILE_JSON="$(./bin/helm mcp wrap \
  --server-id "local-fixture-mcp" \
  --upstream-command "$FIXTURE_CMD" \
  --require-pinned-schema=true \
  --json)"
printf '%s\n' "$PROFILE_JSON" | python3 -c 'import json,sys; payload=json.load(sys.stdin); assert payload["server_id"] == "local-fixture-mcp"; assert payload["transport"] == "stdio"; assert payload["upstream_command"][:2] == ["python3", "scripts/launch/mcp-fixture-server.py"]'
printf '%s\n' "$PROFILE_JSON"

echo ""
echo "==> 3. HELM Interceptor Output"
echo "HELM will intercept all MCP tools/call requests and evaluate them against the boundary policy."
echo "If a tool call violates policy, the interceptor returns an MCP error and logs the failed receipt."
echo ""
echo "To start the interceptor manually:"
echo "  ./bin/helm mcp serve --profile local-fixture-mcp"
echo ""
echo "MCP clients will now see 'HELM Boundary Interceptor' instead of raw GitHub tools."
