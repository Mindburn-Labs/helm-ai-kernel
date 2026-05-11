#!/usr/bin/env bash
set -e

echo "==> HELM Launch Demo: MCP Quarantine"
echo "Demonstrating how HELM wraps an upstream MCP server with a Fail-Closed boundary."
echo ""

make build > /dev/null

echo "==> 1. Generating Execution-Firewall Wrapper Profile"
./bin/helm mcp wrap \
  --server-id "github-mcp-upstream" \
  --upstream-command "npx -y @modelcontextprotocol/server-github" \
  --require-pinned-schema=true

echo ""
echo "==> 2. HELM Interceptor Output"
echo "HELM will intercept all MCP tools/call requests and evaluate them against the boundary policy."
echo "If a tool call violates policy, the interceptor returns an MCP error and logs the failed receipt."
echo ""
echo "To start the interceptor manually:"
echo "  ./bin/helm mcp serve --profile github-mcp-upstream"
echo ""
echo "MCP clients will now see 'HELM Boundary Interceptor' instead of raw GitHub tools."
