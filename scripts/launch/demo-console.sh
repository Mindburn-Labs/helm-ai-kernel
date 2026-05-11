#!/usr/bin/env bash
set -e

echo "==> HELM Launch Demo: Console Walkthrough"
echo "Starting the HELM Local Governance Console..."
echo ""

make build > /dev/null

echo "Starting server with console enabled..."
./bin/helm serve --console --policy examples/launch/policies/agent_tool_call_boundary.toml &
HELM_PID=$!
sleep 2

echo ""
echo "Console is now running at http://127.0.0.1:7715"
echo "In this console, you can:"
echo "1. View all intercepted and governed requests."
echo "2. Inspect the cryptographically signed receipts."
echo "3. Review the policy boundaries enforced on the agent."
echo "4. Simulate tools/call requests directly."
echo ""
echo "To exit the demo, press Ctrl+C."
trap "kill $HELM_PID" EXIT
wait $HELM_PID
