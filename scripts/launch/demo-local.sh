#!/usr/bin/env bash
set -e

echo "==> Building HELM binary..."
make build

echo "==> Starting HELM Server with Strict Boundary Policy..."
./bin/helm serve --policy examples/launch/policies/agent_tool_call_boundary.toml &
HELM_PID=$!

sleep 2

echo "==> Testing ALLOW: Read Ticket"
curl -s -X POST http://127.0.0.1:7715/api/v1/evaluate \
  -H "Content-Type: application/json" \
  -d @examples/launch/payloads/payload_read_ticket.json | jq .

echo ""
echo "==> Testing DENY: Export Customer List"
curl -s -X POST http://127.0.0.1:7715/api/v1/evaluate \
  -H "Content-Type: application/json" \
  -d @examples/launch/payloads/payload_export_customer.json | jq .

echo ""
echo "==> Testing DENY: Dangerous Shell"
curl -s -X POST http://127.0.0.1:7715/api/v1/evaluate \
  -H "Content-Type: application/json" \
  -d @examples/launch/payloads/payload_dangerous_shell.json | jq .

echo ""
echo "==> Testing ESCALATE: Large Refund"
curl -s -X POST http://127.0.0.1:7715/api/v1/evaluate \
  -H "Content-Type: application/json" \
  -d @examples/launch/payloads/payload_large_refund.json | jq .

echo ""
echo "==> Verifying Receipts (Tail)"
curl -s "http://127.0.0.1:7715/api/v1/receipts?limit=4" | jq .

kill $HELM_PID
wait $HELM_PID 2>/dev/null || true
echo "==> Demo completed."
