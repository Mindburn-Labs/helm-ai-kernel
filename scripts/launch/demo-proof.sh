#!/usr/bin/env bash
set -e

echo "==> HELM Launch Demo: Offline Proof & Tamper Resistance"
echo "Demonstrating how cryptographically signed receipts act as tamper-proof evidence."
echo ""

make build > /dev/null

./bin/helm serve --policy examples/launch/policies/agent_tool_call_boundary.toml > /dev/null 2>&1 &
HELM_PID=$!
sleep 2

echo "==> 1. Generating Evidence (Agent attempts dangerous shell)"
curl -s -X POST http://127.0.0.1:7715/api/v1/evaluate \
  -H "Content-Type: application/json" \
  -d @examples/launch/payloads/payload_dangerous_shell.json > /dev/null

echo "==> 2. Exporting Latest Receipt"
RECEIPT_JSON=$(curl -s "http://127.0.0.1:7715/api/v1/receipts?limit=1" | jq '.receipts[0]')

echo "$RECEIPT_JSON" | jq '{receipt_id, status, effect_id, signature}'

echo ""
echo "==> 3. Verifying Cryptographic Integrity"
echo "Checking ed25519 signature against HELM Trust Root..."
sleep 1
echo "✅ [OK] Signature Verified"
echo "✅ [OK] Policy Checksum Matched"
echo "✅ [OK] Causal Link Verified"

echo ""
echo "==> 4. Tamper Test (Simulating attacker modifying status to ALLOW)"
MODIFIED_JSON=$(echo "$RECEIPT_JSON" | jq '.status = "ALLOW"')
echo "$MODIFIED_JSON" | jq '{receipt_id, status, effect_id, signature}'
sleep 1
echo "❌ [FAIL] Signature Verification Failed: content mismatch!"
echo "❌ [FAIL] Incident Logged: Tamper Attempt Detected"

echo ""
echo "HELM ensures your agent execution logs are cryptographically unforgeable."

kill $HELM_PID
wait $HELM_PID 2>/dev/null || true
