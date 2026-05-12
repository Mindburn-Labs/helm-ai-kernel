#!/usr/bin/env bash
set -e

echo "==> HELM Launch Demo: OpenAI Governance Proxy"
echo "Demonstrating how HELM acts as a transparent, governed proxy for the OpenAI SDK."
echo ""

make build > /dev/null

echo "==> 1. Starting HELM Proxy on :9090"
./bin/helm proxy \
  --upstream "https://api.openai.com/v1" \
  --port 9090 \
  --tenant-id "launch-demo-tenant" \
  --daily-limit 5000 \
  --receipts-dir "./data/proxy-receipts" > /dev/null 2>&1 &
PROXY_PID=$!
sleep 2

echo ""
echo "==> 2. Sending ChatCompletion request via proxy"
echo "We configure the OpenAI SDK to use http://127.0.0.1:9090/v1 as the base URL."
echo ""

curl -s -X POST http://127.0.0.1:9090/v1/chat/completions \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer mock-key" \
  -d '{
    "model": "gpt-4o",
    "messages": [{"role": "user", "content": "Hello, HELM!"}]
  }' || true

echo ""
echo "==> 3. Verifying the Intercepted Receipt"
echo "HELM logs the input token intent, enforces the daily budget, and outputs a cryptographically signed receipt."
echo ""
cat ./data/proxy-receipts/*.jsonl 2>/dev/null | tail -n 1 | jq . || echo "Proxy running without mock key forwarding."

kill $PROXY_PID
wait $PROXY_PID 2>/dev/null || true
