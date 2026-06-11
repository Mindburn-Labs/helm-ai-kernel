#!/usr/bin/env bash
set -euo pipefail

echo "==> HELM Launch Demo: OpenAI Governance Proxy"
echo "Demonstrating how HELM acts as a transparent, governed proxy for the OpenAI SDK."
echo ""

make build > /dev/null

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/helm-openai-proxy-demo.XXXXXX")"
UPSTREAM_PORT="${HELM_MOCK_OPENAI_PORT:-19090}"
PROXY_PORT="${HELM_PROXY_PORT:-19091}"
UPSTREAM_PID=""
PROXY_PID=""

cleanup() {
  if [ -n "$PROXY_PID" ]; then
    kill "$PROXY_PID" 2>/dev/null || true
    wait "$PROXY_PID" 2>/dev/null || true
  fi
  if [ -n "$UPSTREAM_PID" ]; then
    kill "$UPSTREAM_PID" 2>/dev/null || true
    wait "$UPSTREAM_PID" 2>/dev/null || true
  fi
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

echo "==> 1. Starting local OpenAI-compatible mock upstream on :$UPSTREAM_PORT"
python3 scripts/launch/mock-openai-upstream.py --port "$UPSTREAM_PORT" > "$TMP_DIR/upstream.log" 2>&1 &
UPSTREAM_PID=$!
for _ in $(seq 1 50); do
  curl -fsS "http://127.0.0.1:$UPSTREAM_PORT/healthz" > /dev/null 2>&1 && break
  sleep 0.1
done
curl -fsS "http://127.0.0.1:$UPSTREAM_PORT/healthz" > /dev/null

echo "==> 2. Starting HELM Proxy on :$PROXY_PORT"
./bin/helm-ai-kernel proxy \
  --upstream "http://127.0.0.1:$UPSTREAM_PORT/v1" \
  --port "$PROXY_PORT" \
  --tenant-id "launch-demo-tenant" \
  --daily-limit 5000 \
  --receipts-dir "$TMP_DIR/proxy-receipts" > "$TMP_DIR/proxy.log" 2>&1 &
PROXY_PID=$!
for _ in $(seq 1 50); do
  curl -fsS "http://127.0.0.1:$PROXY_PORT/healthz" > /dev/null 2>&1 && break
  sleep 0.1
done
curl -fsS "http://127.0.0.1:$PROXY_PORT/healthz" > /dev/null

echo ""
echo "==> 3. Sending ChatCompletion request via proxy"
echo "We configure the OpenAI SDK to use http://127.0.0.1:$PROXY_PORT/v1 as the base URL."
echo ""

curl -fsS -X POST "http://127.0.0.1:$PROXY_PORT/v1/chat/completions" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer mock-key" \
  -d '{
    "model": "helm-local-mock",
    "messages": [{"role": "user", "content": "Hello, HELM!"}]
  }' > "$TMP_DIR/proxy-response.json"
python3 - "$TMP_DIR/proxy-response.json" <<'PY'
import json
import sys

payload = json.load(open(sys.argv[1], encoding="utf-8"))
assert payload["id"] == "chatcmpl-helm-local-fixture"
assert payload["choices"][0]["message"]["content"] == "local fixture response"
PY
cat "$TMP_DIR/proxy-response.json"

echo ""
echo "==> 4. Verifying the Intercepted Receipt"
echo "HELM logs the input token intent, enforces the daily budget, and outputs a cryptographically signed receipt."
echo ""
receipt_file="$(find "$TMP_DIR/proxy-receipts" -name '*.jsonl' -type f | sort | tail -n 1)"
test -s "$receipt_file"
tail -n 1 "$receipt_file" | python3 -c 'import json,sys; payload=json.load(sys.stdin); assert payload["status"] == "APPROVED"; assert payload["upstream"].startswith("http://127.0.0.1:")'

echo ""
echo "==> 5. Sending risky tool-call fixture via proxy"
echo "The mock upstream returns an OpenAI-shaped tool_calls response; HELM must deny it before the caller can execute the tool."
echo ""

DENY_STATUS="$(curl -sS -o "$TMP_DIR/proxy-deny-response.json" -D "$TMP_DIR/proxy-deny-headers.txt" -w '%{http_code}' -X POST "http://127.0.0.1:$PROXY_PORT/v1/chat/completions" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer mock-key" \
  -d '{
    "model": "helm-local-tool-fixture",
    "messages": [{"role": "user", "content": "call a denied tool"}]
  }')"

python3 - "$DENY_STATUS" "$TMP_DIR/proxy-deny-headers.txt" "$TMP_DIR/proxy-deny-response.json" <<'PY'
import json
import sys

status, headers_path, body_path = sys.argv[1:4]
assert status == "403", status
headers = {}
for raw in open(headers_path, encoding="utf-8"):
    if ":" not in raw:
        continue
    name, value = raw.split(":", 1)
    headers[name.strip().lower()] = value.strip()
assert headers.get("x-helm-status") == "DENIED", headers
assert headers.get("x-helm-receipt-id"), headers
raw_body = open(body_path, encoding="utf-8").read()
assert "tool_calls" not in raw_body, raw_body
body = json.loads(raw_body)
assert body["helm"]["status"] == "DENIED", body
assert body["error"]["type"] == "helm_governance_denied", body
print(json.dumps({
    "http_status": int(status),
    "x_helm_status": headers["x-helm-status"],
    "receipt_id": headers["x-helm-receipt-id"],
    "tool_calls_redacted": True,
}, sort_keys=True))
PY

receipt_file="$(find "$TMP_DIR/proxy-receipts" -name '*.jsonl' -type f | sort | tail -n 1)"
tail -n 1 "$receipt_file" | python3 -c 'import json,sys; payload=json.load(sys.stdin); assert payload["status"] == "DENIED"; assert payload["tool_calls_intercepted"] == 1; print(json.dumps({"receipt_status":payload["status"],"tool_calls_intercepted":payload["tool_calls_intercepted"],"receipt_id":payload["receipt_id"]}, sort_keys=True))'

echo ""
echo "==> OpenAI proxy demo complete: approved request and denied tool-call receipt verified."
