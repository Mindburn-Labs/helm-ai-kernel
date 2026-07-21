#!/usr/bin/env bash
# Governed local inference — end-to-end.
#
# Points an OpenAI-compatible client at HELM instead of at a local model server.
# HELM allows a safe request, denies a risky tool call before the caller can act
# on it, and writes a signed, hash-chained receipt for each decision. The chain
# is then verified offline with no HELM binary and no network.
#
# The upstream here is a local mock so the example runs anywhere. For a real
# local runtime, set HELM_UPSTREAM to your server, e.g.:
#   HELM_UPSTREAM=http://127.0.0.1:11434/v1   # Ollama
#   HELM_UPSTREAM=http://127.0.0.1:8000/v1    # vLLM
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

UPSTREAM_PORT="${HELM_MOCK_OPENAI_PORT:-19092}"
PROXY_PORT="${HELM_PROXY_PORT:-19093}"
HELM_UPSTREAM="${HELM_UPSTREAM:-http://127.0.0.1:${UPSTREAM_PORT}/v1}"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/helm-local-inference.XXXXXX")"
RECEIPTS="$WORK/receipts"
UPSTREAM_PID="" PROXY_PID=""

cleanup() {
  [ -n "$PROXY_PID" ] && { kill "$PROXY_PID" 2>/dev/null || true; wait "$PROXY_PID" 2>/dev/null || true; }
  [ -n "$UPSTREAM_PID" ] && { kill "$UPSTREAM_PID" 2>/dev/null || true; wait "$UPSTREAM_PID" 2>/dev/null || true; }
}
trap cleanup EXIT

wait_health() { for _ in $(seq 1 150); do curl -fsS "$1" >/dev/null 2>&1 && return 0; sleep 0.1; done; curl -fsS "$1" >/dev/null; }

echo "==> Build"
make build >/dev/null

if [ "$HELM_UPSTREAM" = "http://127.0.0.1:${UPSTREAM_PORT}/v1" ]; then
  echo "==> Start local mock model server on :$UPSTREAM_PORT"
  python3 scripts/launch/mock-openai-upstream.py --port "$UPSTREAM_PORT" >"$WORK/upstream.log" 2>&1 &
  UPSTREAM_PID=$!
  wait_health "http://127.0.0.1:$UPSTREAM_PORT/healthz"
fi

echo "==> Start HELM in front of the model server on :$PROXY_PORT (signed receipts)"
./bin/helm-ai-kernel proxy \
  --upstream "$HELM_UPSTREAM" \
  --port "$PROXY_PORT" \
  --tenant-id "local-inference" \
  --sign "governed-local-inference-demo-seed" \
  --receipts-dir "$RECEIPTS" >"$WORK/proxy.log" 2>&1 &
PROXY_PID=$!
wait_health "http://127.0.0.1:$PROXY_PORT/healthz"

echo "==> 1. Safe request → expect ALLOW"
curl -fsS -X POST "http://127.0.0.1:$PROXY_PORT/v1/chat/completions" \
  -H "Content-Type: application/json" -H "Authorization: Bearer local-key" \
  -d '{"model":"helm-local-mock","messages":[{"role":"user","content":"Summarize this report."}]}' \
  | python3 -c 'import json,sys; r=json.load(sys.stdin); print("   upstream reply:", r["choices"][0]["message"]["content"])'

echo "==> 2. Risky tool call → expect DENY before the caller can execute it"
code="$(curl -sS -o "$WORK/deny.json" -D "$WORK/deny.hdr" -w '%{http_code}' \
  -X POST "http://127.0.0.1:$PROXY_PORT/v1/chat/completions" \
  -H "Content-Type: application/json" -H "Authorization: Bearer local-key" \
  -d '{"model":"helm-local-tool-fixture","messages":[{"role":"user","content":"call a denied tool"}]}')"
python3 - "$code" "$WORK/deny.hdr" "$WORK/deny.json" <<'PY'
import sys
code, hdr, body = sys.argv[1:4]
assert code == "403", f"expected 403, got {code}"
headers = {k.strip().lower(): v.strip() for k, v in (l.split(":", 1) for l in open(hdr) if ":" in l)}
assert headers.get("x-helm-status") == "DENIED", headers
assert "tool_calls" not in open(body).read(), "tool_calls must be redacted from a denied response"
print(f"   http {code}, X-Helm-Status: {headers['x-helm-status']}, receipt {headers.get('x-helm-receipt-id','')}")
PY

echo "==> 3. Receipts (one line per decision)"
receipt_file="$(find "$RECEIPTS" -name '*.jsonl' -type f | sort | tail -n1)"
python3 -c 'import json,sys; [print("   ", json.loads(l)["status"], "::", json.loads(l).get("reason_code","")) for l in open(sys.argv[1]) if l.strip()]' "$receipt_file"

echo "==> 4. Verify the receipt chain offline (no binary, no network)"
python3 examples/governed_local_inference/verify_chain.py "$receipt_file"

echo "==> Done. For an exported EvidencePack, verify with: helm-ai-kernel verify <pack>"
