#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TMP="$(mktemp -d)"
PORT="${HELM_LAUNCH_PROOF_PORT:-$((25000 + (RANDOM % 1000)))}"
HEALTH_PORT="${HELM_LAUNCH_PROOF_HEALTH_PORT:-$((26000 + (RANDOM % 1000)))}"
HELM_URL="http://127.0.0.1:${PORT}"
SERVER_LOG="$TMP/helm-server.log"

cleanup() {
  if [ -n "${HELM_PID:-}" ]; then
    kill "$HELM_PID" 2>/dev/null || true
    wait "$HELM_PID" 2>/dev/null || true
  fi
  rm -rf "$TMP"
}
trap cleanup EXIT

cd "$ROOT"

echo "==> HELM Launch Demo: Offline Proof & Tamper Resistance"
echo "Demonstrating how cryptographically signed receipts act as tamper-proof evidence."
echo ""

make build >/dev/null

HELM_HEALTH_PORT="$HEALTH_PORT" ./bin/helm-ai-kernel serve \
  --policy examples/launch/policies/agent_tool_call_boundary.toml \
  --addr 127.0.0.1 \
  --port "$PORT" \
  --data-dir "$TMP/state" \
  >"$SERVER_LOG" 2>&1 &
HELM_PID=$!

for _ in $(seq 1 60); do
  if curl -fsS "$HELM_URL/api/health" >/dev/null 2>&1; then
    break
  fi
  sleep 0.25
done
if ! curl -fsS "$HELM_URL/api/health" >/dev/null 2>&1; then
  cat "$SERVER_LOG"
  echo "HELM boundary did not become healthy"
  exit 1
fi

echo "==> 1. Generating signed DENY receipt for dangerous shell"
echo "==> 2. Verifying receipt signature and ProofGraph hash"
echo "==> 3. Running tamper-failure check by flipping the verdict"
python3 - "$HELM_URL" <<'PY'
import json
import sys
import urllib.request

base_url = sys.argv[1]


def post(path: str, payload: dict) -> dict:
    req = urllib.request.Request(
        base_url + path,
        data=json.dumps(payload).encode(),
        method="POST",
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        return json.loads(resp.read().decode())


run = post(
    "/api/demo/run",
    {
        "action_id": "dangerous_shell",
        "policy_id": "agent_tool_call_boundary",
        "args": {"sample": True, "external_side_effects": False},
    },
)
if run.get("verdict") != "DENY":
    raise AssertionError(f"dangerous_shell verdict = {run.get('verdict')}, want DENY")

receipt = run.get("receipt")
refs = run.get("proof_refs", {})
if not isinstance(receipt, dict):
    raise AssertionError("receipt missing")
for key in ("receipt_id", "signature", "status"):
    if not receipt.get(key):
        raise AssertionError(f"receipt.{key} missing")
if receipt.get("metadata", {}).get("side_effect_dispatched") is not False:
    raise AssertionError("receipt side_effect_dispatched must be false")
receipt_hash = refs.get("receipt_hash")
if not receipt_hash:
    raise AssertionError("proof_refs.receipt_hash missing")

verify = post("/api/demo/verify", {"receipt": receipt, "expected_receipt_hash": receipt_hash})
if verify.get("valid") is not True:
    raise AssertionError(f"receipt verification failed: {verify}")
if verify.get("signature_valid") is not True or verify.get("hash_matches") is not True:
    raise AssertionError(f"verification did not bind signature and hash: {verify}")

tamper = post(
    "/api/demo/tamper",
    {
        "receipt": receipt,
        "expected_receipt_hash": receipt_hash,
        "mutation": "flip_verdict",
    },
)
if tamper.get("valid") is not False:
    raise AssertionError(f"tampered receipt unexpectedly valid: {tamper}")
if tamper.get("signature_valid") is not False or tamper.get("hash_matches") is not False:
    raise AssertionError(f"tamper did not fail signature and hash checks: {tamper}")
if tamper.get("original_hash") == tamper.get("tampered_hash"):
    raise AssertionError("tamper hash did not change")

print(
    json.dumps(
        {
            "receipt_id": receipt["receipt_id"],
            "verdict": run["verdict"],
            "receipt_hash": receipt_hash,
            "verified": verify["valid"],
            "tamper_valid": tamper["valid"],
            "side_effect_dispatched": False,
        },
        indent=2,
        sort_keys=True,
    )
)
PY

echo "✅ Offline proof and tamper-failure demo passed"
