#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TMP="$(mktemp -d)"
PORT="${HELM_LAUNCH_DEMO_PORT:-$((23000 + (RANDOM % 1000)))}"
HEALTH_PORT="${HELM_LAUNCH_DEMO_HEALTH_PORT:-$((24000 + (RANDOM % 1000)))}"
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

echo "==> Building HELM binary"
make build >/dev/null

echo "==> Starting local HELM boundary with sample launch policy"
HELM_HEALTH_PORT="$HEALTH_PORT" ./bin/helm serve \
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

echo "==> Running seven-action launch demo"
python3 - "$HELM_URL" <<'PY'
import json
import sys
import urllib.request

base_url = sys.argv[1]
cases = [
    ("read_ticket", "ALLOW"),
    ("draft_reply", "ALLOW"),
    ("small_refund", "ALLOW"),
    ("large_refund", "ESCALATE"),
    ("dangerous_shell", "DENY"),
    ("export_customer_list", "DENY"),
    ("modify_policy", "ESCALATE"),
]
canonical = {"ALLOW", "DENY", "ESCALATE"}


def post(path: str, payload: dict) -> dict:
    req = urllib.request.Request(
        base_url + path,
        data=json.dumps(payload).encode(),
        method="POST",
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        return json.loads(resp.read().decode())


summary = []
for action_id, expected in cases:
    response = post(
        "/api/demo/run",
        {
            "action_id": action_id,
            "policy_id": "agent_tool_call_boundary",
            "args": {"sample": True, "external_side_effects": False},
        },
    )
    verdict = response.get("verdict")
    if verdict not in canonical:
        raise AssertionError(f"{action_id}: non-canonical verdict {verdict!r}")
    if verdict != expected:
        raise AssertionError(f"{action_id}: got {verdict}, want {expected}")
    receipt = response.get("receipt")
    refs = response.get("proof_refs", {})
    if not isinstance(receipt, dict):
        raise AssertionError(f"{action_id}: receipt missing")
    if not receipt.get("receipt_id"):
        raise AssertionError(f"{action_id}: receipt.receipt_id missing")
    if not receipt.get("signature"):
        raise AssertionError(f"{action_id}: receipt.signature missing")
    if not isinstance(refs, dict) or not refs.get("receipt_hash"):
        raise AssertionError(f"{action_id}: proof_refs.receipt_hash missing")
    if receipt.get("metadata", {}).get("side_effect_dispatched") is not False:
        raise AssertionError(f"{action_id}: side_effect_dispatched must be false")
    verification = post(
        "/api/demo/verify",
        {
            "receipt": receipt,
            "expected_receipt_hash": refs["receipt_hash"],
        },
    )
    if verification.get("valid") is not True:
        raise AssertionError(f"{action_id}: receipt verification failed: {verification}")
    summary.append(
        {
            "action_id": action_id,
            "verdict": verdict,
            "receipt_id": receipt["receipt_id"],
            "proof_ref": refs["receipt_hash"],
            "side_effect_dispatched": False,
        }
    )

print(json.dumps({"launch_demo": summary, "external_side_effects": False}, indent=2, sort_keys=True))
PY

echo "==> Local launch demo completed with sample data only."
