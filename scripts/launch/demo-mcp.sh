#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TMP="$(mktemp -d)"
PORT="${HELM_MCP_DEMO_PORT:-$((21000 + (RANDOM % 1000)))}"
HEALTH_PORT="${HELM_MCP_DEMO_HEALTH_PORT:-$((22000 + (RANDOM % 1000)))}"
HELM_URL="http://127.0.0.1:${PORT}"
SERVER_LOG="$TMP/helm-server.log"
FIXTURE_CMD="python3 scripts/launch/mcp-fixture-server.py"
ADMIN_KEY="${HELM_ADMIN_API_KEY:-launch-mcp-local-admin-key}"
TENANT_ID="${HELM_TENANT_ID:-launch-mcp-demo}"

cleanup() {
  if [ -n "${HELM_PID:-}" ]; then
    kill "$HELM_PID" 2>/dev/null || true
    wait "$HELM_PID" 2>/dev/null || true
  fi
  rm -rf "$TMP"
}
trap cleanup EXIT

cd "$ROOT"

echo "==> HELM Launch Demo: MCP Quarantine"
echo "==> Building HELM binary"
make build >/dev/null

echo "==> Inspecting local MCP fixture metadata and schema"
FIXTURE_JSON="$(python3 scripts/launch/mcp-fixture-server.py --self-test)"
TOOL_SCHEMA_JSON="$(printf '%s\n' "$FIXTURE_JSON" | python3 -c 'import json,sys; p=json.load(sys.stdin); print(json.dumps(p["tools"][0]["inputSchema"], sort_keys=True, separators=(",",":")))')"
TOOL_SCHEMA_HASH="$(printf '%s\n' "$TOOL_SCHEMA_JSON" | python3 -c 'import hashlib,json,sys; schema=json.load(sys.stdin); pre={"name":"local.echo","schema":schema}; print("sha256:"+hashlib.sha256(json.dumps(pre, sort_keys=True, separators=(",",":"), ensure_ascii=False).encode()).hexdigest())')"
printf '%s\n' "$FIXTURE_JSON" | python3 -c 'import json,sys; p=json.load(sys.stdin); assert p["status"]=="ok"; assert p["tools"][0]["name"]=="local.echo"; print(json.dumps({"fixture":"local-fixture-mcp","tool":"local.echo","schema_pinned":True}, sort_keys=True))'

echo "==> Generating fail-closed MCP wrapper profile"
PROFILE_JSON="$(./bin/helm mcp wrap \
  --server-id "local-fixture-mcp" \
  --upstream-command "$FIXTURE_CMD" \
  --require-pinned-schema=true \
  --json)"
printf '%s\n' "$PROFILE_JSON" | python3 -c 'import json,sys; p=json.load(sys.stdin); assert p["server_id"]=="local-fixture-mcp"; assert p["quarantine_default"]=="quarantined"; assert p["upstream_command"][:2]==["python3","scripts/launch/mcp-fixture-server.py"]; print(json.dumps({"wrapper":p["server_id"],"quarantine_default":p["quarantine_default"]}, sort_keys=True))'

echo "==> Starting local HELM boundary"
HELM_ADMIN_API_KEY="$ADMIN_KEY" HELM_HEALTH_PORT="$HEALTH_PORT" ./bin/helm serve \
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

echo "==> Exercising API quarantine, approval, and schema-pin authorization"
python3 - "$HELM_URL" "$FIXTURE_JSON" "$TOOL_SCHEMA_JSON" "$TOOL_SCHEMA_HASH" "$ADMIN_KEY" "$TENANT_ID" <<'PY'
import json
import sys
import urllib.error
import urllib.request

base_url, fixture_json, schema_json, schema_hash, admin_key, tenant_id = sys.argv[1:7]
fixture = json.loads(fixture_json)
tool_names = [tool["name"] for tool in fixture["tools"]]
tool_schema = json.loads(schema_json)


def request(method: str, path: str, payload: dict | None = None, expected: set[int] | None = None) -> tuple[int, dict]:
    data = None if payload is None else json.dumps(payload).encode()
    req = urllib.request.Request(
        base_url + path,
        data=data,
        method=method,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {admin_key}",
            "X-Helm-Tenant-ID": tenant_id,
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            body = resp.read().decode()
            status = resp.status
    except urllib.error.HTTPError as exc:
        status = exc.code
        body = exc.read().decode()
    parsed = json.loads(body) if body else {}
    if expected is not None and status not in expected:
        raise AssertionError(f"{method} {path}: status {status}, body {parsed}")
    return status, parsed


def require_no_allow(record: dict, label: str) -> str:
    verdict = record.get("verdict")
    if verdict == "ALLOW":
        raise AssertionError(f"{label}: fail-closed check returned ALLOW")
    if verdict not in {"DENY", "ESCALATE"}:
        raise AssertionError(f"{label}: got {verdict}, want DENY or ESCALATE")
    return verdict


_, discovered = request(
    "POST",
    "/api/v1/mcp/registry",
    {
        "server_id": "local-fixture-mcp",
        "name": "HELM local fixture",
        "transport": "stdio",
        "endpoint": "python3 scripts/launch/mcp-fixture-server.py",
        "tool_names": tool_names,
        "risk": "high",
        "reason": "launch demo fixture must be approved before dispatch",
    },
    {202},
)
assert discovered["state"] == "quarantined", discovered

_, scan = request(
    "POST",
    "/api/v1/mcp/scan",
    {
        "server_id": "local-fixture-mcp",
        "name": "HELM local fixture",
        "transport": "stdio",
        "endpoint": "python3 scripts/launch/mcp-fixture-server.py",
        "tool_names": tool_names,
    },
    {202},
)
assert scan["risk"] == "high" and scan["requires_approval"] is True, scan

_, unknown_server = request(
    "POST",
    "/api/v1/mcp/authorize-call",
    {
        "server_id": "unknown-fixture-mcp",
        "tool_name": "local.echo",
        "args_hash": "sha256:unknown-server",
        "tool_schema": tool_schema,
        "pinned_schema_hash": schema_hash,
    },
    {403},
)
unknown_server_verdict = require_no_allow(unknown_server, "unknown server")

_, decision = request(
    "POST",
    "/api/v1/evaluate",
    {
        "principal": "mcp-demo-agent",
        "action": "read-ticket",
        "resource": "ticket:MCP-100",
        "context": {"demo": "mcp-quarantine"},
    },
    {200},
)
assert decision["verdict"] == "ALLOW", decision

_, receipts = request("GET", "/api/v1/proofgraph/sessions/mcp-demo-agent/receipts", None, {200})
if not isinstance(receipts, list) or not receipts:
    raise AssertionError("approval decision receipt was not visible through ProofGraph")
approval_receipt_id = receipts[0]["receipt_id"]

_, approval = request(
    "POST",
    "/api/v1/approvals",
    {
        "approval_id": "approval-local-fixture-mcp",
        "subject": "mcp:local-fixture-mcp",
        "action": "approve_mcp_server",
        "requested_by": "mcp-demo-agent",
        "approvers": ["user:local-admin"],
        "quorum": 1,
        "reason": "local fixture schema inspected for public launch demo",
        "receipt_id": approval_receipt_id,
    },
    {201},
)
assert approval["state"] == "pending", approval

_, approval_done = request(
    "POST",
    "/api/v1/approvals/approval-local-fixture-mcp/approve",
    {
        "actor": "user:local-admin",
        "receipt_id": approval_receipt_id,
        "reason": "approved local fixture only",
    },
    {200},
)
assert approval_done["state"] == "approved", approval_done

_, registry_approval = request(
    "POST",
    "/api/v1/mcp/registry/local-fixture-mcp/approve",
    {
        "approver_id": "user:local-admin",
        "approval_receipt_id": approval_receipt_id,
        "reason": "schema pin bound to approval ceremony",
    },
    {200},
)
assert registry_approval["state"] == "approved", registry_approval

_, unknown_tool = request(
    "POST",
    "/api/v1/mcp/authorize-call",
    {
        "server_id": "local-fixture-mcp",
        "tool_name": "local.missing",
        "args_hash": "sha256:unknown-tool",
    },
    {403},
)
unknown_tool_verdict = require_no_allow(unknown_tool, "unknown tool")

_, missing_pin = request(
    "POST",
    "/api/v1/mcp/authorize-call",
    {
        "server_id": "local-fixture-mcp",
        "tool_name": "local.echo",
        "args_hash": "sha256:missing-pin",
        "tool_schema": tool_schema,
    },
    {403},
)
missing_pin_verdict = require_no_allow(missing_pin, "missing schema pin")

_, allowed = request(
    "POST",
    "/api/v1/mcp/authorize-call",
    {
        "server_id": "local-fixture-mcp",
        "tool_name": "local.echo",
        "args_hash": "sha256:pinned-call",
        "tool_schema": tool_schema,
        "pinned_schema_hash": schema_hash,
        "receipt_id": approval_receipt_id,
    },
    {200},
)
if allowed["verdict"] != "ALLOW":
    raise AssertionError(f"pinned fixture call was not allowed: {allowed}")

print(json.dumps({
    "api_unknown_server": unknown_server_verdict,
    "api_unknown_tool": unknown_tool_verdict,
    "api_missing_schema_pin": missing_pin_verdict,
    "api_pinned_call": allowed["verdict"],
    "approval_receipt_id": approval_receipt_id,
    "proofgraph_visible": True,
}, sort_keys=True))
PY

echo "==> Exercising CLI authorize-call fail-closed paths"
set +e
CLI_UNKNOWN_SERVER="$(./bin/helm mcp authorize-call --server-id cli-unknown-fixture --tool-name local.echo --json 2>/dev/null)"
CLI_UNKNOWN_CODE=$?
set -e
if [ "$CLI_UNKNOWN_CODE" -ne 1 ]; then
  echo "CLI unknown server unexpectedly exited $CLI_UNKNOWN_CODE"
  exit 1
fi
printf '%s\n' "$CLI_UNKNOWN_SERVER" | python3 -c 'import json,sys; p=json.load(sys.stdin); assert p["verdict"] in ("DENY","ESCALATE"); print(json.dumps({"cli_unknown_server":p["verdict"]}, sort_keys=True))'

set +e
CLI_UNKNOWN_TOOL="$(./bin/helm mcp authorize-call --server-id cli-local-fixture --tool-name local.missing --approved --json 2>/dev/null)"
CLI_UNKNOWN_TOOL_CODE=$?
set -e
if [ "$CLI_UNKNOWN_TOOL_CODE" -ne 1 ]; then
  echo "CLI unknown tool unexpectedly exited $CLI_UNKNOWN_TOOL_CODE"
  exit 1
fi
printf '%s\n' "$CLI_UNKNOWN_TOOL" | python3 -c 'import json,sys; p=json.load(sys.stdin); assert p["verdict"] in ("DENY","ESCALATE"); print(json.dumps({"cli_unknown_tool":p["verdict"]}, sort_keys=True))'

CLI_ALLOWED="$(./bin/helm mcp authorize-call \
  --server-id cli-local-fixture \
  --tool-name local.echo \
  --approved \
  --tool-schema-json "$TOOL_SCHEMA_JSON" \
  --pinned-schema-hash "$TOOL_SCHEMA_HASH" \
  --json)"
printf '%s\n' "$CLI_ALLOWED" | python3 -c 'import json,sys; p=json.load(sys.stdin); assert p["verdict"]=="ALLOW"; print(json.dumps({"cli_pinned_call":p["verdict"]}, sort_keys=True))'

echo "==> MCP quarantine demo completed with no fixture dispatch for unknown tools or servers."
