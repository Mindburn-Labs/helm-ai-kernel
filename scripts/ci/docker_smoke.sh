#!/usr/bin/env bash
# Smoke-test the self-hosted HELM AI Kernel container runtime.
#
# The test exercises the production entrypoint shape used by Docker and Compose:
# explicit `serve --policy`, durable data directory, admin/tenant auth, receipt
# persistence, evidence export/verify, replay verification, and restart
# persistence. It intentionally uses host-side curl/python instead of relying on
# shell utilities inside the distroless runtime image.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
MODE="docker"
if [ "${1:-}" = "--compose" ]; then
    MODE="compose"
fi

IMAGE="${HELM_SMOKE_IMAGE:-ghcr.io/mindburn-labs/helm-ai-kernel:local}"
API_PORT="${HELM_SMOKE_API_PORT:-18080}"
HEALTH_PORT="${HELM_SMOKE_HEALTH_PORT:-18081}"
ADMIN_KEY="${HELM_SMOKE_ADMIN_KEY:-helm-admin-smoke}"
SERVICE_KEY="${HELM_SMOKE_SERVICE_KEY:-helm-service-smoke}"
TENANT_ID="${HELM_SMOKE_TENANT_ID:-tenant-smoke}"
AGENT_ID="${HELM_SMOKE_AGENT_ID:-agent.smoke}"
CONTAINER_NAME="${HELM_SMOKE_CONTAINER_NAME:-helm-ai-kernel-smoke}"
DATA_DIR="${HELM_SMOKE_DATA_DIR:-}"
COMPOSE_PROJECT="${HELM_SMOKE_COMPOSE_PROJECT:-helmoss_smoke}"
COMPOSE_FILE="${HELM_SMOKE_COMPOSE_FILE:-docker-compose.yml}"
cleanup_data=0

require() {
    command -v "$1" >/dev/null 2>&1 || {
        echo "::error::$1 is required for docker smoke"
        exit 1
    }
}

require docker
require curl
require python3

if [ -z "$DATA_DIR" ]; then
    mkdir -p "$ROOT/tmp"
    DATA_DIR="$(mktemp -d "$ROOT/tmp/helm-ai-kernel-docker-smoke.XXXXXX")"
    cleanup_data=1
fi
mkdir -p "$DATA_DIR"
# The runtime image runs as distroless nonroot (65532). Bind-mounted smoke
# directories must be writable by that UID across Linux and Docker Desktop.
chmod 0777 "$DATA_DIR"

cleanup() {
    if [ "$MODE" = "compose" ]; then
        (cd "$ROOT" && docker compose -p "$COMPOSE_PROJECT" -f "$COMPOSE_FILE" down -v --remove-orphans >/dev/null 2>&1 || true)
    else
        docker rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true
    fi
    if [ "$cleanup_data" = "1" ]; then
        rm -rf "$DATA_DIR"
        rmdir "$ROOT/tmp" >/dev/null 2>&1 || true
    fi
}
trap cleanup EXIT

wait_http() {
    url="$1"
    for _ in $(seq 1 60); do
        if curl -fsS "$url" >/dev/null 2>&1; then
            return 0
        fi
        sleep 1
    done
    echo "::error::timed out waiting for $url"
    return 1
}

base_url() {
    printf 'http://127.0.0.1:%s' "$API_PORT"
}

health_url() {
    printf 'http://127.0.0.1:%s/health' "$HEALTH_PORT"
}

auth_headers=(
    -H "Authorization: Bearer ${ADMIN_KEY}"
    -H "X-Helm-Tenant-ID: ${TENANT_ID}"
    -H "X-Helm-Principal-ID: ${AGENT_ID}"
)

start_docker() {
    docker rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true
    docker run -d --name "$CONTAINER_NAME" \
        -p "${API_PORT}:8080" \
        -p "${HEALTH_PORT}:8081" \
        -e HELM_ADMIN_API_KEY="$ADMIN_KEY" \
        -e HELM_SERVICE_API_KEY="$SERVICE_KEY" \
        -e EVIDENCE_SIGNING_KEY="helm-evidence-smoke" \
        -e HELM_HEALTH_PORT=8081 \
        -v "${DATA_DIR}:/var/lib/helm-ai-kernel" \
        "$IMAGE" >/dev/null
}

start_compose() {
    (cd "$ROOT" && docker compose -p "$COMPOSE_PROJECT" -f "$COMPOSE_FILE" down -v --remove-orphans >/dev/null 2>&1 || true)
    HELM_ADMIN_API_KEY="$ADMIN_KEY" \
    HELM_SERVICE_API_KEY="$SERVICE_KEY" \
    EVIDENCE_SIGNING_KEY="helm-evidence-smoke" \
    HELM_SMOKE_DATA_DIR="$DATA_DIR" \
    HELM_SMOKE_API_PORT="$API_PORT" \
    HELM_SMOKE_HEALTH_PORT="$HEALTH_PORT" \
        docker compose -p "$COMPOSE_PROJECT" -f "$ROOT/$COMPOSE_FILE" up -d --build >/dev/null
}

start_runtime() {
    if [ "$MODE" = "compose" ]; then
        start_compose
    else
        start_docker
    fi
    wait_http "$(health_url)"
    wait_http "$(base_url)/healthz"
}

stop_runtime() {
    if [ "$MODE" = "compose" ]; then
        (cd "$ROOT" && docker compose -p "$COMPOSE_PROJECT" -f "$COMPOSE_FILE" stop >/dev/null)
    else
        docker stop "$CONTAINER_NAME" >/dev/null
    fi
}

root_key_hash() {
    if shasum -a 256 "$DATA_DIR/root.key" >/dev/null 2>&1; then
        shasum -a 256 "$DATA_DIR/root.key" | awk '{print $1}'
        return
    fi
    docker run --rm -v "${DATA_DIR}:/data:ro" busybox:1.36.1 sha256sum /data/root.key | awk '{print $1}'
}

evaluate_unknown_tool() {
    curl -fsS -X POST "$(base_url)/api/v1/evaluate" \
        -H 'Content-Type: application/json' \
        --data-binary @- >"$DATA_DIR/decision.json" <<JSON
{"principal":"${AGENT_ID}","action":"EXECUTE_TOOL","resource":"unknown.tool.smoke","context":{"session_id":"${AGENT_ID}","destination":"blocked.smoke.local","payload_size":1}}
JSON
    python3 - "$DATA_DIR/decision.json" <<'PY'
import json, sys
decision = json.load(open(sys.argv[1]))
verdict = str(decision.get("verdict", "")).upper()
if verdict != "DENY":
    raise SystemExit(f"expected unknown tool DENY, got {verdict}: {decision}")
if not decision.get("id"):
    raise SystemExit(f"decision id missing: {decision}")
PY
}

list_receipts() {
    curl -fsS "$(base_url)/api/v1/receipts?limit=10" "${auth_headers[@]}" >"$DATA_DIR/receipts.json"
    python3 - "$DATA_DIR/receipts.json" <<'PY'
import json, sys
payload = json.load(open(sys.argv[1]))
receipts = payload.get("receipts") or []
if not receipts:
    raise SystemExit(f"expected at least one receipt: {payload}")
receipt = receipts[0]
if not receipt.get("receipt_id"):
    raise SystemExit(f"receipt id missing: {receipt}")
print(receipt["receipt_id"])
PY
}

fetch_receipt() {
    receipt_id="$1"
    curl -fsS "$(base_url)/api/v1/receipts/${receipt_id}" "${auth_headers[@]}" >"$DATA_DIR/receipt.json"
}

assert_authz_negative() {
    status="$(curl -sS -o "$DATA_DIR/no-auth.json" -w '%{http_code}' "$(base_url)/api/v1/receipts?limit=1")"
    if [ "$status" != "401" ]; then
        echo "::error::expected missing auth to return 401, got $status"
        cat "$DATA_DIR/no-auth.json"
        exit 1
    fi
    status="$(curl -sS -o "$DATA_DIR/no-tenant.json" -w '%{http_code}' "$(base_url)/api/v1/receipts?limit=1" -H "Authorization: Bearer ${ADMIN_KEY}")"
    if [ "$status" != "403" ]; then
        echo "::error::expected missing tenant to return 403, got $status"
        cat "$DATA_DIR/no-tenant.json"
        exit 1
    fi
}

export_and_verify_evidence() {
    curl -fsS -X POST "$(base_url)/api/v1/evidence/export" \
        "${auth_headers[@]}" \
        -H 'Content-Type: application/json' \
        --data-binary "{\"session_id\":\"${AGENT_ID}\",\"format\":\"tar.gz\"}" \
        -o "$DATA_DIR/evidence.tar.gz"
    test -s "$DATA_DIR/evidence.tar.gz"

    curl -fsS -X POST "$(base_url)/api/v1/evidence/verify" \
        -H 'Content-Type: application/octet-stream' \
        --data-binary "@$DATA_DIR/evidence.tar.gz" >"$DATA_DIR/evidence-verify.json"
    curl -fsS -X POST "$(base_url)/api/v1/replay/verify" \
        -H 'Content-Type: application/octet-stream' \
        --data-binary "@$DATA_DIR/evidence.tar.gz" >"$DATA_DIR/replay-verify.json"
    python3 - "$DATA_DIR/evidence-verify.json" "$DATA_DIR/replay-verify.json" <<'PY'
import json, sys
for path in sys.argv[1:]:
    payload = json.load(open(path))
    if payload.get("verified") is not True and payload.get("verdict") != "PASS":
        raise SystemExit(f"{path} expected verified=true or verdict=PASS: {payload}")
    checks = payload.get("checks") or {}
    failed = {k: v for k, v in checks.items() if v != "PASS"}
    if failed:
        raise SystemExit(f"{path} expected all checks PASS: {payload}")
PY
}

assert_persistence_files() {
    test -f "$DATA_DIR/root.key" || { echo "::error::root.key missing from durable data dir"; exit 1; }
    test -f "$DATA_DIR/helm.db" || { echo "::error::helm.db missing from durable data dir"; exit 1; }
    root_key_hash >"$DATA_DIR/root-key.before"
}

assert_persistence_after_restart() {
    root_key_hash >"$DATA_DIR/root-key.after"
    diff "$DATA_DIR/root-key.before" "$DATA_DIR/root-key.after" >/dev/null || {
        echo "::error::root key changed across restart"
        exit 1
    }
    list_receipts >/dev/null
}

echo "docker smoke mode=$MODE image=$IMAGE api_port=$API_PORT health_port=$HEALTH_PORT data_dir=$DATA_DIR"
start_runtime
evaluate_unknown_tool
receipt_id="$(list_receipts)"
fetch_receipt "$receipt_id"
assert_authz_negative
export_and_verify_evidence
assert_persistence_files
stop_runtime
start_runtime
assert_persistence_after_restart
echo "docker smoke passed"
