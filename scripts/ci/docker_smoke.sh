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
TENANT_ID="${HELM_SMOKE_TENANT_ID:-tenant-smoke}"
AGENT_ID="${HELM_SMOKE_AGENT_ID:-agent.smoke}"
CONTAINER_NAME="${HELM_SMOKE_CONTAINER_NAME:-helm-ai-kernel-smoke}"
RUNTIME_DATA_DIR="${HELM_SMOKE_DATA_DIR:-}"
ARTIFACT_DIR="${HELM_SMOKE_ARTIFACT_DIR:-}"
COMPOSE_PROJECT="${HELM_SMOKE_COMPOSE_PROJECT:-helmoss_smoke}"
COMPOSE_FILE="${HELM_SMOKE_COMPOSE_FILE:-docker-compose.yml}"
AUTHORITY_INIT_IMAGE="docker.io/library/busybox@sha256:73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662"
cleanup_runtime_data=0
cleanup_artifacts=0

BUILD_VERSION="${HELM_BUILD_VERSION:-$(cat "$ROOT/VERSION" 2>/dev/null || echo dev)}"
BUILD_COMMIT="${HELM_BUILD_COMMIT:-$(git -C "$ROOT" rev-parse HEAD 2>/dev/null || echo unknown)}"
BUILD_TIME="${HELM_BUILD_TIME:-$(date -u +%Y-%m-%dT%H:%M:%SZ)}"

require() {
    command -v "$1" >/dev/null 2>&1 || {
        echo "::error::$1 is required for docker smoke"
        exit 1
    }
}

require_pinned_authority_init_image() {
    if [[ ! "$AUTHORITY_INIT_IMAGE" =~ @sha256:[0-9a-f]{64}$ ]]; then
        echo "::error::AUTHORITY_INIT_IMAGE must be pinned by immutable sha256 digest"
        exit 1
    fi
}

require docker
require curl
require python3
require_pinned_authority_init_image

random_key() {
    python3 - <<'PY'
import secrets
print(secrets.token_urlsafe(32))
PY
}

ADMIN_KEY="${HELM_SMOKE_ADMIN_KEY:-$(random_key)}"
SERVICE_KEY="${HELM_SMOKE_SERVICE_KEY:-$(random_key)}"
EVIDENCE_SIGNING_KEY="${HELM_SMOKE_EVIDENCE_SIGNING_KEY:-$(random_key)}"

if [ -z "$RUNTIME_DATA_DIR" ]; then
    mkdir -p "$ROOT/tmp"
    RUNTIME_DATA_DIR="$(mktemp -d "$ROOT/tmp/helm-ai-kernel-docker-runtime.XXXXXX")"
    cleanup_runtime_data=1
fi
mkdir -p "$RUNTIME_DATA_DIR"
RUNTIME_DATA_DIR="$(cd "$RUNTIME_DATA_DIR" && pwd -P)"

if [ -z "$ARTIFACT_DIR" ]; then
    mkdir -p "$ROOT/tmp"
    ARTIFACT_DIR="$(mktemp -d "$ROOT/tmp/helm-ai-kernel-docker-artifacts.XXXXXX")"
    cleanup_artifacts=1
fi
mkdir -p "$ARTIFACT_DIR"
ARTIFACT_DIR="$(cd "$ARTIFACT_DIR" && pwd -P)"

prepare_direct_runtime_data_dir() {
    # The runtime rejects group/world-writable or foreign-owned authority
    # state. Prepare only the mounted state directory; smoke artifacts stay
    # outside that authority boundary.
    docker run --rm --user 0:0 \
        --mount "type=bind,source=$RUNTIME_DATA_DIR,target=/runtime-data" \
        "$AUTHORITY_INIT_IMAGE" \
        sh -ec 'chown 65532:65532 /runtime-data && chmod 0700 /runtime-data' \
        >/dev/null
}

cleanup() {
    if [ "$MODE" = "compose" ]; then
        (cd "$ROOT" && docker compose -p "$COMPOSE_PROJECT" -f "$COMPOSE_FILE" down -v --remove-orphans >/dev/null 2>&1 || true)
    else
        docker rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true
    fi
    if [ "$cleanup_runtime_data" = "1" ]; then
        # The container ran as distroless nonroot (UID 65532) and may have
        # written files under $RUNTIME_DATA_DIR/keys/ with mode 0700 (KMS
        # keystore). The host user can't traverse that directory, so delegate
        # the recursive delete to a short-lived root container with the same
        # mount. Falling through to the host rm afterwards picks up the now-
        # empty directory plus anything the cleanup container missed.
        if [ -d "$RUNTIME_DATA_DIR" ]; then
            docker run --rm --user 0:0 \
                --mount "type=bind,source=$RUNTIME_DATA_DIR,target=/cleanup" \
                "$AUTHORITY_INIT_IMAGE" \
                sh -c 'rm -rf /cleanup/..?* /cleanup/.[!.]* /cleanup/* 2>/dev/null || true' \
                >/dev/null 2>&1 || true
        fi
        rm -rf "$RUNTIME_DATA_DIR" 2>/dev/null || true
    fi
    if [ "$cleanup_artifacts" = "1" ]; then
        rm -rf "$ARTIFACT_DIR" 2>/dev/null || true
    fi
    if [ "$cleanup_runtime_data" = "1" ] || [ "$cleanup_artifacts" = "1" ]; then
        rmdir "$ROOT/tmp" >/dev/null 2>&1 || true
    fi
}

diagnose_runtime_failure() {
    echo "::group::docker smoke diagnostics"
    echo "runtime diagnostics omit inspect and environment output so credentials are not exposed"
    if [ "$MODE" = "compose" ]; then
        (cd "$ROOT" && docker compose -p "$COMPOSE_PROJECT" -f "$COMPOSE_FILE" ps) || true
        (cd "$ROOT" && docker compose -p "$COMPOSE_PROJECT" -f "$COMPOSE_FILE" logs --no-color --tail 200 helm authority-state) || true
    else
        docker ps -a --filter "name=^/$CONTAINER_NAME$" --format '{{.Names}} {{.Status}}' || true
        docker logs --tail 200 "$CONTAINER_NAME" || true
    fi
    echo "::endgroup::"
}

on_exit() {
    status=$?
    if [ "$status" -ne 0 ]; then
        diagnose_runtime_failure
    fi
    cleanup
    return "$status"
}

runtime_file_exists() {
    docker run --rm --user 0:0 \
        --mount "type=bind,source=$RUNTIME_DATA_DIR,target=/runtime-data,readonly" \
        "$AUTHORITY_INIT_IMAGE" \
        test -f "/runtime-data/$1"
}

root_key_hash() {
    docker run --rm --user 0:0 \
        --mount "type=bind,source=$RUNTIME_DATA_DIR,target=/runtime-data,readonly" \
        "$AUTHORITY_INIT_IMAGE" \
        sha256sum /runtime-data/root.key | awk '{print $1}'
}

trap on_exit EXIT

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
    prepare_direct_runtime_data_dir
    docker run -d --name "$CONTAINER_NAME" \
        -p "127.0.0.1:${API_PORT}:8080" \
        -p "127.0.0.1:${HEALTH_PORT}:8081" \
        -e HELM_ADMIN_API_KEY="$ADMIN_KEY" \
        -e HELM_SERVICE_API_KEY="$SERVICE_KEY" \
        -e HELM_RUNTIME_TENANT_ID="$TENANT_ID" \
        -e HELM_RUNTIME_PRINCIPAL_ID="$AGENT_ID" \
        -e EVIDENCE_SIGNING_KEY="$EVIDENCE_SIGNING_KEY" \
        -e HELM_HEALTH_PORT=8081 \
        -v "${RUNTIME_DATA_DIR}:/var/lib/helm-ai-kernel" \
        "$IMAGE" >/dev/null
}

start_compose() {
    (cd "$ROOT" && docker compose -p "$COMPOSE_PROJECT" -f "$COMPOSE_FILE" down -v --remove-orphans >/dev/null 2>&1 || true)
    HELM_ADMIN_API_KEY="$ADMIN_KEY" \
    HELM_SERVICE_API_KEY="$SERVICE_KEY" \
    HELM_RUNTIME_TENANT_ID="$TENANT_ID" \
    HELM_RUNTIME_PRINCIPAL_ID="$AGENT_ID" \
    EVIDENCE_SIGNING_KEY="$EVIDENCE_SIGNING_KEY" \
    HELM_SMOKE_DATA_DIR="$RUNTIME_DATA_DIR" \
    HELM_SMOKE_API_PORT="$API_PORT" \
    HELM_SMOKE_HEALTH_PORT="$HEALTH_PORT" \
    HELM_BUILD_VERSION="$BUILD_VERSION" \
    HELM_BUILD_COMMIT="$BUILD_COMMIT" \
    HELM_BUILD_TIME="$BUILD_TIME" \
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

assert_compose_build_metadata() {
    if [ "$MODE" != "compose" ]; then
        return
    fi
    curl -fsS "$(base_url)/version" >"$ARTIFACT_DIR/version.json"
    python3 - "$ARTIFACT_DIR/version.json" "$BUILD_COMMIT" <<'PY'
import json, sys
payload = json.load(open(sys.argv[1], encoding="utf-8"))
expected_commit = sys.argv[2]
version = str(payload.get("version", ""))
commit = str(payload.get("commit", ""))
build_time = str(payload.get("build_time", ""))
if not version or version in {"unknown", "vunknown"}:
    raise SystemExit(f"/version missing build version: {payload}")
if not commit or commit == "unknown":
    raise SystemExit(f"/version missing build commit: {payload}")
if expected_commit != "unknown" and commit != expected_commit[:12]:
    raise SystemExit(f"/version commit {commit!r} does not match expected {expected_commit[:12]!r}: {payload}")
if not build_time or build_time == "unknown":
    raise SystemExit(f"/version missing build_time: {payload}")
PY
}

stop_runtime() {
    if [ "$MODE" = "compose" ]; then
        (cd "$ROOT" && docker compose -p "$COMPOSE_PROJECT" -f "$COMPOSE_FILE" stop >/dev/null)
    else
        docker stop "$CONTAINER_NAME" >/dev/null
    fi
}

evaluate_unknown_tool() {
    curl -fsS -X POST "$(base_url)/api/v1/evaluate" \
        -H 'Content-Type: application/json' \
        "${auth_headers[@]}" \
        --data-binary @- >"$ARTIFACT_DIR/decision.json" <<JSON
{"principal":"${AGENT_ID}","action":"EXECUTE_TOOL","resource":"unknown.tool.smoke","context":{"session_id":"${AGENT_ID}","destination":"blocked.smoke.local","payload_size":1}}
JSON
    python3 - "$ARTIFACT_DIR/decision.json" <<'PY'
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
    curl -fsS "$(base_url)/api/v1/receipts?limit=10" "${auth_headers[@]}" >"$ARTIFACT_DIR/receipts.json"
    python3 - "$ARTIFACT_DIR/receipts.json" <<'PY'
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
    curl -fsS "$(base_url)/api/v1/receipts/${receipt_id}" "${auth_headers[@]}" >"$ARTIFACT_DIR/receipt.json"
}

assert_authz_negative() {
    status="$(curl -sS -o "$ARTIFACT_DIR/no-auth.json" -w '%{http_code}' "$(base_url)/api/v1/receipts?limit=1")"
    if [ "$status" != "401" ]; then
        echo "::error::expected missing auth to return 401, got $status"
        cat "$ARTIFACT_DIR/no-auth.json"
        exit 1
    fi
    status="$(curl -sS -o "$ARTIFACT_DIR/no-tenant.json" -w '%{http_code}' "$(base_url)/api/v1/receipts?limit=1" -H "Authorization: Bearer ${ADMIN_KEY}")"
    if [ "$status" != "403" ]; then
        echo "::error::expected missing tenant to return 403, got $status"
        cat "$ARTIFACT_DIR/no-tenant.json"
        exit 1
    fi
}

export_and_verify_evidence() {
    curl -fsS -X POST "$(base_url)/api/v1/evidence/export" \
        "${auth_headers[@]}" \
        -H 'Content-Type: application/json' \
        --data-binary "{\"session_id\":\"${AGENT_ID}\",\"format\":\"tar.gz\"}" \
        -o "$ARTIFACT_DIR/evidence.tar.gz"
    test -s "$ARTIFACT_DIR/evidence.tar.gz"

    curl -fsS -X POST "$(base_url)/api/v1/evidence/verify" \
        -H 'Content-Type: application/octet-stream' \
        --data-binary "@$ARTIFACT_DIR/evidence.tar.gz" >"$ARTIFACT_DIR/evidence-verify.json"
    curl -fsS -X POST "$(base_url)/api/v1/replay/verify" \
        -H 'Content-Type: application/octet-stream' \
        --data-binary "@$ARTIFACT_DIR/evidence.tar.gz" >"$ARTIFACT_DIR/replay-verify.json"
    python3 - "$ARTIFACT_DIR/evidence-verify.json" "$ARTIFACT_DIR/replay-verify.json" <<'PY'
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
    runtime_file_exists root.key || { echo "::error::root.key missing from durable data dir"; exit 1; }
    runtime_file_exists helm.db || { echo "::error::helm.db missing from durable data dir"; exit 1; }
    root_key_hash >"$ARTIFACT_DIR/root-key.before"
}

assert_persistence_after_restart() {
    root_key_hash >"$ARTIFACT_DIR/root-key.after"
    diff "$ARTIFACT_DIR/root-key.before" "$ARTIFACT_DIR/root-key.after" >/dev/null || {
        echo "::error::root key changed across restart"
        exit 1
    }
    list_receipts >/dev/null
}

echo "docker smoke mode=$MODE image=$IMAGE api_port=$API_PORT health_port=$HEALTH_PORT runtime_data_dir=$RUNTIME_DATA_DIR artifact_dir=$ARTIFACT_DIR"
start_runtime
assert_compose_build_metadata
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
