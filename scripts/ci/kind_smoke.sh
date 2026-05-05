#!/usr/bin/env bash
# End-to-end Kubernetes smoke using kind and the checked-in Helm chart.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CLUSTER="${KIND_CLUSTER_NAME:-helm-oss-smoke}"
NAMESPACE="${HELM_SMOKE_NAMESPACE:-helm-smoke}"
RELEASE="${HELM_SMOKE_RELEASE:-helm-smoke}"
FULLNAME="${HELM_SMOKE_FULLNAME:-${RELEASE}-helm-firewall}"
IMAGE="${HELM_SMOKE_IMAGE:-ghcr.io/mindburn-labs/helm-oss:local}"
SIGNING_KEY="${HELM_CHART_SMOKE_SIGNING_KEY:-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef}"
API_PORT="${HELM_SMOKE_API_PORT:-18080}"
ADMIN_KEY="${HELM_SMOKE_ADMIN_KEY:-helm-admin-smoke}"
TENANT_ID="${HELM_SMOKE_TENANT_ID:-tenant-smoke}"
AGENT_ID="${HELM_SMOKE_AGENT_ID:-agent.smoke}"
KUBE_HELM_IMAGE="${KUBE_HELM_IMAGE:-alpine/helm:3.15.4}"
CREATED_CLUSTER=0
PF_PID=""
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/helm-oss-kind-smoke.XXXXXX")"

require() {
    command -v "$1" >/dev/null 2>&1 || {
        echo "::error::$1 is required for kind smoke"
        exit 1
    }
}

require docker
require kind
require kubectl
require curl
require python3

cleanup() {
    if [ -n "$PF_PID" ]; then
        kill "$PF_PID" >/dev/null 2>&1 || true
    fi
    kubectl delete namespace "$NAMESPACE" --ignore-not-found >/dev/null 2>&1 || true
    if [ "$CREATED_CLUSTER" = "1" ] && [ "${HELM_SMOKE_KEEP_KIND_CLUSTER:-0}" != "1" ]; then
        kind delete cluster --name "$CLUSTER" >/dev/null 2>&1 || true
    fi
    rm -rf "$TMP_DIR"
}
trap cleanup EXIT

helm_runner() {
    if [ -n "${KUBE_HELM_CMD:-}" ]; then
        "$KUBE_HELM_CMD" "$@"
        return
    fi
    if command -v kube-helm >/dev/null 2>&1; then
        kube-helm "$@"
        return
    fi
    if command -v helm >/dev/null 2>&1 && helm version --short >/dev/null 2>&1 && helm template --help >/dev/null 2>&1; then
        helm "$@"
        return
    fi
    docker run --rm \
        -v "$ROOT:/work" \
        -v "${HOME}/.kube:/root/.kube" \
        -w /work \
        --network host \
        "$KUBE_HELM_IMAGE" "$@"
}

if ! kind get clusters | grep -qx "$CLUSTER"; then
    kind create cluster --name "$CLUSTER"
    CREATED_CLUSTER=1
fi
kubectl cluster-info --context "kind-${CLUSTER}" >/dev/null
kubectl config use-context "kind-${CLUSTER}" >/dev/null

kind load docker-image "$IMAGE" --name "$CLUSTER"
kubectl create namespace "$NAMESPACE" --dry-run=client -o yaml | kubectl apply -f - >/dev/null

helm_runner upgrade --install "$RELEASE" deploy/helm-chart \
    --namespace "$NAMESPACE" \
    --set helm.production=true \
    --set helm.signing.key="$SIGNING_KEY" \
    --set helm.auth.adminAPIKey="$ADMIN_KEY" \
    --set helm.auth.serviceAPIKey="${HELM_SMOKE_SERVICE_KEY:-helm-service-smoke}" \
    --set image.repository="${IMAGE%:*}" \
    --set image.tag="${IMAGE##*:}" \
    --set image.pullPolicy=IfNotPresent \
    --set persistence.enabled=true \
    --wait --timeout 180s

kubectl -n "$NAMESPACE" rollout status "deployment/${FULLNAME}" --timeout=180s
kubectl -n "$NAMESPACE" port-forward "svc/${FULLNAME}" "${API_PORT}:8080" >"$TMP_DIR/port-forward.log" 2>&1 &
PF_PID="$!"

for _ in $(seq 1 60); do
    if curl -fsS "http://127.0.0.1:${API_PORT}/healthz" >/dev/null 2>&1; then
        break
    fi
    sleep 1
done
curl -fsS "http://127.0.0.1:${API_PORT}/healthz" >/dev/null

curl -fsS -X POST "http://127.0.0.1:${API_PORT}/api/v1/evaluate" \
    -H 'Content-Type: application/json' \
    --data-binary "{\"principal\":\"${AGENT_ID}\",\"action\":\"EXECUTE_TOOL\",\"resource\":\"unknown.tool.kind\",\"context\":{\"session_id\":\"${AGENT_ID}\"}}" >"$TMP_DIR/decision.json"
python3 - "$TMP_DIR/decision.json" <<'PY'
import json, sys
payload = json.load(open(sys.argv[1]))
if str(payload.get("verdict", "")).upper() != "DENY":
    raise SystemExit(f"expected DENY decision: {payload}")
PY

AUTH=(-H "Authorization: Bearer ${ADMIN_KEY}" -H "X-Helm-Tenant-ID: ${TENANT_ID}" -H "X-Helm-Principal-ID: ${AGENT_ID}")
status="$(curl -sS -o "$TMP_DIR/no-auth.json" -w '%{http_code}' "http://127.0.0.1:${API_PORT}/api/v1/receipts?limit=1")"
test "$status" = "401" || { echo "::error::expected 401 without auth, got $status"; exit 1; }

curl -fsS "http://127.0.0.1:${API_PORT}/api/v1/receipts?limit=10" "${AUTH[@]}" >"$TMP_DIR/receipts.json"
python3 - "$TMP_DIR/receipts.json" <<'PY'
import json, sys
payload = json.load(open(sys.argv[1]))
if not payload.get("receipts"):
    raise SystemExit(f"expected persisted receipts: {payload}")
PY

curl -fsS -X POST "http://127.0.0.1:${API_PORT}/api/v1/evidence/export" \
    "${AUTH[@]}" \
    -H 'Content-Type: application/json' \
    --data-binary "{\"session_id\":\"${AGENT_ID}\",\"format\":\"tar.gz\"}" \
    -o "$TMP_DIR/evidence.tar.gz"
curl -fsS -X POST "http://127.0.0.1:${API_PORT}/api/v1/replay/verify" \
    -H 'Content-Type: application/octet-stream' \
    --data-binary "@$TMP_DIR/evidence.tar.gz" >"$TMP_DIR/replay.json"
python3 - "$TMP_DIR/replay.json" <<'PY'
import json, sys
payload = json.load(open(sys.argv[1]))
if payload.get("verified") is not True and payload.get("verdict") != "PASS":
    raise SystemExit(f"expected replay verification success: {payload}")
PY

before="$(kubectl -n "$NAMESPACE" get secret "${FULLNAME}-signing" -o jsonpath='{.data.signing-key}')"
kubectl -n "$NAMESPACE" rollout restart "deployment/${FULLNAME}" >/dev/null
kubectl -n "$NAMESPACE" rollout status "deployment/${FULLNAME}" --timeout=180s
after="$(kubectl -n "$NAMESPACE" get secret "${FULLNAME}-signing" -o jsonpath='{.data.signing-key}')"
test "$before" = "$after" || { echo "::error::signing key changed across restart"; exit 1; }

echo "kind smoke passed"
