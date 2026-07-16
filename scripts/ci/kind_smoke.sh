#!/usr/bin/env bash
# End-to-end Kubernetes smoke using kind and the checked-in Helm chart.
# quantum_posture: this smoke uses a deterministic test signing key only; it
# does not add, remove, or claim a production or post-quantum crypto control.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CLUSTER="${KIND_CLUSTER_NAME:-helm-ai-kernel-smoke}"
NAMESPACE="${HELM_SMOKE_NAMESPACE:-helm-smoke}"
RELEASE="${HELM_SMOKE_RELEASE:-helm-smoke}"
FULLNAME="${HELM_SMOKE_FULLNAME:-${RELEASE}-helm-ai-kernel}"
IMAGE="${HELM_SMOKE_IMAGE:-ghcr.io/mindburn-labs/helm-ai-kernel:local}"
SIGNING_KEY="${HELM_CHART_SMOKE_SIGNING_KEY:-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef}"
API_PORT="${HELM_SMOKE_API_PORT:-18080}"
ADMIN_KEY="${HELM_SMOKE_ADMIN_KEY:-helm-admin-smoke}"
TENANT_ID="${HELM_SMOKE_TENANT_ID:-tenant-smoke}"
AGENT_ID="${HELM_SMOKE_AGENT_ID:-agent.smoke}"
WORKSPACE_ID="${HELM_SMOKE_WORKSPACE_ID:-default}"
KUBE_HELM_IMAGE="${KUBE_HELM_IMAGE:-docker.io/alpine/helm@sha256:105741fa6621ed9a3ea944066de78bb27d4b9bb93a56ce8e7cb4d621e1e4bbf2}"
CREATED_CLUSTER=0
PF_PID=""
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/helm-ai-kernel-kind-smoke.XXXXXX")"
HELM_KUBECONFIG="$TMP_DIR/kubeconfig.helm"

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

require_pinned_helm_image() {
    if [[ ! "$KUBE_HELM_IMAGE" =~ @sha256:[0-9a-f]{64}$ ]]; then
        echo "::error::KUBE_HELM_IMAGE must be pinned by immutable sha256 digest, got: ${KUBE_HELM_IMAGE}"
        exit 1
    fi
}

prepare_helm_kubeconfig() {
    if [ -s "$HELM_KUBECONFIG" ]; then
        return
    fi
    kubectl config view --raw --minify --context "kind-${CLUSTER}" >"$HELM_KUBECONFIG"
    python3 - "$HELM_KUBECONFIG" "$CLUSTER" <<'PY'
import re
import sys

path, cluster = sys.argv[1], sys.argv[2]
with open(path, "r", encoding="utf-8") as fh:
    data = fh.read()
rewritten, count = re.subn(
    r"(^\s*server:\s*)https://\S+",
    lambda match: f"{match.group(1)}https://{cluster}-control-plane:6443",
    data,
    count=1,
    flags=re.MULTILINE,
)
if count != 1:
    raise SystemExit("kind kubeconfig did not contain exactly one API server")
with open(path, "w", encoding="utf-8") as fh:
    fh.write(rewritten)
PY
    chmod 0600 "$HELM_KUBECONFIG"
}

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
    if command -v helm >/dev/null 2>&1 && helm-ai-kernel version --short >/dev/null 2>&1 && helm template --help >/dev/null 2>&1; then
        helm "$@"
        return
    fi
    require_pinned_helm_image
    prepare_helm_kubeconfig
    docker run --rm \
        --mount "type=bind,source=${ROOT},target=/work,readonly" \
        --mount "type=bind,source=${HELM_KUBECONFIG},target=/root/.kube/config,readonly" \
        -w /work \
        --network kind \
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
    --set helm.auth.tenantID="$TENANT_ID" \
    --set helm.auth.principalID="$AGENT_ID" \
    --set helm.auth.workspaceID="$WORKSPACE_ID" \
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
    -H "Authorization: Bearer ${ADMIN_KEY}" \
    -H "X-Helm-Tenant-ID: ${TENANT_ID}" \
    -H "X-Helm-Principal-ID: ${AGENT_ID}" \
    -H "X-Helm-Workspace-ID: ${WORKSPACE_ID}" \
    --data-binary '{"action":"EXECUTE_TOOL","resource":"unknown.tool.kind","context":{"payload_size":1}}' >"$TMP_DIR/decision.json"
python3 - "$TMP_DIR/decision.json" <<'PY'
import json, sys
payload = json.load(open(sys.argv[1]))
if str(payload.get("verdict", "")).upper() != "DENY":
    raise SystemExit(f"expected DENY decision: {payload}")
if payload.get("reason_code") == "POLICY_NOT_READY":
    raise SystemExit(f"evaluator did not resolve the installed policy snapshot: {payload}")
if not payload.get("policy_content_hash") or not payload.get("policy_epoch"):
    raise SystemExit(f"decision was not bound to an installed policy snapshot: {payload}")
PY

AUTH=(-H "Authorization: Bearer ${ADMIN_KEY}" -H "X-Helm-Tenant-ID: ${TENANT_ID}" -H "X-Helm-Principal-ID: ${AGENT_ID}" -H "X-Helm-Workspace-ID: ${WORKSPACE_ID}")
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
