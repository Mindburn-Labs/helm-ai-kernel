#!/usr/bin/env bash
# End-to-end Kubernetes smoke using kind and the checked-in Helm chart.
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
KUBE_HELM_IMAGE="${KUBE_HELM_IMAGE:-docker.io/alpine/helm@sha256:105741fa6621ed9a3ea944066de78bb27d4b9bb93a56ce8e7cb4d621e1e4bbf2}"
POLICY_FIXTURE_IMAGE="${HELM_SMOKE_POLICY_FIXTURE_IMAGE:-docker.io/library/busybox@sha256:73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662}"
POLICY_FIXTURE_CONFIGMAP="helm-policy-controlplane-fixture"
POLICY_AUTH_SECRET="helm-policy-reader"
POLICY_FIXTURE_PORT=18081
CREATED_CLUSTER=0
PF_PID=""
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/helm-ai-kernel-kind-smoke.XXXXXX")"
HELM_KUBECONFIG="$TMP_DIR/kubeconfig.helm"
POLICY_FIXTURE_DIR="$TMP_DIR/policy-controlplane"

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
require go

require_pinned_helm_image() {
    if [[ ! "$KUBE_HELM_IMAGE" =~ @sha256:[0-9a-f]{64}$ ]]; then
        echo "::error::KUBE_HELM_IMAGE must be pinned by immutable sha256 digest, got: ${KUBE_HELM_IMAGE}"
        exit 1
    fi
}

require_pinned_policy_fixture_image() {
    if [[ ! "$POLICY_FIXTURE_IMAGE" =~ @sha256:[0-9a-f]{64}$ ]]; then
        echo "::error::POLICY_FIXTURE_IMAGE must be pinned by immutable sha256 digest, got: ${POLICY_FIXTURE_IMAGE}"
        exit 1
    fi
}

require_pinned_policy_fixture_image

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

kind_failure_diagnostics() {
    # Keep diagnostics useful without reading Secrets or printing process
    # environments. Pod descriptions expose secret references, not values.
    echo "::group::kind smoke diagnostics"
    kubectl -n "$NAMESPACE" get pods -o wide || true
    kubectl -n "$NAMESPACE" describe pods || true
    while IFS= read -r pod; do
        [ -n "$pod" ] || continue
        echo "::group::logs $pod"
        kubectl -n "$NAMESPACE" logs "$pod" --all-containers=true --prefix=true || true
        kubectl -n "$NAMESPACE" logs "$pod" --all-containers=true --prefix=true --previous || true
        echo "::endgroup::"
    done < <(kubectl -n "$NAMESPACE" get pods -o name 2>/dev/null || true)
    echo "::endgroup::"
}

cleanup() {
    status=$?
    if [ "$status" -ne 0 ]; then
        kind_failure_diagnostics
    fi
    if [ -n "$PF_PID" ]; then
        kill "$PF_PID" >/dev/null 2>&1 || true
    fi
    kubectl delete namespace "$NAMESPACE" --ignore-not-found >/dev/null 2>&1 || true
    if [ "$CREATED_CLUSTER" = "1" ] && [ "${HELM_SMOKE_KEEP_KIND_CLUSTER:-0}" != "1" ]; then
        kind delete cluster --name "$CLUSTER" >/dev/null 2>&1 || true
    fi
    rm -rf "$TMP_DIR"
    return "$status"
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
IMAGE_DIGEST="$(
    docker exec "${CLUSTER}-control-plane" \
        ctr --namespace k8s.io images inspect "$IMAGE" \
        | sed -nE 's/.*@(sha256:[0-9a-f]{64}).*/\1/p' \
        | sed -n '1p'
)"
if [[ ! "$IMAGE_DIGEST" =~ ^sha256:[0-9a-f]{64}$ ]]; then
    echo "::error::could not resolve the loaded Kernel image to an immutable sha256 digest"
    exit 1
fi
IMAGE_REPOSITORY="${IMAGE%:*}"
IMAGE_DIGEST_REF="${IMAGE_REPOSITORY}@${IMAGE_DIGEST}"
docker exec "${CLUSTER}-control-plane" \
    ctr --namespace k8s.io images tag --force "$IMAGE" "$IMAGE_DIGEST_REF" >/dev/null
kubectl create namespace "$NAMESPACE" --dry-run=client -o yaml | kubectl apply -f - >/dev/null
kubectl label namespace "$NAMESPACE" \
    pod-security.kubernetes.io/enforce=restricted \
    pod-security.kubernetes.io/enforce-version=latest \
    --overwrite >/dev/null

(
    cd "$ROOT/core"
    go run ./scripts/ci/generate_policy_controlplane_fixture.go \
        --out "$POLICY_FIXTURE_DIR" \
        --tenant "$TENANT_ID" \
        --workspace default \
        --reference-pack "$ROOT/reference_packs/eu_ai_act_high_risk.v2.json"
)
POLICY_PUBLIC_KEY="$(tr -d '\r\n' <"$POLICY_FIXTURE_DIR/public-key.hex")"
if [[ ! "$POLICY_PUBLIC_KEY" =~ ^[0-9a-f]{64}$ ]]; then
    echo "::error::generated policy fixture public key is invalid"
    exit 1
fi
kubectl -n "$NAMESPACE" create configmap "$POLICY_FIXTURE_CONFIGMAP" \
    --from-file=head="$POLICY_FIXTURE_DIR/head.json" \
    --from-file=bundle="$POLICY_FIXTURE_DIR/bundle.toml" \
    --dry-run=client -o yaml | kubectl apply -f - >/dev/null
kubectl -n "$NAMESPACE" create secret generic "$POLICY_AUTH_SECRET" \
    --from-literal=HELM_POLICY_BEARER_TOKEN=kind-smoke-policy-reader \
    --dry-run=client -o yaml | kubectl apply -f - >/dev/null

helm_runner upgrade --install "$RELEASE" deploy/helm-chart \
    --namespace "$NAMESPACE" \
    --values scripts/ci/helm_production_network_policy_values.yaml \
    --set helm.production=true \
    --set helm.signing.key="$SIGNING_KEY" \
    --set helm.auth.adminAPIKey="$ADMIN_KEY" \
    --set helm.auth.serviceAPIKey="${HELM_SMOKE_SERVICE_KEY:-helm-service-smoke}" \
    --set helm.auth.tenantID="$TENANT_ID" \
    --set helm.auth.principalID="$AGENT_ID" \
    --set helm.policy.source.kind=controlplane \
    --set-string helm.policy.source.controlplane.url="http://127.0.0.1:${POLICY_FIXTURE_PORT}" \
    --set helm.policy.source.controlplane.auth.mode=bearerToken \
    --set helm.policy.source.controlplane.auth.existingSecret="$POLICY_AUTH_SECRET" \
    --set helm.policy.signature.required=true \
    --set-string helm.policy.signature.publicKey="$POLICY_PUBLIC_KEY" \
    --set image.repository="$IMAGE_REPOSITORY" \
    --set image.digest="$IMAGE_DIGEST" \
    --set image.pullPolicy=IfNotPresent \
    --set persistence.enabled=true

cat >"$TMP_DIR/policy-controlplane-patch.yaml" <<EOF
spec:
  template:
    spec:
      containers:
        - name: policy-controlplane-fixture
          image: ${POLICY_FIXTURE_IMAGE}
          imagePullPolicy: IfNotPresent
          command: ["/bin/httpd", "-f", "-p", "${POLICY_FIXTURE_PORT}", "-h", "/www"]
          securityContext:
            allowPrivilegeEscalation: false
            capabilities:
              drop: ["ALL"]
            readOnlyRootFilesystem: true
            runAsNonRoot: true
            runAsUser: 65532
            runAsGroup: 65532
          readinessProbe:
            httpGet:
              path: /api/v1/policy/head
              port: ${POLICY_FIXTURE_PORT}
          resources:
            requests:
              cpu: 5m
              memory: 8Mi
            limits:
              cpu: 50m
              memory: 32Mi
          volumeMounts:
            - name: policy-controlplane-fixture
              mountPath: /www
              readOnly: true
      volumes:
        - name: policy-controlplane-fixture
          configMap:
            name: ${POLICY_FIXTURE_CONFIGMAP}
            items:
              - key: head
                path: api/v1/policy/head
              - key: bundle
                path: api/v1/policy/bundle
EOF
kubectl -n "$NAMESPACE" patch "deployment/${FULLNAME}" \
    --type=strategic \
    --patch-file "$TMP_DIR/policy-controlplane-patch.yaml" >/dev/null

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
