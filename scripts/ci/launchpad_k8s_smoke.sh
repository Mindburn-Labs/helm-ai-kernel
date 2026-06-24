#!/usr/bin/env bash
# Launchpad k8s smoke driver. Installs the helm chart with openclaw and hermes
# co-deployed, runs the canonical positive or negative scenario, and audits for
# leaks after teardown. The default path owns a clean minikube lifecycle; generic
# clusters can be reused with --reuse-cluster and an already-selected kubeconfig.
#
# Modes (--mode):
#   baseline  — chart-only install, no launchpad apps. Confirms the kernel still
#               renders and rolls out cleanly when launchpadApps.* default to false.
#   positive  — openclaw + hermes enabled, real OPENROUTER_API_KEY in Secret.
#               Expects openclaw Pod Ready, hermes Job succeeded, helm test PASS.
#   negative  — openclaw + hermes enabled, sk-fake OPENROUTER_API_KEY in Secret.
#               Expects hermes Job failed; openclaw either CrashLoopBackOff or
#               never reaches Ready within the timeout.
#
# Required tools: kubectl, helm, python3, jq. Minikube mode also requires
# minikube and docker.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
IMAGE_LOCK="${ROOT}/registry/launchpad/image-lock.json"
MODE="${LAUNCHPAD_SMOKE_MODE:-positive}"
CLUSTER_MODE="${LAUNCHPAD_SMOKE_CLUSTER_MODE:-minikube}"
PROFILE="${LAUNCHPAD_SMOKE_PROFILE:-launchpad-smoke}"
NAMESPACE="${LAUNCHPAD_SMOKE_NAMESPACE:-helm-launchpad-smoke}"
RELEASE="${LAUNCHPAD_SMOKE_RELEASE:-kernel}"
KERNEL_IMAGE="${LAUNCHPAD_SMOKE_KERNEL_IMAGE:-ghcr.io/mindburn-labs/helm-ai-kernel:local}"
SIGNING_KEY="${LAUNCHPAD_SMOKE_SIGNING_KEY:-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef}"
ADMIN_KEY="${LAUNCHPAD_SMOKE_ADMIN_KEY:-helm-admin-smoke}"
SERVICE_KEY="${LAUNCHPAD_SMOKE_SERVICE_KEY:-helm-service-smoke}"
OPENROUTER_KEY_REAL="${OPENROUTER_API_KEY:-}"
OPENROUTER_KEY_FAKE="sk-fake-1234567890"
KEEP_CLUSTER="${LAUNCHPAD_SMOKE_KEEP_CLUSTER:-0}"
FRESH_CLUSTER="${LAUNCHPAD_SMOKE_FRESH_CLUSTER:-1}"
MANAGE_NAMESPACE="${LAUNCHPAD_SMOKE_MANAGE_NAMESPACE:-1}"
EPHEMERAL_NAMESPACE="${LAUNCHPAD_SMOKE_EPHEMERAL_NAMESPACE:-0}"
KUBE_CONTEXT="${LAUNCHPAD_SMOKE_CONTEXT:-}"
STORAGE_CLASS="${LAUNCHPAD_SMOKE_STORAGE_CLASS:-}"
PERSISTENCE_ENABLED="${LAUNCHPAD_SMOKE_PERSISTENCE_ENABLED:-true}"
PRE_LOAD_LAUNCHPAD_IMAGES="${LAUNCHPAD_SMOKE_PRE_LOAD_LAUNCHPAD_IMAGES:-0}"
PRE_LOAD_LAUNCHPAD_PLATFORM="${LAUNCHPAD_SMOKE_PRE_LOAD_LAUNCHPAD_PLATFORM:-linux/amd64}"
GHCR_SECRET_NAME="${LAUNCHPAD_SMOKE_GHCR_SECRET_NAME:-ghcr-read}"
GHCR_USERNAME="${GHCR_USERNAME:-}"
GHCR_TOKEN="${GHCR_TOKEN:-}"
KUBE_HELM_CMD="${KUBE_HELM_CMD:-}"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/launchpad-k8s-smoke.XXXXXX")"

usage() {
    cat <<EOF
Usage: $0 [--mode baseline|positive|negative] [--reuse-cluster] [--ephemeral-namespace]

Environment overrides:
  LAUNCHPAD_SMOKE_MODE          one of baseline|positive|negative (default positive)
  LAUNCHPAD_SMOKE_CLUSTER_MODE  one of minikube|reuse (default minikube)
  LAUNCHPAD_SMOKE_CONTEXT       optional kube context to select before running
  LAUNCHPAD_SMOKE_PROFILE       minikube profile name (default launchpad-smoke)
  LAUNCHPAD_SMOKE_NAMESPACE     release namespace (default helm-launchpad-smoke)
  LAUNCHPAD_SMOKE_RELEASE       helm release name (default kernel)
  LAUNCHPAD_SMOKE_KERNEL_IMAGE  kernel image to load into minikube (default ghcr.io/mindburn-labs/helm-ai-kernel:local)
  LAUNCHPAD_SMOKE_KEEP_CLUSTER  set to 1 to skip the final minikube delete
  LAUNCHPAD_SMOKE_FRESH_CLUSTER set to 0 to reuse an existing minikube profile (assumes the cluster is already running and kernel image is loaded)
  LAUNCHPAD_SMOKE_MANAGE_NAMESPACE set to 0 when the namespace already exists and the kubeconfig has namespace-scoped RBAC only
  LAUNCHPAD_SMOKE_EPHEMERAL_NAMESPACE set to 1 to append a unique suffix to LAUNCHPAD_SMOKE_NAMESPACE
  LAUNCHPAD_SMOKE_STORAGE_CLASS optional persistence.storageClass override; empty uses the cluster default
  LAUNCHPAD_SMOKE_PERSISTENCE_ENABLED set to false to disable the chart PVC in storage-less smoke clusters
  LAUNCHPAD_SMOKE_GHCR_SECRET_NAME Secret name for private GHCR pulls (default ghcr-read)
  LAUNCHPAD_SMOKE_PRE_LOAD_LAUNCHPAD_IMAGES set to 1 for debug-only host pull + minikube image load verification
  LAUNCHPAD_SMOKE_PRE_LOAD_LAUNCHPAD_PLATFORM platform for debug-only launchpad image preload (default linux/amd64)
  KUBE_HELM_CMD                  Kubernetes Helm binary to use when `helm` is occupied by HELM verifier
  GHCR_USERNAME                  GitHub/GHCR username for positive/negative launchpad app image pulls
  GHCR_TOKEN                     GitHub token with read:packages for private GHCR launchpad app image pulls
  OPENROUTER_API_KEY            real key for the positive scenario; ignored on negative
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        --mode) MODE="$2"; shift 2;;
        --mode=*) MODE="${1#--mode=}"; shift;;
        --context) KUBE_CONTEXT="$2"; shift 2;;
        --context=*) KUBE_CONTEXT="${1#--context=}"; shift;;
        --keep-cluster) KEEP_CLUSTER=1; shift;;
        --reuse-cluster) CLUSTER_MODE="reuse"; FRESH_CLUSTER=0; KEEP_CLUSTER=1; shift;;
        --ephemeral-namespace) EPHEMERAL_NAMESPACE=1; MANAGE_NAMESPACE=1; shift;;
        --existing-namespace) MANAGE_NAMESPACE=0; shift;;
        -h|--help) usage; exit 0;;
        *) echo "unknown arg: $1" >&2; usage >&2; exit 2;;
    esac
done

case "$MODE" in
    baseline|positive|negative) ;;
    *) echo "::error::invalid --mode '$MODE' (expected baseline|positive|negative)" >&2; exit 2;;
esac
case "$CLUSTER_MODE" in
    minikube|reuse) ;;
    *) echo "::error::invalid LAUNCHPAD_SMOKE_CLUSTER_MODE '$CLUSTER_MODE' (expected minikube|reuse)" >&2; exit 2;;
esac
if [ "$CLUSTER_MODE" = "reuse" ]; then
    FRESH_CLUSTER=0
    KEEP_CLUSTER=1
fi
if [ "$EPHEMERAL_NAMESPACE" = "1" ]; then
    NAMESPACE="${NAMESPACE}-$(date +%s)-$$"
    if [ "${#NAMESPACE}" -gt 63 ]; then
        echo "::error::ephemeral namespace name is too long: $NAMESPACE" >&2
        exit 2
    fi
fi

require() {
    command -v "$1" >/dev/null 2>&1 || {
        echo "::error::$1 is required for launchpad k8s smoke" >&2
        exit 1
    }
}
kube_helm() {
    if [ -n "$KUBE_HELM_CMD" ]; then
        "$KUBE_HELM_CMD" "$@"
        return
    fi
    if command -v kube-helm >/dev/null 2>&1; then
        kube-helm "$@"
        return
    fi
    if command -v helm >/dev/null 2>&1 && helm version --short 2>/dev/null | grep -q '^v3\.'; then
        helm "$@"
        return
    fi
    echo "::error::Kubernetes Helm v3 is required. Set KUBE_HELM_CMD when the helm command is occupied by the HELM verifier." >&2
    exit 1
}
require kubectl
kube_helm version --short >/dev/null
require python3
require jq
if [ "$CLUSTER_MODE" = "minikube" ]; then
    require minikube
    require docker
fi
if [ "$PRE_LOAD_LAUNCHPAD_IMAGES" = "1" ] && [ "$CLUSTER_MODE" != "minikube" ]; then
    echo "::error::LAUNCHPAD_SMOKE_PRE_LOAD_LAUNCHPAD_IMAGES=1 is only supported in minikube mode" >&2
    exit 2
fi

apply_ghcr_pull_secret() {
    GHCR_USERNAME="$GHCR_USERNAME" GHCR_TOKEN="$GHCR_TOKEN" \
        python3 - "$GHCR_SECRET_NAME" <<'PY' | kubectl -n "$NAMESPACE" apply -f -
import base64
import json
import os
import sys

name = sys.argv[1]
username = os.environ["GHCR_USERNAME"]
token = os.environ["GHCR_TOKEN"]
auth = base64.b64encode(f"{username}:{token}".encode()).decode()
dockerconfig = {
    "auths": {
        "ghcr.io": {
            "username": username,
            "password": token,
            "auth": auth,
        }
    }
}
manifest = {
    "apiVersion": "v1",
    "kind": "Secret",
    "metadata": {"name": name},
    "type": "kubernetes.io/dockerconfigjson",
    "data": {
        ".dockerconfigjson": base64.b64encode(
            json.dumps(dockerconfig, separators=(",", ":")).encode()
        ).decode()
    },
}
print(json.dumps(manifest))
PY
}

cleanup_ad_hoc_runtime_secrets() {
    if [ "$MODE" = "baseline" ]; then
        return 0
    fi
    kubectl -n "$NAMESPACE" delete secret openrouter-key "$GHCR_SECRET_NAME" --ignore-not-found
}

if [ "$MODE" = "positive" ] && [ -z "$OPENROUTER_KEY_REAL" ]; then
    echo "::error::OPENROUTER_API_KEY env var is required for --mode positive" >&2
    exit 1
fi
if [ "$MODE" != "baseline" ] && { [ -z "$GHCR_USERNAME" ] || [ -z "$GHCR_TOKEN" ]; }; then
    echo "::error::GHCR_USERNAME and GHCR_TOKEN are required for launchpad app image pulls in --mode ${MODE}" >&2
    exit 1
fi

cleanup() {
    local rc=$?
    if [ "$rc" -ne 0 ]; then
        echo "::group::cluster state at failure"
        kubectl get pods -n "$NAMESPACE" -o wide 2>/dev/null || true
        kubectl describe pods -n "$NAMESPACE" 2>/dev/null | tail -200 || true
        kubectl logs -n "$NAMESPACE" -l app.kubernetes.io/component=launchpad-app --all-containers --tail=200 2>/dev/null || true
        echo "::endgroup::"
        # Best-effort namespace-scoped teardown so the next run starts clean.
        # The cluster itself stays around when KEEP_CLUSTER=1.
        kube_helm uninstall "$RELEASE" -n "$NAMESPACE" --ignore-not-found --wait --timeout 60s 2>/dev/null || true
        cleanup_ad_hoc_runtime_secrets 2>/dev/null || true
        if [ "$MANAGE_NAMESPACE" = "1" ]; then
            kubectl delete namespace "$NAMESPACE" --wait=false 2>/dev/null || true
        fi
    fi
    rm -rf "$TMP_DIR"
    if [ "$CLUSTER_MODE" = "minikube" ] && [ "$KEEP_CLUSTER" != "1" ] && [ "$FRESH_CLUSTER" = "1" ]; then
        minikube delete -p "$PROFILE" >/dev/null 2>&1 || true
    fi
    exit "$rc"
}
trap cleanup EXIT

echo "::group::stage 1 — kubernetes cluster"
if [ "$CLUSTER_MODE" = "minikube" ]; then
    # CI default: always start from a clean slate (FRESH_CLUSTER=1). Local verify
    # loops set FRESH_CLUSTER=0 to reuse the cluster between scenario runs so the
    # kernel image built inside minikube docker doesn't have to be rebuilt every
    # time. The chart's NetworkPolicy needs a CNI that enforces it; calico is the
    # lightest option that ships with minikube addons.
    if [ "$FRESH_CLUSTER" = "1" ]; then
        minikube delete -p "$PROFILE" >/dev/null 2>&1 || true
    fi
    # Use `apiserver: Running` as the reuse signal rather than the overall
    # `minikube status` exit code, which goes non-zero on `InsufficientStorage`
    # and other non-fatal warnings even when the cluster is usable.
    if minikube -p "$PROFILE" status 2>/dev/null | grep -q '^apiserver: Running'; then
        echo "reusing existing minikube profile '$PROFILE'"
    else
        minikube start -p "$PROFILE" \
            --cpus="${LAUNCHPAD_SMOKE_CPUS:-4}" \
            --memory="${LAUNCHPAD_SMOKE_MEMORY:-5g}" \
            --disk-size="${LAUNCHPAD_SMOKE_DISK:-20g}" \
            --kubernetes-version="${LAUNCHPAD_SMOKE_K8S_VERSION:-v1.30.0}" \
            --cni=calico \
            --driver="${LAUNCHPAD_SMOKE_DRIVER:-docker}"
    fi
    kubectl config use-context "$PROFILE"
else
    if [ -n "$KUBE_CONTEXT" ]; then
        kubectl config use-context "$KUBE_CONTEXT"
    fi
    echo "reusing kube context: $(kubectl config current-context)"
fi
if [ "$CLUSTER_MODE" = "minikube" ]; then
    kubectl cluster-info
else
    kubectl version --request-timeout=10s >/dev/null
fi
echo "::endgroup::"

echo "::group::stage 2 — local kernel image + optional launchpad image debug"
if [ "$CLUSTER_MODE" = "minikube" ]; then
    # Kernel image: built locally by the caller (CI step or developer make target).
    # Skip the load if it is already inside minikube (common when the caller built
    # directly inside the minikube docker daemon via `eval $(minikube docker-env)`).
    if minikube -p "$PROFILE" image ls 2>/dev/null | grep -qF "$KERNEL_IMAGE"; then
        echo "kernel image already present in minikube: $KERNEL_IMAGE"
    elif docker image inspect "$KERNEL_IMAGE" >/dev/null 2>&1; then
        minikube -p "$PROFILE" image load "$KERNEL_IMAGE"
    else
        echo "::warning::kernel image $KERNEL_IMAGE not in local docker; relying on imagePullPolicy=IfNotPresent against registry"
    fi
else
    echo "reused-cluster mode: kubelet must pull kernel image $KERNEL_IMAGE from a registry or node cache"
fi

if [ "$PRE_LOAD_LAUNCHPAD_IMAGES" = "1" ] && [ "$MODE" != "baseline" ]; then
    # Debug-only path. Private digest-pinned GHCR refs have proven unreliable
    # through `minikube image load`; the normal path below uses imagePullSecrets.
    if [ ! -f "$IMAGE_LOCK" ]; then
        echo "::error::Launchpad image lock not found: $IMAGE_LOCK" >&2
        exit 1
    fi
    preload_images=()
    while IFS= read -r img; do
        preload_images+=("$img")
    done < <(jq -r '.images[] | select(.preload != false) | .image' "$IMAGE_LOCK")
    if [ "${#preload_images[@]}" -eq 0 ]; then
        echo "::error::Launchpad image lock does not contain preload images: $IMAGE_LOCK" >&2
        exit 1
    fi
    for img in "${preload_images[@]}"; do
        docker pull --platform="$PRE_LOAD_LAUNCHPAD_PLATFORM" "$img"
        minikube -p "$PROFILE" image load "$img"
        if ! minikube -p "$PROFILE" image ls 2>/dev/null | grep -qF "$img"; then
            echo "::error::minikube image load did not make $img resolvable in the node; use the GHCR imagePullSecret path" >&2
            exit 1
        fi
    done
fi
echo "::endgroup::"

echo "::group::stage 3 — namespace + runtime secrets"
if [ "$MANAGE_NAMESPACE" = "1" ]; then
    kubectl create namespace "$NAMESPACE" --dry-run=client -o yaml | kubectl apply -f -
else
    kubectl auth can-i get pods -n "$NAMESPACE" >/dev/null
fi

if [ "$MODE" != "baseline" ]; then
    case "$MODE" in
        positive) key="$OPENROUTER_KEY_REAL" ;;
        negative) key="$OPENROUTER_KEY_FAKE" ;;
    esac
    kubectl -n "$NAMESPACE" create secret generic openrouter-key \
        --from-literal=OPENROUTER_API_KEY="$key" \
        --dry-run=client -o yaml | kubectl apply -f -
    apply_ghcr_pull_secret
fi
echo "::endgroup::"

echo "::group::stage 4 — helm render + install"
helm_args=(
    "$RELEASE" "${ROOT}/deploy/helm-chart"
    --namespace "$NAMESPACE"
    --set "helm.production=true"
    --set "helm.signing.key=${SIGNING_KEY}"
    --set "helm.auth.adminAPIKey=${ADMIN_KEY}"
    --set "helm.auth.serviceAPIKey=${SERVICE_KEY}"
    --set "image.repository=${KERNEL_IMAGE%:*}"
    --set "image.tag=${KERNEL_IMAGE##*:}"
    --set "image.pullPolicy=IfNotPresent"
    --set "persistence.enabled=${PERSISTENCE_ENABLED}"
)
if [ -n "$STORAGE_CLASS" ]; then
    helm_args+=(--set "persistence.storageClass=${STORAGE_CLASS}")
fi
case "$MODE" in
    baseline) : ;;
    positive|negative)
        helm_args+=(
            --set "launchpadApps.openclaw.enabled=true"
            --set "launchpadApps.hermes.enabled=true"
            --set "imagePullSecrets[0].name=${GHCR_SECRET_NAME}"
        )
        ;;
esac

rendered_manifest="${TMP_DIR}/rendered.yaml"
kube_helm template "${helm_args[@]}" > "$rendered_manifest"
if grep -Eq '^kind: (ClusterRole|ClusterRoleBinding|CustomResourceDefinition|Namespace|PersistentVolume|StorageClass)$' "$rendered_manifest"; then
    echo "::error::helm template rendered cluster-scoped resources; launchpad smoke must stay namespace-scoped" >&2
    grep -E '^kind: (ClusterRole|ClusterRoleBinding|CustomResourceDefinition|Namespace|PersistentVolume|StorageClass)$' "$rendered_manifest" >&2 || true
    exit 1
fi

install_args=("${helm_args[@]}")
case "$MODE" in
    positive|baseline) install_args+=(--wait --timeout 8m) ;;
    # On negative we expect openclaw never to become Ready — don't make helm
    # block on it. We assert the failure ourselves below.
    negative) install_args+=(--timeout 8m) ;;
esac

kube_helm upgrade --install "${install_args[@]}"
echo "::endgroup::"

assert_pod_ready() {
    local app="$1" timeout="$2"
    local sel="app.kubernetes.io/component=launchpad-app,helm.ai/launchpad-app=${app}"
    echo "waiting up to ${timeout} for Pod ${app} Ready"
    kubectl -n "$NAMESPACE" wait \
        --for=condition=Ready pod \
        -l "$sel" \
        --timeout="$timeout"
}

assert_pod_not_ready() {
    local app="$1" timeout="$2"
    local sel="app.kubernetes.io/component=launchpad-app,helm.ai/launchpad-app=${app}"
    echo "asserting Pod ${app} is NOT Ready within ${timeout}"
    if kubectl -n "$NAMESPACE" wait \
        --for=condition=Ready pod \
        -l "$sel" \
        --timeout="$timeout" >/dev/null 2>&1; then
        echo "::error::pod ${app} became Ready on negative scenario — fake key was silently accepted"
        return 1
    fi
    echo "ok: ${app} did not reach Ready (expected on negative)"
}

assert_job_succeeded() {
    local app="$1" timeout="$2"
    local jobname
    jobname="$(kubectl -n "$NAMESPACE" get jobs -l "helm.ai/launchpad-app=${app}" -o jsonpath='{.items[0].metadata.name}')"
    echo "waiting up to ${timeout} for Job ${jobname} to complete"
    kubectl -n "$NAMESPACE" wait --for=condition=Complete "job/${jobname}" --timeout="$timeout"
}

assert_job_failed() {
    local app="$1" timeout="$2"
    local jobname
    jobname="$(kubectl -n "$NAMESPACE" get jobs -l "helm.ai/launchpad-app=${app}" -o jsonpath='{.items[0].metadata.name}')"
    echo "waiting up to ${timeout} for Job ${jobname} to fail"
    kubectl -n "$NAMESPACE" wait --for=condition=Failed "job/${jobname}" --timeout="$timeout"
}

assert_negative_hermes() {
    # Hermes' Python CLI may exit 0 even when OpenRouter rejects the key
    # (errors are caught, logged, and swallowed). Accept either a Failed Job
    # OR an auth-error pattern in the workload container logs as the negative
    # signal. If the Job Succeeded with no auth error visible — that is a real
    # silent acceptance of a fake credential and we must fail the smoke.
    local timeout="$1"
    local jobname
    jobname="$(kubectl -n "$NAMESPACE" get jobs -l "helm.ai/launchpad-app=hermes" -o jsonpath='{.items[0].metadata.name}')"
    echo "waiting up to ${timeout} for Job ${jobname} to terminate"
    # Try both terminal conditions; whichever fires first wins.
    kubectl -n "$NAMESPACE" wait --for=condition=Complete "job/${jobname}" --timeout="$timeout" 2>/dev/null \
        || kubectl -n "$NAMESPACE" wait --for=condition=Failed "job/${jobname}" --timeout=10s 2>/dev/null \
        || true

    local hermes_pod
    hermes_pod="$(kubectl -n "$NAMESPACE" get pods -l "helm.ai/launchpad-app=hermes" -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)"
    local logs=""
    if [ -n "$hermes_pod" ]; then
        logs="$(kubectl -n "$NAMESPACE" logs "$hermes_pod" -c hermes 2>/dev/null || true)"
    fi
    if echo "$logs" | grep -qiE '401|missing authentication|invalid api key|unauthorized|invalid_api_key'; then
        echo "ok: hermes received auth-rejection from OpenRouter (expected on negative)"
        return 0
    fi
    local job_failed job_succeeded
    job_failed="$(kubectl -n "$NAMESPACE" get "job/${jobname}" -o jsonpath='{.status.failed}' 2>/dev/null || echo 0)"
    job_succeeded="$(kubectl -n "$NAMESPACE" get "job/${jobname}" -o jsonpath='{.status.succeeded}' 2>/dev/null || echo 0)"
    if [ "${job_failed:-0}" != "0" ]; then
        echo "ok: hermes Job reached Failed (expected on negative)"
        return 0
    fi
    if [ "${job_succeeded:-0}" = "1" ]; then
        echo "::error::hermes Job Succeeded on negative scenario with no auth-error visible in logs — fake key was silently accepted"
        echo "::group::hermes container logs"
        echo "$logs"
        echo "::endgroup::"
        return 1
    fi
    echo "ok: hermes did not Complete and did not Fail (expected on negative)"
}

case "$MODE" in
    baseline)
        echo "::group::stage 5 — baseline assertions"
        kubectl -n "$NAMESPACE" rollout status "deployment/${RELEASE}-helm-ai-kernel" --timeout=180s
        kube_helm test "$RELEASE" -n "$NAMESPACE" 2>&1 || {
            # Baseline has no launchpad apps and the test Pod is gated on at
            # least one app being enabled — `helm test` is a no-op then.
            echo "no test hooks rendered for baseline (expected)"
        }
        echo "::endgroup::"
        ;;
    positive)
        echo "::group::stage 5 — positive assertions"
        kubectl -n "$NAMESPACE" rollout status "deployment/${RELEASE}-helm-ai-kernel" --timeout=300s
        assert_pod_ready openclaw 6m
        assert_job_succeeded hermes 3m
        echo "helm test"
        kube_helm test "$RELEASE" -n "$NAMESPACE" --logs
        echo "openclaw kubectl exec healthcheck"
        kubectl -n "$NAMESPACE" exec \
            "deployment/${RELEASE}-helm-ai-kernel-openclaw" \
            -c openclaw \
            -- helm-launchpad-openrouter-check
        echo "::endgroup::"
        ;;
    negative)
        echo "::group::stage 5 — negative assertions"
        kubectl -n "$NAMESPACE" rollout status "deployment/${RELEASE}-helm-ai-kernel" --timeout=300s
        assert_pod_not_ready openclaw 90s
        assert_negative_hermes 3m
        echo "::endgroup::"
        ;;
esac

echo "::group::stage 6 — teardown + leak audit"
kube_helm uninstall "$RELEASE" -n "$NAMESPACE" --wait || true
cleanup_ad_hoc_runtime_secrets

# Leak audit (k8s analogue of GAP #17): after uninstall, no launchpad-app or
# kernel resources should remain in the smoke namespace.
leftover="$(kubectl -n "$NAMESPACE" get all -l app.kubernetes.io/part-of=helm-ai-kernel --no-headers 2>/dev/null || true)"
if [ -n "$leftover" ]; then
    echo "::error::leftover resources detected after helm uninstall:"
    echo "$leftover"
    exit 1
fi
if [ "$MANAGE_NAMESPACE" = "1" ]; then
    kubectl delete namespace "$NAMESPACE" --wait --timeout=120s || true
fi
echo "no leftover resources — teardown clean"
echo "::endgroup::"

echo "launchpad k8s smoke (${MODE}) passed"
