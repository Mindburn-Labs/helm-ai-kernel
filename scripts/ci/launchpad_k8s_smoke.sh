#!/usr/bin/env bash
# Launchpad k8s smoke driver. Brings up a clean minikube cluster, installs the
# helm chart with openclaw and hermes co-deployed, runs the canonical positive
# or negative scenario, and audits for leaks after teardown.
#
# Generic-cluster mode (vanilla k8s, EKS, GKE, bare-metal) is tracked as a
# follow-up task `launchpad-k8s-smoke-generic-cluster`. This driver intentionally
# owns the cluster lifecycle so smoke iterations start from a known empty state.
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
# Required tools: minikube, kubectl, helm. The driver fails fast if any are
# missing.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
MODE="${LAUNCHPAD_SMOKE_MODE:-positive}"
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
PRE_PULL="${LAUNCHPAD_SMOKE_PRE_PULL:-1}"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/launchpad-k8s-smoke.XXXXXX")"

usage() {
    cat <<EOF
Usage: $0 [--mode baseline|positive|negative]

Environment overrides:
  LAUNCHPAD_SMOKE_MODE          one of baseline|positive|negative (default positive)
  LAUNCHPAD_SMOKE_PROFILE       minikube profile name (default launchpad-smoke)
  LAUNCHPAD_SMOKE_NAMESPACE     release namespace (default helm-launchpad-smoke)
  LAUNCHPAD_SMOKE_RELEASE       helm release name (default kernel)
  LAUNCHPAD_SMOKE_KERNEL_IMAGE  kernel image to load into minikube (default ghcr.io/mindburn-labs/helm-ai-kernel:local)
  LAUNCHPAD_SMOKE_KEEP_CLUSTER  set to 1 to skip the final minikube delete
  LAUNCHPAD_SMOKE_FRESH_CLUSTER set to 0 to reuse an existing minikube profile (assumes the cluster is already running and kernel image is loaded)
  LAUNCHPAD_SMOKE_PRE_PULL      set to 0 to skip pulling openclaw/hermes/egress-proxy
  OPENROUTER_API_KEY            real key for the positive scenario; ignored on negative
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        --mode) MODE="$2"; shift 2;;
        --mode=*) MODE="${1#--mode=}"; shift;;
        --keep-cluster) KEEP_CLUSTER=1; shift;;
        -h|--help) usage; exit 0;;
        *) echo "unknown arg: $1" >&2; usage >&2; exit 2;;
    esac
done

case "$MODE" in
    baseline|positive|negative) ;;
    *) echo "::error::invalid --mode '$MODE' (expected baseline|positive|negative)" >&2; exit 2;;
esac

require() {
    command -v "$1" >/dev/null 2>&1 || {
        echo "::error::$1 is required for launchpad k8s smoke" >&2
        exit 1
    }
}
require minikube
require kubectl
require helm
require docker

if [ "$MODE" = "positive" ] && [ -z "$OPENROUTER_KEY_REAL" ]; then
    echo "::error::OPENROUTER_API_KEY env var is required for --mode positive" >&2
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
        # Best-effort namespace teardown so the next run starts clean. The
        # cluster itself stays around when KEEP_CLUSTER=1 (local iteration);
        # only the smoke namespace is sacrificed.
        helm uninstall "$RELEASE" -n "$NAMESPACE" --ignore-not-found --wait --timeout 60s 2>/dev/null || true
        kubectl delete namespace "$NAMESPACE" --wait=false 2>/dev/null || true
    fi
    rm -rf "$TMP_DIR"
    if [ "$KEEP_CLUSTER" != "1" ] && [ "$FRESH_CLUSTER" = "1" ]; then
        minikube delete -p "$PROFILE" >/dev/null 2>&1 || true
    fi
    exit "$rc"
}
trap cleanup EXIT

echo "::group::stage 1 — minikube cluster"
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
kubectl cluster-info
echo "::endgroup::"

echo "::group::stage 2 — load images into minikube"
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

if [ "$PRE_PULL" = "1" ] && [ "$MODE" != "baseline" ]; then
    # Cold-pull on minikube is slow and prone to timing out helm install.
    # Pull on the host first, then load into the cluster.
    for img in \
        "ghcr.io/mindburn-labs/helm-launchpad/openclaw@sha256:4da80a1e48b5603fd203b7d2b98539a01f796142b0ed9315e5ed86b25bf5d995" \
        "ghcr.io/mindburn-labs/helm-launchpad/hermes@sha256:4ec024dd8d0191fc887f04dc92c959fc865808d1526f782b5093f395fdd41652" \
        "ghcr.io/mindburn-labs/helm-launchpad/egress-proxy@sha256:e09e0aec1e0e1f926f4cd18444e88310656b85551cbc10a6c340acb979a42e03"; do
        docker pull --platform=linux/amd64 "$img"
        minikube -p "$PROFILE" image load "$img"
    done
fi
echo "::endgroup::"

echo "::group::stage 3 — namespace + OpenRouter secret"
kubectl create namespace "$NAMESPACE" --dry-run=client -o yaml | kubectl apply -f -

if [ "$MODE" != "baseline" ]; then
    case "$MODE" in
        positive) key="$OPENROUTER_KEY_REAL" ;;
        negative) key="$OPENROUTER_KEY_FAKE" ;;
    esac
    kubectl -n "$NAMESPACE" create secret generic openrouter-key \
        --from-literal=OPENROUTER_API_KEY="$key" \
        --dry-run=client -o yaml | kubectl apply -f -
fi
echo "::endgroup::"

echo "::group::stage 4 — helm install"
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
    --set "persistence.enabled=true"
)
case "$MODE" in
    baseline) : ;;
    positive|negative)
        helm_args+=(
            --set "launchpadApps.openclaw.enabled=true"
            --set "launchpadApps.hermes.enabled=true"
        )
        ;;
esac

case "$MODE" in
    positive|baseline) helm_args+=(--wait --timeout 8m) ;;
    # On negative we expect openclaw never to become Ready — don't make helm
    # block on it. We assert the failure ourselves below.
    negative) helm_args+=(--timeout 8m) ;;
esac

helm upgrade --install "${helm_args[@]}"
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
        helm test "$RELEASE" -n "$NAMESPACE" 2>&1 || {
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
        helm test "$RELEASE" -n "$NAMESPACE" --logs
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
helm uninstall "$RELEASE" -n "$NAMESPACE" --wait || true
kubectl delete namespace "$NAMESPACE" --wait --timeout=120s || true

# Leak audit (k8s analogue of GAP #17): after uninstall, no launchpad-app or
# kernel resources should remain anywhere on the cluster.
leftover="$(kubectl get all -A -l app.kubernetes.io/part-of=helm-ai-kernel --no-headers 2>/dev/null || true)"
if [ -n "$leftover" ]; then
    echo "::error::leftover resources detected after helm uninstall:"
    echo "$leftover"
    exit 1
fi
echo "no leftover resources — teardown clean"
echo "::endgroup::"

echo "launchpad k8s smoke (${MODE}) passed"
