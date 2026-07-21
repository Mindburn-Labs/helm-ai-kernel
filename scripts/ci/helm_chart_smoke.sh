#!/usr/bin/env bash
# Validate the Kubernetes Helm chart with an actual Kubernetes Helm CLI.
#
# Use the Kubernetes Helm CLI for chart rendering. Set KUBE_HELM_CMD to an
# explicit binary, or let the script use a pinned containerized Helm runner.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CHART="${HELM_CHART_PATH:-deploy/helm-chart}"
RELEASE="${HELM_CHART_RELEASE:-helm-smoke}"
NAMESPACE="${HELM_CHART_NAMESPACE:-helm-smoke}"
KUBE_HELM_IMAGE="${KUBE_HELM_IMAGE:-docker.io/alpine/helm@sha256:105741fa6621ed9a3ea944066de78bb27d4b9bb93a56ce8e7cb4d621e1e4bbf2}"
SIGNING_KEY="${HELM_CHART_SMOKE_SIGNING_KEY:-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef}"
TRUST_PUBLIC_KEY="${HELM_CHART_SMOKE_POLICY_TRUST_PUBLIC_KEY:-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef}"
ADMIN_KEY="${HELM_SMOKE_ADMIN_KEY:-helm-admin-smoke}"
SERVICE_KEY="${HELM_SMOKE_SERVICE_KEY:-helm-service-smoke}"
TENANT_ID="${HELM_SMOKE_TENANT_ID:-tenant-smoke}"
AGENT_ID="${HELM_SMOKE_AGENT_ID:-agent.smoke}"
RENDER_DIR="${HELM_CHART_RENDER_DIR:-$(mktemp -d "${TMPDIR:-/tmp}/helm-ai-kernel-chart.XXXXXX")}"

cleanup() {
    if [ -z "${HELM_CHART_RENDER_DIR:-}" ]; then
        rm -rf "$RENDER_DIR"
    fi
}
trap cleanup EXIT

require_pinned_helm_image() {
    if [[ ! "$KUBE_HELM_IMAGE" =~ @sha256:[0-9a-f]{64}$ ]]; then
        echo "::error::KUBE_HELM_IMAGE must be pinned by immutable sha256 digest, got: ${KUBE_HELM_IMAGE}"
        exit 1
    fi
}

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
    command -v docker >/dev/null 2>&1 || {
        echo "::error::Kubernetes Helm not found. Set KUBE_HELM_CMD or install docker for ${KUBE_HELM_IMAGE}."
        exit 1
    }
    require_pinned_helm_image
    docker run --rm -v "$ROOT:/work" -w /work "$KUBE_HELM_IMAGE" "$@"
}

assert_contains() {
    file="$1"
    pattern="$2"
    if ! grep -q -- "$pattern" "$file"; then
        echo "::error::rendered chart missing pattern: $pattern"
        exit 1
    fi
}

assert_not_contains() {
    file="$1"
    pattern="$2"
    if grep -q -- "$pattern" "$file"; then
        echo "::error::rendered chart unexpectedly contained pattern: $pattern"
        exit 1
    fi
}

default_rendered="$RENDER_DIR/rendered-default.yaml"
helm_runner template "$RELEASE" "$CHART" \
    --namespace "$NAMESPACE" \
    --set image.repository=ghcr.io/mindburn-labs/helm-ai-kernel \
    --set image.tag=local \
    --set image.pullPolicy=IfNotPresent >"$default_rendered"

assert_contains "$default_rendered" "kind: Deployment"
assert_contains "$default_rendered" "HELM_POLICY_SOURCE_KIND"
assert_contains "$default_rendered" "mountedFile"
assert_contains "$default_rendered" "HELM_POLICY_SIGNATURE_REQUIRED"
assert_contains "$default_rendered" "/etc/helm-ai-kernel/policy/serve-policy.toml"
assert_contains "$default_rendered" "HELM_RUNTIME_TENANT_ID"
assert_contains "$default_rendered" "HELM_RUNTIME_PRINCIPAL_ID"
assert_contains "$default_rendered" "HELM_RUNTIME_WORKSPACE_ID"
assert_contains "$default_rendered" "HELM_EMERGENCY_STOP_FENCE_ENABLED"
assert_contains "$default_rendered" "value: \"default\""
assert_contains "$default_rendered" "value: \"system-admin\""
assert_contains "$default_rendered" "value: \"0\""
assert_not_contains "$default_rendered" "HELM_EMERGENCY_STOP_COMMAND_AUDIENCE"
assert_not_contains "$default_rendered" "HELM_EMERGENCY_STOP_COMMAND_PUBLIC_KEYS"
assert_contains "$default_rendered" "automountServiceAccountToken: false"
assert_not_contains "$default_rendered" "HELM_POLICY_TRUST_PUBLIC_KEY"
assert_not_contains "$default_rendered" "checksum/config"
assert_not_contains "$default_rendered" "configmap-reload"
assert_not_contains "$default_rendered" "kind: CustomResourceDefinition"
assert_not_contains "$default_rendered" "HelmPolicyBundle"
assert_not_contains "$default_rendered" "policy-reader"

emergency_stop_rendered="$RENDER_DIR/rendered-emergency-stop.yaml"
helm_runner template "$RELEASE" "$CHART" \
    --namespace "$NAMESPACE" \
    --set helm.emergencyStop.enabled=true \
    --set helm.emergencyStop.audience=kernel-qa \
    --set helm.emergencyStop.commandPublicKeys=cp-stop-qa=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa >"$emergency_stop_rendered"
assert_contains "$emergency_stop_rendered" "HELM_EMERGENCY_STOP_FENCE_ENABLED"
assert_contains "$emergency_stop_rendered" "value: \"1\""
assert_contains "$emergency_stop_rendered" "HELM_EMERGENCY_STOP_COMMAND_AUDIENCE"
assert_contains "$emergency_stop_rendered" "kernel-qa"
assert_contains "$emergency_stop_rendered" "HELM_EMERGENCY_STOP_COMMAND_PUBLIC_KEYS"

emergency_stop_missing_authority_log="$RENDER_DIR/emergency-stop-missing-authority.log"
if helm_runner template "$RELEASE" "$CHART" \
    --namespace "$NAMESPACE" \
    --set helm.emergencyStop.enabled=true \
    --set helm.emergencyStop.audience=kernel-qa >"$RENDER_DIR/emergency-stop-missing-authority.yaml" 2>"$emergency_stop_missing_authority_log"; then
    echo "::error::emergency-stop render without command authority unexpectedly succeeded"
    exit 1
fi
assert_contains "$emergency_stop_missing_authority_log" "helm.emergencyStop.commandPublicKeys"

hermes_job_rendered="$RENDER_DIR/rendered-hermes-job.yaml"
helm_runner template "$RELEASE" "$CHART" \
    --namespace "$NAMESPACE" \
    --set launchpadApps.hermes.enabled=true \
    --set launchpadApps.hermes.provider=anthropic \
    --set-string launchpadApps.hermes.model=anthropic/claude-3-5-haiku \
    --set-string launchpadApps.hermes.query="chart smoke" >"$hermes_job_rendered"
assert_contains "$hermes_job_rendered" "kind: Job"
assert_contains "$hermes_job_rendered" "helm-ai-kernel-hermes"
assert_contains "$hermes_job_rendered" "helm.sh/hook-delete-policy: before-hook-creation,hook-succeeded"
# Match any argument order or added redirection, not one exact spelling.
if grep -Eq 'kube_helm[[:space:]]+test\b[^#]*--logs' "$ROOT/scripts/ci/launchpad_k8s_smoke.sh"; then
    echo "::error::launchpad smoke requests Helm test logs after successful hooks are deleted"
    exit 1
fi
assert_contains "$hermes_job_rendered" "anthropic/claude-3-5-haiku"
assert_contains "$hermes_job_rendered" "chart smoke"
assert_contains "$hermes_job_rendered" "--provider"

hermes_deployment_rendered="$RENDER_DIR/rendered-hermes-deployment.yaml"
helm_runner template "$RELEASE" "$CHART" \
    --namespace "$NAMESPACE" \
    --set launchpadApps.hermes.enabled=true \
    --set launchpadApps.hermes.mode=deployment >"$hermes_deployment_rendered"
assert_contains "$hermes_deployment_rendered" "kind: Deployment"
assert_contains "$hermes_deployment_rendered" "gateway-mode-not-live-f2-promoted"
assert_contains "$hermes_deployment_rendered" "HOME=/var/lib/hermes exec hermes --gateway"
assert_contains "$hermes_deployment_rendered" "name: egress-proxy"

hermes_override_rendered="$RENDER_DIR/rendered-hermes-command-override.yaml"
helm_runner template "$RELEASE" "$CHART" \
    --namespace "$NAMESPACE" \
    --set launchpadApps.hermes.enabled=true \
    --set-json 'launchpadApps.hermes.commandOverride=["/bin/sh","-c","echo custom-hermes-command"]' >"$hermes_override_rendered"
assert_contains "$hermes_override_rendered" "custom-hermes-command"
assert_not_contains "$hermes_override_rendered" "--provider"

hermes_mode_fail_log="$RENDER_DIR/hermes-invalid-mode.log"
if helm_runner template "$RELEASE" "$CHART" \
    --namespace "$NAMESPACE" \
    --set launchpadApps.hermes.enabled=true \
    --set launchpadApps.hermes.mode=daemon >"$RENDER_DIR/hermes-invalid-mode.yaml" 2>"$hermes_mode_fail_log"; then
    echo "::error::Hermes render with invalid mode unexpectedly succeeded"
    exit 1
fi
assert_contains "$hermes_mode_fail_log" "launchpadApps.hermes.mode"

fail_log="$RENDER_DIR/production-missing-key.log"
if helm_runner template "$RELEASE" "$CHART" \
    --namespace "$NAMESPACE" \
    --set helm.production=true >"$RENDER_DIR/production-missing-key.yaml" 2>"$fail_log"; then
    echo "::error::production render without signing key unexpectedly succeeded"
    exit 1
fi
assert_contains "$fail_log" "requires helm.signing.key"

tenant_fail_log="$RENDER_DIR/production-missing-runtime-tenant.log"
if helm_runner template "$RELEASE" "$CHART" \
    --namespace "$NAMESPACE" \
    --set helm.production=true \
    --set helm.signing.key="$SIGNING_KEY" \
    --set helm.auth.adminAPIKey="$ADMIN_KEY" \
    --set helm.auth.serviceAPIKey="$SERVICE_KEY" \
    --set-string helm.auth.tenantID= >"$RENDER_DIR/production-missing-runtime-tenant.yaml" 2>"$tenant_fail_log"; then
    echo "::error::production render without runtime tenant unexpectedly succeeded"
    exit 1
fi
assert_contains "$tenant_fail_log" "helm.auth.tenantID"

principal_fail_log="$RENDER_DIR/production-missing-runtime-principal.log"
if helm_runner template "$RELEASE" "$CHART" \
    --namespace "$NAMESPACE" \
    --set helm.production=true \
    --set helm.signing.key="$SIGNING_KEY" \
    --set helm.auth.adminAPIKey="$ADMIN_KEY" \
    --set helm.auth.serviceAPIKey="$SERVICE_KEY" \
    --set-string helm.auth.principalID= >"$RENDER_DIR/production-missing-runtime-principal.yaml" 2>"$principal_fail_log"; then
    echo "::error::production render without runtime principal unexpectedly succeeded"
    exit 1
fi
assert_contains "$principal_fail_log" "helm.auth.principalID"

postgres_inline_fail_log="$RENDER_DIR/postgres-inline-production.log"
if helm_runner template "$RELEASE" "$CHART" \
    --namespace "$NAMESPACE" \
    --set helm.production=true \
    --set helm.signing.key="$SIGNING_KEY" \
    --set helm.auth.adminAPIKey="$ADMIN_KEY" \
    --set helm.auth.serviceAPIKey="$SERVICE_KEY" \
    --set helm.storage.type=postgres \
    --set helm.storage.postgres.host=postgres.example.internal \
    --set helm.storage.postgres.password=secret >"$RENDER_DIR/postgres-inline-production.yaml" 2>"$postgres_inline_fail_log"; then
    echo "::error::production postgres render with inline credentials unexpectedly succeeded"
    exit 1
fi
assert_contains "$postgres_inline_fail_log" "requires helm.storage.postgres.existingSecret"

postgres_tls_fail_log="$RENDER_DIR/postgres-weak-tls-production.log"
if helm_runner template "$RELEASE" "$CHART" \
    --namespace "$NAMESPACE" \
    --set helm.production=true \
    --set helm.signing.key="$SIGNING_KEY" \
    --set helm.auth.adminAPIKey="$ADMIN_KEY" \
    --set helm.auth.serviceAPIKey="$SERVICE_KEY" \
    --set helm.storage.type=postgres \
    --set helm.storage.postgres.existingSecret=helm-postgres-url \
    --set helm.storage.postgres.sslMode=disable >"$RENDER_DIR/postgres-weak-tls-production.yaml" 2>"$postgres_tls_fail_log"; then
    echo "::error::production postgres render with weak sslMode unexpectedly succeeded"
    exit 1
fi
assert_contains "$postgres_tls_fail_log" "requires helm.storage.postgres.sslMode"

postgres_subchart_fail_log="$RENDER_DIR/postgres-subchart-production.log"
if helm_runner template "$RELEASE" "$CHART" \
    --namespace "$NAMESPACE" \
    --set helm.production=true \
    --set helm.signing.key="$SIGNING_KEY" \
    --set helm.auth.adminAPIKey="$ADMIN_KEY" \
    --set helm.auth.serviceAPIKey="$SERVICE_KEY" \
    --set helm.storage.type=postgres \
    --set helm.storage.postgres.existingSecret=helm-postgres-url \
    --set postgresql.enabled=true >"$RENDER_DIR/postgres-subchart-production.yaml" 2>"$postgres_subchart_fail_log"; then
    echo "::error::production postgres render with bundled subchart unexpectedly succeeded"
    exit 1
fi
assert_contains "$postgres_subchart_fail_log" "does not support the bundled postgresql subchart"

postgres_rendered="$RENDER_DIR/rendered-postgres-secret.yaml"
helm_runner template "$RELEASE" "$CHART" \
    --namespace "$NAMESPACE" \
    --set helm.production=true \
    --set helm.signing.key="$SIGNING_KEY" \
    --set helm.auth.adminAPIKey="$ADMIN_KEY" \
    --set helm.auth.serviceAPIKey="$SERVICE_KEY" \
    --set helm.storage.type=postgres \
    --set helm.storage.postgres.existingSecret=helm-postgres-url \
    --set helm.storage.postgres.sslMode=verify-full >"$postgres_rendered"
assert_contains "$postgres_rendered" "name: DATABASE_URL"
assert_contains "$postgres_rendered" "secretKeyRef:"
assert_contains "$postgres_rendered" "name: helm-postgres-url"
assert_not_contains "$postgres_rendered" "postgres://"
assert_not_contains "$postgres_rendered" "POSTGRES_PASSWORD"
assert_not_contains "$postgres_rendered" "sslmode=disable"

helm_runner lint "$CHART" \
    --set helm.production=true \
    --set helm.signing.key="$SIGNING_KEY" \
    --set helm.auth.adminAPIKey="$ADMIN_KEY" \
    --set helm.auth.serviceAPIKey="$SERVICE_KEY" \
    --set helm.auth.tenantID="$TENANT_ID" \
    --set helm.auth.principalID="$AGENT_ID" \
    --set image.repository=ghcr.io/mindburn-labs/helm-ai-kernel \
    --set image.tag=local \
    --set image.pullPolicy=IfNotPresent >/dev/null

rendered="$RENDER_DIR/rendered.yaml"
helm_runner template "$RELEASE" "$CHART" \
    --namespace "$NAMESPACE" \
    --set helm.production=true \
    --set helm.signing.key="$SIGNING_KEY" \
    --set helm.auth.adminAPIKey="$ADMIN_KEY" \
    --set helm.auth.serviceAPIKey="$SERVICE_KEY" \
    --set helm.auth.tenantID="$TENANT_ID" \
    --set helm.auth.principalID="$AGENT_ID" \
    --set image.repository=ghcr.io/mindburn-labs/helm-ai-kernel \
    --set image.tag=local \
    --set image.pullPolicy=IfNotPresent >"$rendered"

assert_contains "$rendered" "kind: Deployment"
assert_contains "$rendered" "serve"
assert_contains "$rendered" "--policy"
assert_contains "$rendered" "/etc/helm-ai-kernel/policy/serve-policy.toml"
assert_contains "$rendered" "--data-dir"
assert_contains "$rendered" "/data"
assert_contains "$rendered" "HELM_PRODUCTION"
assert_contains "$rendered" "HELM_POLICY_SOURCE_KIND"
assert_contains "$rendered" "mountedFile"
assert_contains "$rendered" "HELM_POLICY_POLL_INTERVAL"
assert_contains "$rendered" "HELM_POLICY_SIGNATURE_REQUIRED"
assert_contains "$rendered" "/internal/policy/reconcile"
assert_contains "$rendered" "EVIDENCE_SIGNING_KEY"
assert_contains "$rendered" "HELM_ADMIN_API_KEY"
assert_contains "$rendered" "HELM_SERVICE_API_KEY"
assert_contains "$rendered" "HELM_RUNTIME_TENANT_ID"
assert_contains "$rendered" "HELM_RUNTIME_PRINCIPAL_ID"
assert_contains "$rendered" "value: \"$TENANT_ID\""
assert_contains "$rendered" "value: \"$AGENT_ID\""
assert_contains "$rendered" "readOnlyRootFilesystem: true"
assert_contains "$rendered" "runAsNonRoot: true"
assert_contains "$rendered" "persistentVolumeClaim:"
assert_contains "$rendered" "path: /health"
assert_contains "$rendered" "kind: Secret"
assert_contains "$rendered" "kind: ConfigMap"
assert_not_contains "$rendered" "configmap-reload"
assert_not_contains "$rendered" "kind: CustomResourceDefinition"
assert_not_contains "$rendered" "HelmPolicyBundle"
assert_not_contains "$rendered" "policy-reader"

controlplane_fail_log="$RENDER_DIR/controlplane-missing-url.log"
if helm_runner template "$RELEASE" "$CHART" \
    --namespace "$NAMESPACE" \
    --set helm.production=true \
    --set helm.signing.key="$SIGNING_KEY" \
    --set helm.auth.adminAPIKey="$ADMIN_KEY" \
    --set helm.auth.serviceAPIKey="$SERVICE_KEY" \
    --set helm.policy.source.kind=controlplane >"$RENDER_DIR/controlplane-missing-url.yaml" 2>"$controlplane_fail_log"; then
    echo "::error::production controlplane render without URL unexpectedly succeeded"
    exit 1
fi
assert_contains "$controlplane_fail_log" "helm.policy.source.controlplane.url"

controlplane_unsigned_log="$RENDER_DIR/controlplane-missing-signature.log"
if helm_runner template "$RELEASE" "$CHART" \
    --namespace "$NAMESPACE" \
    --set helm.production=true \
    --set helm.signing.key="$SIGNING_KEY" \
    --set helm.auth.adminAPIKey="$ADMIN_KEY" \
    --set helm.auth.serviceAPIKey="$SERVICE_KEY" \
    --set helm.policy.source.kind=controlplane \
    --set helm.policy.source.controlplane.url=https://helm-controlplane.example.internal >"$RENDER_DIR/controlplane-missing-signature.yaml" 2>"$controlplane_unsigned_log"; then
    echo "::error::production controlplane render without required policy signatures unexpectedly succeeded"
    exit 1
fi
assert_contains "$controlplane_unsigned_log" "helm.policy.signature.required=true"

controlplane_rendered="$RENDER_DIR/rendered-controlplane.yaml"
helm_runner template "$RELEASE" "$CHART" \
    --namespace "$NAMESPACE" \
    --set helm.production=true \
    --set helm.signing.key="$SIGNING_KEY" \
    --set helm.auth.adminAPIKey="$ADMIN_KEY" \
    --set helm.auth.serviceAPIKey="$SERVICE_KEY" \
    --set helm.policy.source.kind=controlplane \
    --set helm.policy.source.controlplane.url=https://helm-controlplane.example.internal \
    --set helm.policy.signature.required=true \
    --set helm.policy.signature.publicKey="$TRUST_PUBLIC_KEY" \
    --set image.repository=ghcr.io/mindburn-labs/helm-ai-kernel \
    --set image.tag=local \
    --set image.pullPolicy=IfNotPresent >"$controlplane_rendered"

assert_contains "$controlplane_rendered" "HELM_POLICY_SOURCE_KIND"
assert_contains "$controlplane_rendered" "controlplane"
assert_contains "$controlplane_rendered" "HELM_POLICY_CONTROLPLANE_URL"
assert_contains "$controlplane_rendered" "https://helm-controlplane.example.internal"
assert_contains "$controlplane_rendered" "HELM_POLICY_SIGNATURE_REQUIRED"
assert_contains "$controlplane_rendered" "HELM_POLICY_TRUST_PUBLIC_KEY"
assert_not_contains "$controlplane_rendered" "configmap-reload"
assert_not_contains "$controlplane_rendered" "kind: CustomResourceDefinition"
assert_not_contains "$controlplane_rendered" "policy-reader"

crd_rendered="$RENDER_DIR/rendered-crd.yaml"
helm_runner template "$RELEASE" "$CHART" \
    --namespace "$NAMESPACE" \
    --set helm.production=true \
    --set helm.signing.key="$SIGNING_KEY" \
    --set helm.auth.adminAPIKey="$ADMIN_KEY" \
    --set helm.auth.serviceAPIKey="$SERVICE_KEY" \
    --set helm.policy.source.kind=crd \
    --set helm.policy.source.crd.install=true \
    --set image.repository=ghcr.io/mindburn-labs/helm-ai-kernel \
    --set image.tag=local \
    --set image.pullPolicy=IfNotPresent >"$crd_rendered"

assert_contains "$crd_rendered" "kind: CustomResourceDefinition"
assert_contains "$crd_rendered" "HelmPolicyBundle"
assert_contains "$crd_rendered" "kind: Role"
assert_contains "$crd_rendered" "helmpolicybundles"
assert_contains "$crd_rendered" "automountServiceAccountToken: true"

echo "helm chart smoke passed"
