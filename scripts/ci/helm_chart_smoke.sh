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
PRODUCTION_IMAGE_DIGEST="${HELM_CHART_SMOKE_IMAGE_DIGEST:-sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef}"
REPLAY_KEYRING='{"keyring_version":"emergency-stop-fence-command-replay-keyring.v1","keys":[{"command_key_id":"cp-stop-before-rotation","command_audience":"kernel-before-rotation","command_public_key":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}]}'
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

# Every assertion below is a literal string from the rendered chart, so both
# helpers match fixed strings. Without -F, grep reads the pattern as a BRE and
# `.` matches any character: `helm.sh/hook-delete-policy` would also accept
# `helmXsh/...`, which is a test that can pass on the wrong output.
assert_contains() {
    file="$1"
    pattern="$2"
    if ! grep -qF -- "$pattern" "$file"; then
        echo "::error::rendered chart missing pattern: $pattern"
        exit 1
    fi
}

assert_not_contains() {
    file="$1"
    pattern="$2"
    if grep -qF -- "$pattern" "$file"; then
        echo "::error::rendered chart unexpectedly contained pattern: $pattern"
        exit 1
    fi
}

PRODUCTION_NETWORK_POLICY_VALUES="scripts/ci/helm_production_network_policy_values.yaml"

production_helm_runner() {
    helm_runner "$@" \
        --values "$PRODUCTION_NETWORK_POLICY_VALUES" \
        --set image.digest="$PRODUCTION_IMAGE_DIGEST"
}

production_controlplane_helm_runner() {
    production_helm_runner "$@" \
        --set helm.policy.source.kind=controlplane \
        --set helm.policy.source.controlplane.url=https://helm-controlplane.example.internal \
        --set helm.policy.source.controlplane.tls.existingSecret=helm-policy-controlplane-ca \
        --set helm.policy.signature.required=true \
        --set helm.policy.signature.publicKey="$TRUST_PUBLIC_KEY"
}

default_rendered="$RENDER_DIR/rendered-default.yaml"
helm_runner template "$RELEASE" "$CHART" \
    --namespace "$NAMESPACE" \
    --set image.repository=ghcr.io/mindburn-labs/helm-ai-kernel \
    --set image.tag=local \
    --set image.pullPolicy=IfNotPresent >"$default_rendered"

assert_contains "$default_rendered" "kind: Deployment"
assert_contains "$default_rendered" 'image: "ghcr.io/mindburn-labs/helm-ai-kernel:local"'
assert_contains "$default_rendered" "HELM_POLICY_SOURCE_KIND"
assert_contains "$default_rendered" "mountedFile"
assert_contains "$default_rendered" "HELM_POLICY_ON_INVALID_UPDATE"
assert_contains "$default_rendered" "HELM_POLICY_LAST_KNOWN_GOOD_MAX_AGE"
assert_contains "$default_rendered" "keepLastKnownGood"
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
assert_not_contains "$default_rendered" "HELM_EMERGENCY_STOP_COMMAND_REPLAY_KEYRING"
assert_contains "$default_rendered" "automountServiceAccountToken: false"
assert_not_contains "$default_rendered" "HELM_POLICY_TRUST_PUBLIC_KEY"
assert_not_contains "$default_rendered" "checksum/config"
assert_not_contains "$default_rendered" "configmap-reload"
assert_not_contains "$default_rendered" "kind: CustomResourceDefinition"
assert_not_contains "$default_rendered" "HelmPolicyBundle"
assert_not_contains "$default_rendered" "policy-reader"
assert_not_contains "$default_rendered" "HELM_ENV"
assert_not_contains "$default_rendered" "HELM_SEMANTIC_THREAT_ESCALATION_BP"
assert_not_contains "$default_rendered" "HELM_GITHUB_TOKEN"
assert_not_contains "$default_rendered" "HELM_GITHUB_API_URL"
assert_not_contains "$default_rendered" "kernel ingress and egress are allowlist-only"
assert_contains "$default_rendered" '"runtime_actions": []'
assert_contains "$default_rendered" "name: prepare-authority-state"
assert_contains "$default_rendered" "HELM_AUTHORITY_DATA_DIR"
assert_contains "$default_rendered" "/var/run/helm-signing-key"
assert_contains "$default_rendered" "defaultMode: 256"
assert_contains "$default_rendered" "runAsNonRoot: true"
assert_contains "$default_rendered" "runAsUser: 65534"
assert_contains "$default_rendered" "runAsGroup: 65534"
authority_init_security="$RENDER_DIR/rendered-authority-init-security.yaml"
awk '/name: prepare-authority-state/{capture=1} capture{print} capture && /^[[:space:]]+command:/{exit}' "$default_rendered" >"$authority_init_security"
assert_contains "$authority_init_security" "drop:"
assert_contains "$authority_init_security" "ALL"
assert_not_contains "$authority_init_security" "add:"
assert_not_contains "$authority_init_security" "CHOWN"
assert_not_contains "$authority_init_security" "runAsNonRoot: false"
assert_not_contains "$authority_init_security" "runAsUser: 0"
assert_not_contains "$authority_init_security" "runAsGroup: 0"
assert_contains "$default_rendered" "refusing silent rotation"
assert_contains "$default_rendered" "authority data volume is not writable by the restricted runtime identity"
assert_not_contains "$default_rendered" "subPath: root.key"
assert_not_contains "$default_rendered" "mountPath: /data/root.key"

# Upgrade-with-existing-data contract: a durable key written by an earlier
# release can be owned by a different uid, and chmod by a non-owner is EPERM
# even when the file is readable. The init must verify content identity with
# the Secret and treat mode-tightening on a pre-existing key as best-effort —
# an unconditional chmod stranded every QA upgrade to chart 0.8.3 while fresh
# installs (CI) passed. An unreadable existing key must still fail closed.
assert_contains "$default_rendered" 'chmod 0600 "$root_key" 2>/dev/null || true'
assert_contains "$default_rendered" "durable authority root key exists but is not readable"
assert_contains "$default_rendered" 'watermark="$data_dir/policy-replay-watermarks.json"'
assert_contains "$default_rendered" 'chmod 0600 "$watermark"'
assert_contains "$default_rendered" "could not restore private policy replay watermark mode after fsGroup processing"
authority_init_script="$RENDER_DIR/rendered-authority-init-script.txt"
awk '/prepare-authority-state/{capture=1} capture{print} capture && /volumeMounts:/{exit}' "$default_rendered" >"$authority_init_script"
if [ "$(/usr/bin/grep -c 'chmod 0600 "$root_key"' "$authority_init_script" 2>/dev/null || grep -c 'chmod 0600 "$root_key"' "$authority_init_script")" != "1" ]; then
    echo "::error::expected exactly one existing-key chmod in the authority init, and it must be best-effort"
    exit 1
fi
if ! awk '/cmp -s "\$source_key" "\$root_key"/{seen_cmp=1} /chmod 0600 "\$root_key" 2>\/dev\/null/{if (!seen_cmp) exit 1}' "$authority_init_script"; then
    echo "::error::the existing-key chmod must come after content verification against the Secret"
    exit 1
fi

runtime_init_fail_log="$RENDER_DIR/runtime-init-unpinned-image.log"
if helm_runner template "$RELEASE" "$CHART" \
    --namespace "$NAMESPACE" \
    --set runtimeInit.image=alpine:3.20 >"$RENDER_DIR/runtime-init-unpinned-image.yaml" 2>"$runtime_init_fail_log"; then
    echo "::error::chart render with an unpinned authority init image unexpectedly succeeded"
    exit 1
fi
assert_contains "$runtime_init_fail_log" "runtimeInit.image"

synthetic_telemetry_rendered="$RENDER_DIR/rendered-synthetic-telemetry.yaml"
helm_runner template "$RELEASE" "$CHART" \
    --namespace "$NAMESPACE" \
    --set telemetry.enabled=true \
    --set telemetry.syntheticLifecycleEvents=true \
    --set telemetry.endpoint=http://telemetry-gateway.telemetry-system.svc.cluster.local:4317 >"$synthetic_telemetry_rendered"
assert_contains "$synthetic_telemetry_rendered" "HELM_ENV"
assert_contains "$synthetic_telemetry_rendered" 'value: "synthetic"'

synthetic_without_telemetry_log="$RENDER_DIR/synthetic-without-telemetry.log"
if helm_runner template "$RELEASE" "$CHART" \
    --namespace "$NAMESPACE" \
    --set telemetry.syntheticLifecycleEvents=true >"$RENDER_DIR/synthetic-without-telemetry.yaml" 2>"$synthetic_without_telemetry_log"; then
    echo "::error::synthetic lifecycle publication without telemetry unexpectedly rendered"
    exit 1
fi
assert_contains "$synthetic_without_telemetry_log" "telemetry.syntheticLifecycleEvents=true requires telemetry.enabled=true"

github_effects_rendered="$RENDER_DIR/rendered-github-effects.yaml"
helm_runner template "$RELEASE" "$CHART" \
    --namespace "$NAMESPACE" \
    --set helm.githubEffects.existingSecret=helm-github-effects \
    --set helm.githubEffects.apiURL=http://github-api.qa.svc.cluster.local >"$github_effects_rendered"
assert_contains "$github_effects_rendered" "HELM_GITHUB_TOKEN"
assert_contains "$github_effects_rendered" "name: helm-github-effects"
assert_contains "$github_effects_rendered" "key: HELM_GITHUB_TOKEN"
assert_contains "$github_effects_rendered" "HELM_GITHUB_API_URL"
assert_contains "$github_effects_rendered" "http://github-api.qa.svc.cluster.local"

github_effects_missing_secret_log="$RENDER_DIR/github-effects-missing-secret.log"
if helm_runner template "$RELEASE" "$CHART" \
    --namespace "$NAMESPACE" \
    --set helm.githubEffects.apiURL=http://github-api.qa.svc.cluster.local >"$RENDER_DIR/github-effects-missing-secret.yaml" 2>"$github_effects_missing_secret_log"; then
    echo "::error::GitHub effects API URL without a token Secret unexpectedly rendered"
    exit 1
fi
assert_contains "$github_effects_missing_secret_log" "helm.githubEffects.apiURL requires helm.githubEffects.existingSecret"

runtime_actions_rendered="$RENDER_DIR/rendered-runtime-actions.yaml"
helm_runner template "$RELEASE" "$CHART" \
    --namespace "$NAMESPACE" \
    --set-json 'helm.policy.runtimeActions=[{"action":"file_read","expression":"input.effect.params.path == \"/etc/hostname\""}]' >"$runtime_actions_rendered"
assert_contains "$runtime_actions_rendered" '"runtime_actions": [{"action":"file_read","expression":"input.effect.params.path == \"/etc/hostname\""}]'

semantic_escalation_rendered="$RENDER_DIR/rendered-semantic-escalation.yaml"
helm_runner template "$RELEASE" "$CHART" \
    --namespace "$NAMESPACE" \
    --set helm.guardian.semanticThreatEscalationBP=7000 >"$semantic_escalation_rendered"
assert_contains "$semantic_escalation_rendered" "HELM_SEMANTIC_THREAT_ESCALATION_BP"
assert_contains "$semantic_escalation_rendered" 'value: "7000"'

if helm_runner template "$RELEASE" "$CHART" \
    --namespace "$NAMESPACE" \
    --set helm.guardian.semanticThreatEscalationBP=10001 >"$RENDER_DIR/rendered-invalid-semantic-escalation.yaml" 2>&1; then
    echo "::error::out-of-range semantic escalation threshold unexpectedly rendered"
    exit 1
fi

authority_identity_rendered="$RENDER_DIR/rendered-authority-identity.yaml"
helm_runner template "$RELEASE" "$CHART" \
    --namespace "$NAMESPACE" \
    --set podSecurityContext.runAsUser=12345 \
    --set podSecurityContext.runAsGroup=12346 \
    --set podSecurityContext.fsGroup=12346 >"$authority_identity_rendered"
authority_identity_security="$RENDER_DIR/rendered-authority-identity-security.yaml"
awk '/name: prepare-authority-state/{capture=1} capture{print} capture && /^[[:space:]]+command:/{exit}' "$authority_identity_rendered" >"$authority_identity_security"
assert_contains "$authority_identity_security" "runAsNonRoot: true"
assert_contains "$authority_identity_security" "runAsUser: 12345"
assert_contains "$authority_identity_security" "runAsGroup: 12346"

lkg_rendered="$RENDER_DIR/rendered-lkg-policy.yaml"
helm_runner template "$RELEASE" "$CHART" \
    --namespace "$NAMESPACE" \
    --set helm.policy.failClosed.onInvalidUpdate=deny \
    --set helm.policy.failClosed.lastKnownGoodMaxAge=45s >"$lkg_rendered"
assert_contains "$lkg_rendered" "HELM_POLICY_ON_INVALID_UPDATE"
assert_contains "$lkg_rendered" "value: \"deny\""
assert_contains "$lkg_rendered" "HELM_POLICY_LAST_KNOWN_GOOD_MAX_AGE"
assert_contains "$lkg_rendered" "value: \"45s\""

if helm_runner template "$RELEASE" "$CHART" \
    --namespace "$NAMESPACE" \
    --set helm.policy.failClosed.onInvalidUpdate=allow >"$RENDER_DIR/rendered-invalid-lkg.yaml" 2>&1; then
    echo "::error::unsupported LKG allow mode unexpectedly rendered"
    exit 1
fi

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

emergency_stop_replay_direct_rendered="$RENDER_DIR/rendered-emergency-stop-replay-direct.yaml"
helm_runner template "$RELEASE" "$CHART" \
    --namespace "$NAMESPACE" \
    --set helm.emergencyStop.enabled=true \
    --set helm.emergencyStop.audience=kernel-qa \
    --set helm.emergencyStop.commandPublicKeys=cp-stop-qa=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
    --set-literal helm.emergencyStop.commandReplayKeyring="$REPLAY_KEYRING" >"$emergency_stop_replay_direct_rendered"
assert_contains "$emergency_stop_replay_direct_rendered" "HELM_EMERGENCY_STOP_COMMAND_REPLAY_KEYRING"
assert_contains "$emergency_stop_replay_direct_rendered" "emergency-stop-fence-command-replay-keyring.v1"
assert_contains "$emergency_stop_replay_direct_rendered" "cp-stop-before-rotation"

emergency_stop_replay_secret_rendered="$RENDER_DIR/rendered-emergency-stop-replay-secret.yaml"
helm_runner template "$RELEASE" "$CHART" \
    --namespace "$NAMESPACE" \
    --set helm.emergencyStop.enabled=true \
    --set helm.emergencyStop.audience=kernel-qa \
    --set helm.emergencyStop.existingSecret=helm-emergency-stop-authority \
    --set helm.emergencyStop.commandReplayKeyringSecretKey=HELM_EMERGENCY_STOP_COMMAND_REPLAY_KEYRING >"$emergency_stop_replay_secret_rendered"
assert_contains "$emergency_stop_replay_secret_rendered" "HELM_EMERGENCY_STOP_COMMAND_REPLAY_KEYRING"
assert_contains "$emergency_stop_replay_secret_rendered" "name: helm-emergency-stop-authority"
assert_contains "$emergency_stop_replay_secret_rendered" "key: HELM_EMERGENCY_STOP_COMMAND_REPLAY_KEYRING"

emergency_stop_replay_ambiguous_log="$RENDER_DIR/emergency-stop-replay-ambiguous.log"
if helm_runner template "$RELEASE" "$CHART" \
    --namespace "$NAMESPACE" \
    --set helm.emergencyStop.enabled=true \
    --set helm.emergencyStop.audience=kernel-qa \
    --set helm.emergencyStop.existingSecret=helm-emergency-stop-authority \
    --set helm.emergencyStop.commandReplayKeyringSecretKey=HELM_EMERGENCY_STOP_COMMAND_REPLAY_KEYRING \
    --set-literal helm.emergencyStop.commandReplayKeyring="$REPLAY_KEYRING" >"$RENDER_DIR/emergency-stop-replay-ambiguous.yaml" 2>"$emergency_stop_replay_ambiguous_log"; then
    echo "::error::emergency-stop render with direct and secret replay keyrings unexpectedly succeeded"
    exit 1
fi
assert_contains "$emergency_stop_replay_ambiguous_log" "commandReplayKeyring and commandReplayKeyringSecretKey are mutually exclusive"

emergency_stop_missing_authority_log="$RENDER_DIR/emergency-stop-missing-authority.log"
if helm_runner template "$RELEASE" "$CHART" \
    --namespace "$NAMESPACE" \
    --set helm.emergencyStop.enabled=true \
    --set helm.emergencyStop.audience=kernel-qa >"$RENDER_DIR/emergency-stop-missing-authority.yaml" 2>"$emergency_stop_missing_authority_log"; then
    echo "::error::emergency-stop render without command authority unexpectedly succeeded"
    exit 1
fi
assert_contains "$emergency_stop_missing_authority_log" "helm.emergencyStop.commandPublicKeys"

openclaw_rendered="$RENDER_DIR/rendered-openclaw.yaml"
helm_runner template "$RELEASE" "$CHART" \
    --namespace "$NAMESPACE" \
    --set launchpadApps.openclaw.enabled=true >"$openclaw_rendered"
assert_contains "$openclaw_rendered" 'openclaw models set "$OPENCLAW_MODEL"'
assert_contains "$openclaw_rendered" 'value: "openrouter/openai/gpt-4o-mini"'
assert_contains "$openclaw_rendered" "OPENROUTER_API_KEY"
assert_not_contains "$openclaw_rendered" "OPENAI_API_KEY"
assert_not_contains "$openclaw_rendered" "OPENAI_BASE_URL"

openclaw_provider_fail_log="$RENDER_DIR/openclaw-invalid-provider.log"
if helm_runner template "$RELEASE" "$CHART" \
    --namespace "$NAMESPACE" \
    --set launchpadApps.openclaw.enabled=true \
    --set-string launchpadApps.openclaw.model=openai/gpt-5.5 >"$RENDER_DIR/openclaw-invalid-provider.yaml" 2>"$openclaw_provider_fail_log"; then
    echo "::error::OpenClaw render with a provider outside the OpenRouter egress boundary unexpectedly succeeded"
    exit 1
fi
assert_contains "$openclaw_provider_fail_log" "launchpadApps.openclaw.model"

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
# Match any argument order or added redirection, not one exact spelling. Uses a
# literal space class rather than \b, which is not portable in POSIX ERE.
if grep -Eq 'kube_helm[[:space:]]+test[[:space:]][^#]*--logs' "$ROOT/scripts/ci/launchpad_k8s_smoke.sh"; then
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
if production_controlplane_helm_runner template "$RELEASE" "$CHART" \
    --namespace "$NAMESPACE" \
    --set helm.production=true >"$RENDER_DIR/production-missing-key.yaml" 2>"$fail_log"; then
    echo "::error::production render without signing key unexpectedly succeeded"
    exit 1
fi
assert_contains "$fail_log" "requires helm.signing.key"

image_digest_fail_log="$RENDER_DIR/production-missing-image-digest.log"
if helm_runner template "$RELEASE" "$CHART" \
    --namespace "$NAMESPACE" \
    --values "$PRODUCTION_NETWORK_POLICY_VALUES" \
    --set helm.production=true \
    --set helm.signing.key="$SIGNING_KEY" \
    --set helm.auth.adminAPIKey="$ADMIN_KEY" \
    --set helm.auth.serviceAPIKey="$SERVICE_KEY" \
    --set helm.auth.tenantID="$TENANT_ID" \
    --set helm.auth.principalID="$AGENT_ID" \
    --set helm.policy.source.kind=controlplane \
    --set helm.policy.source.controlplane.url=https://helm-controlplane.example.internal \
    --set helm.policy.source.controlplane.tls.existingSecret=helm-policy-controlplane-ca \
    --set helm.policy.signature.required=true \
    --set helm.policy.signature.publicKey="$TRUST_PUBLIC_KEY" >"$RENDER_DIR/production-missing-image-digest.yaml" 2>"$image_digest_fail_log"; then
    echo "::error::production render without an immutable Kernel image digest unexpectedly succeeded"
    exit 1
fi
assert_contains "$image_digest_fail_log" "requires image.digest pinned by immutable sha256 digest"

image_digest_invalid_log="$RENDER_DIR/invalid-image-digest.log"
if helm_runner template "$RELEASE" "$CHART" \
    --namespace "$NAMESPACE" \
    --set image.digest=sha256:not-a-digest >"$RENDER_DIR/invalid-image-digest.yaml" 2>"$image_digest_invalid_log"; then
    echo "::error::render with a malformed Kernel image digest unexpectedly succeeded"
    exit 1
fi
assert_contains "$image_digest_invalid_log" "image.digest"

network_policy_disabled_log="$RENDER_DIR/production-network-policy-disabled.log"
if helm_runner template "$RELEASE" "$CHART" \
    --namespace "$NAMESPACE" \
    --set helm.production=true \
    --set helm.signing.key="$SIGNING_KEY" \
    --set helm.auth.adminAPIKey="$ADMIN_KEY" \
    --set helm.auth.serviceAPIKey="$SERVICE_KEY" \
    --set helm.auth.tenantID="$TENANT_ID" \
    --set helm.auth.principalID="$AGENT_ID" \
    --set helm.policy.source.kind=controlplane \
    --set helm.policy.source.controlplane.url=https://helm-controlplane.example.internal \
    --set helm.policy.source.controlplane.tls.existingSecret=helm-policy-controlplane-ca \
    --set helm.policy.signature.required=true \
    --set helm.policy.signature.publicKey="$TRUST_PUBLIC_KEY" \
    --set image.digest="$PRODUCTION_IMAGE_DIGEST" >"$RENDER_DIR/production-network-policy-disabled.yaml" 2>"$network_policy_disabled_log"; then
    echo "::error::production render without a kernel NetworkPolicy unexpectedly succeeded"
    exit 1
fi
assert_contains "$network_policy_disabled_log" "networkPolicy.enabled=true"

network_policy_wildcard_log="$RENDER_DIR/production-network-policy-wildcard.log"
if production_controlplane_helm_runner template "$RELEASE" "$CHART" \
    --namespace "$NAMESPACE" \
    --set helm.production=true \
    --set helm.signing.key="$SIGNING_KEY" \
    --set helm.auth.adminAPIKey="$ADMIN_KEY" \
    --set helm.auth.serviceAPIKey="$SERVICE_KEY" \
    --set-string 'networkPolicy.egress[1].to[0].ipBlock.cidr=0.0.0.0/0' >"$RENDER_DIR/production-network-policy-wildcard.yaml" 2>"$network_policy_wildcard_log"; then
    echo "::error::production render with wildcard kernel egress unexpectedly succeeded"
    exit 1
fi
assert_contains "$network_policy_wildcard_log" "exact /32 or /128 host CIDRs"

tenant_fail_log="$RENDER_DIR/production-missing-runtime-tenant.log"
if production_controlplane_helm_runner template "$RELEASE" "$CHART" \
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
if production_controlplane_helm_runner template "$RELEASE" "$CHART" \
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
if production_controlplane_helm_runner template "$RELEASE" "$CHART" \
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
if production_controlplane_helm_runner template "$RELEASE" "$CHART" \
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
if production_controlplane_helm_runner template "$RELEASE" "$CHART" \
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
production_controlplane_helm_runner template "$RELEASE" "$CHART" \
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

production_controlplane_helm_runner lint "$CHART" \
    --set helm.production=true \
    --set helm.signing.key="$SIGNING_KEY" \
    --set helm.auth.adminAPIKey="$ADMIN_KEY" \
    --set helm.auth.serviceAPIKey="$SERVICE_KEY" \
    --set helm.auth.tenantID="$TENANT_ID" \
    --set helm.auth.principalID="$AGENT_ID" \
    --set image.repository=ghcr.io/mindburn-labs/helm-ai-kernel \
    --set image.pullPolicy=IfNotPresent >/dev/null

rendered="$RENDER_DIR/rendered.yaml"
production_controlplane_helm_runner template "$RELEASE" "$CHART" \
    --namespace "$NAMESPACE" \
    --set helm.production=true \
    --set helm.signing.key="$SIGNING_KEY" \
    --set helm.auth.adminAPIKey="$ADMIN_KEY" \
    --set helm.auth.serviceAPIKey="$SERVICE_KEY" \
    --set helm.auth.tenantID="$TENANT_ID" \
    --set helm.auth.principalID="$AGENT_ID" \
    --set image.repository=ghcr.io/mindburn-labs/helm-ai-kernel \
    --set image.pullPolicy=IfNotPresent >"$rendered"

assert_contains "$rendered" "kind: Deployment"
assert_contains "$rendered" "strategy:"
assert_contains "$rendered" "type: Recreate"
assert_contains "$rendered" "image: \"ghcr.io/mindburn-labs/helm-ai-kernel@${PRODUCTION_IMAGE_DIGEST}\""
assert_contains "$rendered" "serve"
assert_contains "$rendered" "--policy"
assert_contains "$rendered" "/etc/helm-ai-kernel/policy/serve-policy.toml"
assert_contains "$rendered" "--data-dir"
assert_contains "$rendered" "/data"
assert_contains "$rendered" "HELM_PRODUCTION"
assert_contains "$rendered" "HELM_POLICY_SOURCE_KIND"
assert_contains "$rendered" "controlplane"
assert_contains "$rendered" "https://helm-controlplane.example.internal"
assert_contains "$rendered" "HELM_POLICY_TRUST_PUBLIC_KEY"
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
assert_contains "$rendered" "kind: NetworkPolicy"
assert_contains "$rendered" "kernel ingress and egress are allowlist-only"
assert_contains "$rendered" "app.kubernetes.io/name: svc-helm-control-plane"
assert_contains "$rendered" "cidr: 10.116.0.8/32"
assert_contains "$rendered" "port: 5432"

ephemeral_production_log="$RENDER_DIR/production-ephemeral-policy-state.log"
if production_controlplane_helm_runner template "$RELEASE" "$CHART" \
    --namespace "$NAMESPACE" \
    --set helm.production=true \
    --set helm.signing.key="$SIGNING_KEY" \
    --set helm.auth.adminAPIKey="$ADMIN_KEY" \
    --set helm.auth.serviceAPIKey="$SERVICE_KEY" \
    --set persistence.enabled=false >"$RENDER_DIR/production-ephemeral-policy-state.yaml" 2>"$ephemeral_production_log"; then
    echo "::error::production render without durable policy state unexpectedly succeeded"
    exit 1
fi
assert_contains "$ephemeral_production_log" "persistence.enabled=true"

multi_replica_production_log="$RENDER_DIR/production-multi-replica-policy-state.log"
if production_controlplane_helm_runner template "$RELEASE" "$CHART" \
    --namespace "$NAMESPACE" \
    --set helm.production=true \
    --set helm.signing.key="$SIGNING_KEY" \
    --set helm.auth.adminAPIKey="$ADMIN_KEY" \
    --set helm.auth.serviceAPIKey="$SERVICE_KEY" \
    --set replicaCount=2 >"$RENDER_DIR/production-multi-replica-policy-state.yaml" 2>"$multi_replica_production_log"; then
    echo "::error::production multi-writer policy state unexpectedly rendered"
    exit 1
fi
assert_contains "$multi_replica_production_log" "replicaCount=1"

mounted_file_production_log="$RENDER_DIR/production-mounted-file-policy.log"
if production_helm_runner template "$RELEASE" "$CHART" \
    --namespace "$NAMESPACE" \
    --set helm.production=true \
    --set helm.signing.key="$SIGNING_KEY" \
    --set helm.auth.adminAPIKey="$ADMIN_KEY" \
    --set helm.auth.serviceAPIKey="$SERVICE_KEY" \
    --set helm.policy.source.kind=mountedFile >"$RENDER_DIR/production-mounted-file-policy.yaml" 2>"$mounted_file_production_log"; then
    echo "::error::production mounted-file policy source unexpectedly rendered"
    exit 1
fi
assert_contains "$mounted_file_production_log" "source-owned monotonic publication epochs"

controlplane_fail_log="$RENDER_DIR/controlplane-missing-url.log"
if production_helm_runner template "$RELEASE" "$CHART" \
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
if production_helm_runner template "$RELEASE" "$CHART" \
    --namespace "$NAMESPACE" \
    --set helm.production=true \
    --set helm.signing.key="$SIGNING_KEY" \
    --set helm.auth.adminAPIKey="$ADMIN_KEY" \
    --set helm.auth.serviceAPIKey="$SERVICE_KEY" \
    --set helm.policy.source.kind=controlplane \
    --set helm.policy.source.controlplane.url=https://helm-controlplane.example.internal \
    --set helm.policy.source.controlplane.tls.existingSecret=helm-policy-controlplane-ca >"$RENDER_DIR/controlplane-missing-signature.yaml" 2>"$controlplane_unsigned_log"; then
    echo "::error::production controlplane render without required policy signatures unexpectedly succeeded"
    exit 1
fi
assert_contains "$controlplane_unsigned_log" "helm.policy.signature.required=true"

controlplane_ca_log="$RENDER_DIR/controlplane-missing-ca.log"
if production_helm_runner template "$RELEASE" "$CHART" \
    --namespace "$NAMESPACE" \
    --set helm.production=true \
    --set helm.signing.key="$SIGNING_KEY" \
    --set helm.auth.adminAPIKey="$ADMIN_KEY" \
    --set helm.auth.serviceAPIKey="$SERVICE_KEY" \
    --set helm.policy.source.kind=controlplane \
    --set helm.policy.source.controlplane.url=https://helm-controlplane.example.internal \
    --set helm.policy.signature.required=true \
    --set helm.policy.signature.publicKey="$TRUST_PUBLIC_KEY" >"$RENDER_DIR/controlplane-missing-ca.yaml" 2>"$controlplane_ca_log"; then
    echo "::error::production controlplane render without an exclusive TLS CA unexpectedly succeeded"
    exit 1
fi
assert_contains "$controlplane_ca_log" "helm.policy.source.controlplane.tls.existingSecret"

controlplane_loopback_rendered="$RENDER_DIR/rendered-controlplane-loopback.yaml"
production_helm_runner template "$RELEASE" "$CHART" \
    --namespace "$NAMESPACE" \
    --set helm.production=true \
    --set helm.signing.key="$SIGNING_KEY" \
    --set helm.auth.adminAPIKey="$ADMIN_KEY" \
    --set helm.auth.serviceAPIKey="$SERVICE_KEY" \
    --set helm.policy.source.kind=controlplane \
    --set-string helm.policy.source.controlplane.url=http://127.0.0.1:18080 \
    --set helm.policy.signature.required=true \
    --set helm.policy.signature.publicKey="$TRUST_PUBLIC_KEY" >"$controlplane_loopback_rendered"
assert_contains "$controlplane_loopback_rendered" "http://127.0.0.1:18080"
assert_not_contains "$controlplane_loopback_rendered" "HELM_POLICY_CONTROLPLANE_CA_FILE"

controlplane_rendered="$RENDER_DIR/rendered-controlplane.yaml"
production_helm_runner template "$RELEASE" "$CHART" \
    --namespace "$NAMESPACE" \
    --set helm.production=true \
    --set helm.signing.key="$SIGNING_KEY" \
    --set helm.auth.adminAPIKey="$ADMIN_KEY" \
    --set helm.auth.serviceAPIKey="$SERVICE_KEY" \
    --set helm.policy.source.kind=controlplane \
    --set helm.policy.source.controlplane.url=https://helm-controlplane.example.internal \
    --set helm.policy.source.controlplane.tls.existingSecret=helm-policy-controlplane-ca \
    --set helm.policy.signature.required=true \
    --set helm.policy.signature.publicKey="$TRUST_PUBLIC_KEY" \
    --set image.repository=ghcr.io/mindburn-labs/helm-ai-kernel \
    --set image.tag=local \
    --set image.pullPolicy=IfNotPresent >"$controlplane_rendered"

assert_contains "$controlplane_rendered" "HELM_POLICY_SOURCE_KIND"
assert_contains "$controlplane_rendered" "controlplane"
assert_contains "$controlplane_rendered" "HELM_POLICY_CONTROLPLANE_URL"
assert_contains "$controlplane_rendered" "https://helm-controlplane.example.internal"
assert_contains "$controlplane_rendered" "HELM_POLICY_CONTROLPLANE_CA_FILE"
assert_contains "$controlplane_rendered" "/var/run/secrets/helm-policy-controlplane-tls/ca.pem"
assert_contains "$controlplane_rendered" "name: policy-controlplane-tls"
assert_contains "$controlplane_rendered" "secretName: helm-policy-controlplane-ca"
assert_contains "$controlplane_rendered" "HELM_POLICY_CONTROLPLANE_AUTH_MODE"
assert_contains "$controlplane_rendered" "serviceAccountJWT"
assert_contains "$controlplane_rendered" "HELM_POLICY_SERVICE_ACCOUNT_TOKEN_FILE"
assert_contains "$controlplane_rendered" "/var/run/secrets/helm-policy/token"
assert_contains "$controlplane_rendered" "name: policy-service-account-token"
assert_contains "$controlplane_rendered" "audience: \"helm-control-plane\""
assert_contains "$controlplane_rendered" "expirationSeconds: 600"
assert_contains "$controlplane_rendered" "automountServiceAccountToken: false"
assert_not_contains "$controlplane_rendered" "HELM_POLICY_BEARER_TOKEN"
assert_contains "$controlplane_rendered" "HELM_POLICY_SIGNATURE_REQUIRED"
assert_contains "$controlplane_rendered" "HELM_POLICY_TRUST_PUBLIC_KEY"
assert_not_contains "$controlplane_rendered" "configmap-reload"
assert_not_contains "$controlplane_rendered" "kind: CustomResourceDefinition"
assert_not_contains "$controlplane_rendered" "policy-reader"

controlplane_bearer_rendered="$RENDER_DIR/rendered-controlplane-bearer.yaml"
production_helm_runner template "$RELEASE" "$CHART" \
    --namespace "$NAMESPACE" \
    --set helm.production=true \
    --set helm.signing.key="$SIGNING_KEY" \
    --set helm.auth.adminAPIKey="$ADMIN_KEY" \
    --set helm.auth.serviceAPIKey="$SERVICE_KEY" \
    --set helm.policy.source.kind=controlplane \
    --set helm.policy.source.controlplane.url=https://helm-controlplane.example.internal \
    --set helm.policy.source.controlplane.tls.existingSecret=helm-policy-controlplane-ca \
    --set helm.policy.source.controlplane.auth.mode=bearerToken \
    --set helm.policy.source.controlplane.auth.existingSecret=policy-reader \
    --set helm.policy.signature.required=true \
    --set helm.policy.signature.publicKey="$TRUST_PUBLIC_KEY" \
    --set image.repository=ghcr.io/mindburn-labs/helm-ai-kernel \
    --set image.tag=local \
    --set image.pullPolicy=IfNotPresent >"$controlplane_bearer_rendered"

assert_contains "$controlplane_bearer_rendered" "HELM_POLICY_BEARER_TOKEN"
assert_contains "$controlplane_bearer_rendered" "name: policy-reader"
assert_not_contains "$controlplane_bearer_rendered" "policy-service-account-token"
assert_not_contains "$controlplane_bearer_rendered" "HELM_POLICY_SERVICE_ACCOUNT_TOKEN_FILE"

crd_rendered="$RENDER_DIR/rendered-crd.yaml"
production_helm_runner template "$RELEASE" "$CHART" \
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
