# shellcheck shell=bash

# The API authentication and gateway scenarios also inspect this render.
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
python3 scripts/ci/test_authority_state_init.py "$default_rendered"
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
assert_schema_path "$runtime_init_fail_log" "runtimeInit.image"

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
assert_schema_path "$emergency_stop_missing_authority_log" "helm.emergencyStop.commandPublicKeys"
