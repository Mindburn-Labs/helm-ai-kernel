# shellcheck shell=bash

# Native API-listener TLS and the organization-runtime key (HELM-786).
# The default render from runtime.sh must omit these settings.
assert_not_contains "$default_rendered" "HELM_TLS_CERT_FILE"
assert_not_contains "$default_rendered" "name: api-tls"
assert_not_contains "$default_rendered" "HELM_ORGANIZATION_RUNTIME_API_KEY"

tls_rendered="$RENDER_DIR/rendered-api-tls.yaml"
helm_runner template "$RELEASE" "$CHART" \
    --namespace "$NAMESPACE" \
    --set helm.tls.existingSecret=helm-kernel-tls >"$tls_rendered"
assert_contains "$tls_rendered" 'value: "/var/run/secrets/helm-tls/tls.crt"'
assert_contains "$tls_rendered" 'value: "/var/run/secrets/helm-tls/tls.key"'
assert_contains "$tls_rendered" "secretName: helm-kernel-tls"
assert_contains "$tls_rendered" "mountPath: /var/run/secrets/helm-tls"
assert_not_contains "$tls_rendered" "HELM_TLS_CLIENT_AUTH"
assert_not_contains "$tls_rendered" "path: ca.crt"
# The probes hit the plain-HTTP health listener, so TLS leaves them alone.
assert_not_contains "$tls_rendered" "scheme: HTTPS"
assert_contains "$tls_rendered" "port: health"

mtls_rendered="$RENDER_DIR/rendered-api-mtls.yaml"
helm_runner template "$RELEASE" "$CHART" \
    --namespace "$NAMESPACE" \
    --set helm.tls.existingSecret=helm-kernel-tls \
    --set helm.tls.clientAuth=require >"$mtls_rendered"
assert_contains "$mtls_rendered" 'value: "/var/run/secrets/helm-tls/ca.crt"'
assert_contains "$mtls_rendered" "HELM_TLS_CLIENT_AUTH"
assert_contains "$mtls_rendered" 'value: "require"'
assert_contains "$mtls_rendered" "path: ca.crt"

mtls_without_secret_log="$RENDER_DIR/api-mtls-without-secret.log"
if helm_runner template "$RELEASE" "$CHART" \
    --namespace "$NAMESPACE" \
    --set helm.tls.clientAuth=require >"$RENDER_DIR/api-mtls-without-secret.yaml" 2>"$mtls_without_secret_log"; then
    echo "::error::client auth without a TLS Secret unexpectedly rendered"
    exit 1
fi
assert_contains "$mtls_without_secret_log" "helm.tls.clientAuth requires helm.tls.existingSecret"

tls_reloader_log="$RENDER_DIR/api-tls-with-reloader.log"
if helm_runner template "$RELEASE" "$CHART" \
    --namespace "$NAMESPACE" \
    --set helm.tls.existingSecret=helm-kernel-tls \
    --set helm.policy.reloadHints.configReloaderSidecar.enabled=true >"$RENDER_DIR/api-tls-with-reloader.yaml" 2>"$tls_reloader_log"; then
    echo "::error::TLS with the plain-HTTP config-reloader sidecar unexpectedly rendered"
    exit 1
fi
assert_contains "$tls_reloader_log" "cannot be combined with the config-reloader sidecar"

# A well-formed placeholder: 64 lowercase hex characters, built rather than
# written out so the secret scanner does not read it as a key.
activation_key="$(printf 'ab%.0s' $(seq 1 32))"
org_runtime_rendered="$RENDER_DIR/rendered-org-runtime-key.yaml"
helm_runner template "$RELEASE" "$CHART" \
    --namespace "$NAMESPACE" \
    --set helm.auth.existingSecret=helm-kernel-auth \
    --set helm.auth.controlPlaneActivationPublicKey="$activation_key" >"$org_runtime_rendered"
assert_contains "$org_runtime_rendered" "HELM_ORGANIZATION_RUNTIME_API_KEY"
assert_contains "$org_runtime_rendered" "key: HELM_ORGANIZATION_RUNTIME_API_KEY"
assert_contains "$org_runtime_rendered" "HELM_CONTROL_PLANE_ACTIVATION_PUBLIC_KEY"
assert_contains "$org_runtime_rendered" "$activation_key"

# Without the activation public key the organization-runtime key is not wired:
# the Kernel refuses one without the other (degraded service init).
org_runtime_no_activation="$RENDER_DIR/rendered-org-runtime-no-activation.yaml"
helm_runner template "$RELEASE" "$CHART" \
    --namespace "$NAMESPACE" \
    --set helm.auth.existingSecret=helm-kernel-auth >"$org_runtime_no_activation"
assert_not_contains "$org_runtime_no_activation" "HELM_ORGANIZATION_RUNTIME_API_KEY"
assert_not_contains "$org_runtime_no_activation" "HELM_CONTROL_PLANE_ACTIVATION_PUBLIC_KEY"

activation_without_key_log="$RENDER_DIR/activation-without-org-runtime-key.log"
if helm_runner template "$RELEASE" "$CHART" \
    --namespace "$NAMESPACE" \
    --set helm.auth.controlPlaneActivationPublicKey="$activation_key" >"$RENDER_DIR/activation-without-org-runtime-key.yaml" 2>"$activation_without_key_log"; then
    echo "::error::the activation public key without the organization-runtime key unexpectedly rendered"
    exit 1
fi
assert_contains "$activation_without_key_log" "requires the organization-runtime key"

activation_bad_log="$RENDER_DIR/activation-bad-key.log"
if helm_runner template "$RELEASE" "$CHART" \
    --namespace "$NAMESPACE" \
    --set helm.auth.existingSecret=helm-kernel-auth \
    --set helm.auth.controlPlaneActivationPublicKey=NOTHEX >"$RENDER_DIR/activation-bad-key.yaml" 2>"$activation_bad_log"; then
    echo "::error::a malformed activation public key unexpectedly rendered"
    exit 1
fi

org_runtime_off_rendered="$RENDER_DIR/rendered-org-runtime-key-off.yaml"
helm_runner template "$RELEASE" "$CHART" \
    --namespace "$NAMESPACE" \
    --set helm.auth.existingSecret=helm-kernel-auth \
    --set helm.auth.organizationRuntimeAPIKeySecretKey= >"$org_runtime_off_rendered"
assert_not_contains "$org_runtime_off_rendered" "HELM_ORGANIZATION_RUNTIME_API_KEY"
