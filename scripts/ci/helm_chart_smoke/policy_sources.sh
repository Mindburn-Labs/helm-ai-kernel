# shellcheck shell=bash

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
for controlplane_loopback_url in \
    "http://127.42.0.9:18080" \
    "HTTP://LOCALHOST:18080" \
    "http://[::1]:18080" \
    "http://[0:0:0:0:0:0:0:1]:18080" \
    "http://[::ffff:127.0.0.1]:18080" \
    "http://[0:0:0:0:0:ffff:7f00:1]:18080"; do
    production_helm_runner template "$RELEASE" "$CHART" \
        --namespace "$NAMESPACE" \
        --set helm.production=true \
        --set helm.signing.key="$SIGNING_KEY" \
        --set helm.auth.adminAPIKey="$ADMIN_KEY" \
        --set helm.auth.serviceAPIKey="$SERVICE_KEY" \
        --set helm.policy.source.kind=controlplane \
        --set-string "helm.policy.source.controlplane.url=$controlplane_loopback_url" \
        --set helm.policy.signature.required=true \
        --set helm.policy.signature.publicKey="$TRUST_PUBLIC_KEY" >"$controlplane_loopback_rendered"
    assert_contains "$controlplane_loopback_rendered" "$controlplane_loopback_url"
    assert_not_contains "$controlplane_loopback_rendered" "HELM_POLICY_CONTROLPLANE_CA_FILE"
done

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
