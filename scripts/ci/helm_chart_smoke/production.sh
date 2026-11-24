# shellcheck shell=bash

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
assert_schema_path "$image_digest_invalid_log" "image.digest"

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
assert_schema_path "$tenant_fail_log" "helm.auth.tenantID"

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
assert_schema_path "$principal_fail_log" "helm.auth.principalID"

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
