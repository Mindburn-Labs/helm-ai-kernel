# shellcheck shell=bash
# quantum_posture: checks the chart wiring for the gateway's Ed25519 receipt seed.

# Effect gateway (helm-gateway, HELM-789). Off by default: the default render
# carries no gateway object. Enabled, every object renders, each required value
# is enforced at render time, and the GitHub App Secret reaches only the
# gateway Pod.
assert_not_contains "$default_rendered" "helm-gateway"
assert_not_contains "$default_rendered" "effect-gateway"
assert_not_contains "$default_rendered" "HELM_GATEWAY_"

GATEWAY_NAME="${RELEASE}-helm-ai-kernel-gateway"
GATEWAY_ARGS=(
    --set gateway.enabled=true
    --set gateway.tls.existingSecret=gw-tls
    --set gateway.controlPlaneIdentity.jwksURL=https://cp.example.internal/.well-known/jwks.json
    --set gateway.controlPlaneIdentity.issuer=https://cp.example.internal
    --set gateway.controlPlaneIdentity.audience=helm-gateway:smoke
    --set gateway.controlPlaneIdentity.actor=spiffe://helm/control-plane
    --set gateway.database.existingSecret=gw-db
    --set gateway.receipts.existingSecret=gw-receipts
    --set gateway.networkPolicy.controlPlane.namespaceSelector.matchLabels.helm-cp=enabled
    --set gateway.networkPolicy.database.to[0].ipBlock.cidr=10.20.30.40/32
)

# gateway_args_without KEY sets GATEWAY_ARGS_WITHOUT to GATEWAY_ARGS (--set
# VALUE pairs) minus the pair whose value starts with KEY.
gateway_args_without() {
    local i
    GATEWAY_ARGS_WITHOUT=()
    for ((i = 0; i < ${#GATEWAY_ARGS[@]}; i += 2)); do
        if [[ "${GATEWAY_ARGS[i + 1]}" != "$1"* ]]; then
            GATEWAY_ARGS_WITHOUT+=("${GATEWAY_ARGS[i]}" "${GATEWAY_ARGS[i + 1]}")
        fi
    done
}

# docs_containing FILE PATTERN prints the "# Source:" template of every
# rendered document that contains PATTERN.
docs_containing() {
    awk -v pattern="$2" '
        /^---/ { if (hit) print source; hit = 0; source = ""; next }
        /^# Source: / { source = $3 }
        index($0, pattern) { hit = 1 }
        END { if (hit) print source }
    ' "$1"
}

# Installations files live in the repository, not RENDER_DIR, because the
# containerized Helm runner sees only the repository (-v "$ROOT:/work").
# installations.json has the shape helm-gateway's custody reads (HELM-751 s3):
# exactly tenant_id, owner, installation_id and repositories.
GATEWAY_TESTDATA="scripts/ci/testdata/helm-gateway"
gateway_rendered="$RENDER_DIR/rendered-gateway.yaml"
helm_runner template "$RELEASE" "$CHART" \
    --namespace "$NAMESPACE" \
    "${GATEWAY_ARGS[@]}" \
    --set gateway.database.bootstrap.enabled=true \
    --set gateway.database.bootstrap.existingSecret=gw-db-admin \
    --set gateway.github.existingSecret=gw-github-app \
    --set-file gateway.github.installationsFile="$GATEWAY_TESTDATA/installations.json" \
    --set gateway.github.apiURL=https://ghe.example.internal/api/v3 \
    --set-file gateway.activity.sourcesFile="$GATEWAY_TESTDATA/activity-sources.json" \
    --set gateway.activity.pollInterval=45s \
    --set gateway.activity.webhookSecretKey=activity-secret \
    --set gateway.dispatchTimeout=90s \
    --set gateway.controlPlaneIdentity.caBundleConfigMap=cp-jwks-ca >"$gateway_rendered"
assert_contains "$gateway_rendered" "name: HELM_GATEWAY_GITHUB_API_URL"
assert_contains "$gateway_rendered" 'value: "https://ghe.example.internal/api/v3"'
assert_contains "$gateway_rendered" "name: HELM_GATEWAY_DISPATCH_TIMEOUT"
assert_contains "$gateway_rendered" "name: HELM_GATEWAY_ACTIVITY_SOURCES_FILE"
assert_contains "$gateway_rendered" 'value: "45s"'
assert_contains "$gateway_rendered" "path: activity-webhook-secret"
assert_contains "$gateway_rendered" 'value: "90s"'
assert_not_contains "$gateway_rendered" "name: HELM_GATEWAY_OWNER_ASSERTION_REQUIRED"
assert_not_contains "$gateway_rendered" "name: HELM_GATEWAY_OWNER_ORIGINS"
gateway_owner_rendered="$RENDER_DIR/rendered-gateway-owner.yaml"
helm_runner template "$RELEASE" "$CHART" --namespace "$NAMESPACE" "${GATEWAY_ARGS[@]}" \
    --set gateway.ownerAssertionRequired=true \
    --set-string 'gateway.ownerOrigins[0]=https://console.helm.example' \
    --set-string 'gateway.ownerOrigins[1]=http://localhost:5173' >"$gateway_owner_rendered"
assert_contains "$gateway_owner_rendered" "name: HELM_GATEWAY_OWNER_ASSERTION_REQUIRED"
assert_contains "$gateway_owner_rendered" "name: HELM_GATEWAY_OWNER_ORIGINS"
assert_contains "$gateway_owner_rendered" 'value: "https://console.helm.example,http://localhost:5173"'
assert_contains "$gateway_rendered" '"installation_id\":1,\"repositories\":[\"example/repo\"]'
# Secret file modes (s3a review L2): the GitHub App Secret, the TLS key and
# the bootstrap password are mounted 0400 (defaultMode 256). The Pod's
# fsGroup 65534 is what lets the non-root user read them: kubelet adds group
# read for the fsGroup.
for secret_volume in github-app gateway-tls bootstrap-password gateway-receipts; do
    volume_mode="$(awk -v name="- name: ${secret_volume}" '
        index($0, name) && $0 ~ ("name: " v "$") { hit = NR }
        hit && NR > hit && NR <= hit + 4 && /defaultMode:/ { print $2; exit }
    ' v="$secret_volume" "$gateway_rendered")"
    if [ "$volume_mode" != "256" ]; then
        echo "::error::gateway Secret volume ${secret_volume} has defaultMode '${volume_mode}', want 256 (0400)"
        exit 1
    fi
done
assert_contains "$gateway_rendered" "fsGroup: 65534"
# Every object: Deployment, Service, ServiceAccount, NetworkPolicy, the
# installations ConfigMap and the migrate hook Job.
assert_contains "$gateway_rendered" "# Source: helm-ai-kernel/templates/gateway-deployment.yaml"
assert_contains "$gateway_rendered" "# Source: helm-ai-kernel/templates/gateway-service.yaml"
assert_contains "$gateway_rendered" "# Source: helm-ai-kernel/templates/gateway-serviceaccount.yaml"
assert_contains "$gateway_rendered" "# Source: helm-ai-kernel/templates/gateway-networkpolicy.yaml"
assert_contains "$gateway_rendered" "# Source: helm-ai-kernel/templates/gateway-configmap.yaml"
assert_contains "$gateway_rendered" "# Source: helm-ai-kernel/templates/gateway-migrate-job.yaml"
assert_contains "$gateway_rendered" "name: ${GATEWAY_NAME}"
assert_contains "$gateway_rendered" "name: ${GATEWAY_NAME}-migrate"
assert_contains "$gateway_rendered" "serviceAccountName: ${GATEWAY_NAME}"
assert_contains "$gateway_rendered" "kind: NetworkPolicy"
# Same image and tag as the kernel; the gateway binary by command.
assert_contains "$gateway_rendered" 'command: ["/usr/local/bin/helm-gateway"]'
assert_contains "$gateway_rendered" 'command: ["/usr/local/bin/helm-gateway", "migrate"]'
assert_equals_count() {
    local file="$1" pattern="$2" want="$3" got
    got="$(grep -cF -- "$pattern" "$file" || true)"
    if [ "$got" != "$want" ]; then
        echo "::error::expected $want occurrences of '$pattern', found $got"
        exit 1
    fi
}
# Kernel Deployment, gateway Deployment, and the scram and migrate init
# containers.
assert_equals_count "$gateway_rendered" 'image: "ghcr.io/mindburn-labs/helm-ai-kernel:v' 4
# The gateway Pod: TLS with client auth, probes on the health port, identity.
assert_contains "$gateway_rendered" 'value: "/var/run/secrets/helm-gateway-tls/tls.crt"'
assert_contains "$gateway_rendered" 'value: "/var/run/secrets/helm-gateway-tls/ca.crt"'
assert_contains "$gateway_rendered" 'secretName: "gw-tls"'
assert_contains "$gateway_rendered" "path: /readyz"
assert_contains "$gateway_rendered" "path: /healthz"
assert_contains "$gateway_rendered" "containerPort: 8443"
assert_contains "$gateway_rendered" "targetPort: https"
assert_contains "$gateway_rendered" 'value: "helm-gateway:smoke"'
assert_contains "$gateway_rendered" "HELM_CP_IDENTITY_OUTBOUND_CA_BUNDLE_FILE"
assert_contains "$gateway_rendered" "name: HELM_GATEWAY_DATABASE_URL"
assert_contains "$gateway_rendered" 'name: "gw-db"'
assert_not_contains "$gateway_rendered" "--dev-insecure-listen"
# Its ServiceAccount and Pod carry no API token (kernel default render: 1;
# gateway: ServiceAccount, Pod and migrate Job).
assert_equals_count "$gateway_rendered" "automountServiceAccountToken: false" 4
# NetworkPolicy: ingress to 8443 from the Control Plane selector only, and to
# the health port 8081 from anywhere (kubelet probes); egress to DNS, the
# database peer and TCP 443. The ingress block is compared whole.
gateway_ingress="$(helm_runner template "$RELEASE" "$CHART" --namespace "$NAMESPACE" "${GATEWAY_ARGS[@]}" \
    --show-only templates/gateway-networkpolicy.yaml | sed -n '/^  ingress:$/,/^  egress:$/p')"
gateway_ingress_want='  ingress:
    - from:
        - namespaceSelector:
            matchLabels:
              helm-cp: enabled
      ports:
        - protocol: TCP
          port: 8443
    - ports:
        - protocol: TCP
          port: 8081
  egress:'
if [ "$gateway_ingress" != "$gateway_ingress_want" ]; then
    echo "::error::gateway NetworkPolicy ingress differs from: API port from the Control Plane only, health port open"
    printf '%s\n' "$gateway_ingress"
    exit 1
fi
assert_contains "$gateway_rendered" "helm-cp: enabled"
assert_contains "$gateway_rendered" "cidr: 10.20.30.40/32"
assert_contains "$gateway_rendered" "k8s-app: kube-dns"
assert_contains "$gateway_rendered" "port: 443"
# The migrate hook: roles as the administrator, migrate and grants as the owner.
assert_contains "$gateway_rendered" '"helm.sh/hook": pre-install,pre-upgrade'
assert_contains "$gateway_rendered" "- name: roles"
assert_contains "$gateway_rendered" "- name: grants"
assert_contains "$gateway_rendered" 'value: "-c role=helm_owner -c search_path=helm_gateway"'
assert_contains "$gateway_rendered" "CREATE ROLE %I NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOREPLICATION"
assert_contains "$gateway_rendered" "has no helm_gateway grant rule"
assert_contains "$gateway_rendered" '"docker.io/library/postgres:16-alpine@sha256:'
# The runtime password reaches only the scram container, as a file, and
# leaves it as a SCRAM-SHA-256 verifier; no psql container gets the
# plaintext, and no container gets it as an environment variable.
assert_contains "$gateway_rendered" "- name: scram"
assert_contains "$gateway_rendered" "- scram-verifier"
assert_contains "$gateway_rendered" "- --password-file=/var/run/secrets/helm-gateway-bootstrap/runtime-password"
assert_contains "$gateway_rendered" 'key: "HELM_GATEWAY_ROLE_PASSWORD"'
assert_contains "$gateway_rendered" "helm_gateway_bootstrap.runtime_verifier"
assert_not_contains "$gateway_rendered" "name: HELM_GATEWAY_ROLE_PASSWORD"
assert_not_contains "$gateway_rendered" "runtime_password"
# The password volume: its definition and one mount, in the scram container.
assert_equals_count "$gateway_rendered" "name: bootstrap-password" 2
gateway_unmanaged_password_rendered="$RENDER_DIR/rendered-gateway-unmanaged-password.yaml"
helm_runner template "$RELEASE" "$CHART" --namespace "$NAMESPACE" "${GATEWAY_ARGS[@]}" \
    --set gateway.database.bootstrap.enabled=true \
    --set gateway.database.bootstrap.existingSecret=gw-db-admin \
    --set-string gateway.database.bootstrap.runtimePasswordKey= >"$gateway_unmanaged_password_rendered"
assert_contains "$gateway_unmanaged_password_rendered" "- name: roles"
assert_not_contains "$gateway_unmanaged_password_rendered" "- name: scram"
assert_not_contains "$gateway_unmanaged_password_rendered" "bootstrap-password"
# The GitHub App Secret and the installations file reach the gateway
# Deployment and no other object.
gateway_github_docs="$(docs_containing "$gateway_rendered" "gw-github-app")"
if [ "$gateway_github_docs" != "helm-ai-kernel/templates/gateway-deployment.yaml" ]; then
    echo "::error::the GitHub App Secret is referenced outside the gateway Deployment: ${gateway_github_docs}"
    exit 1
fi
assert_contains "$gateway_rendered" 'value: "/var/run/secrets/helm-gateway-github/private-key.pem"'
assert_contains "$gateway_rendered" 'value: "/etc/helm-gateway/github/installations.json"'
gateway_installations_docs="$(docs_containing "$gateway_rendered" "${GATEWAY_NAME}-github-installations" | sort | tr '\n' ' ')"
if [ "$gateway_installations_docs" != "helm-ai-kernel/templates/gateway-configmap.yaml helm-ai-kernel/templates/gateway-deployment.yaml " ]; then
    echo "::error::the installations ConfigMap is referenced outside the gateway Deployment: ${gateway_installations_docs}"
    exit 1
fi

# Signed decision receipts (helm-tracker#276). With existingSecret, the seed
# reaches the gateway Pod and no other object, and the chart creates no
# Secret of its own.
assert_contains "$gateway_rendered" "name: HELM_GATEWAY_RECEIPT_SIGNING_KEY_FILE"
assert_contains "$gateway_rendered" 'value: "/var/run/secrets/helm-gateway-receipts/seed"'
# The default key id is a prefix; helm-gateway appends the key's fingerprint,
# so a new seed gets a new key id.
assert_contains "$gateway_rendered" "name: HELM_GATEWAY_RECEIPT_KEY_ID_PREFIX"
assert_contains "$gateway_rendered" "value: \"helm-gateway:${NAMESPACE}:${GATEWAY_NAME}\""
if grep -qE '^ *- name: HELM_GATEWAY_RECEIPT_KEY_ID$' "$gateway_rendered"; then
    echo "::error::the default receipt key id is set verbatim instead of derived from the key"
    exit 1
fi
assert_contains "$gateway_rendered" 'secretName: "gw-receipts"'
assert_not_contains "$gateway_rendered" "# Source: helm-ai-kernel/templates/gateway-receipts-secret.yaml"
gateway_receipts_docs="$(docs_containing "$gateway_rendered" "gw-receipts")"
if [ "$gateway_receipts_docs" != "helm-ai-kernel/templates/gateway-deployment.yaml" ]; then
    echo "::error::the receipt signing Secret is referenced outside the gateway Deployment: ${gateway_receipts_docs}"
    exit 1
fi
gateway_receipts_key_rendered="$RENDER_DIR/rendered-gateway-receipts-key.yaml"
helm_runner template "$RELEASE" "$CHART" --namespace "$NAMESPACE" "${GATEWAY_ARGS[@]}" \
    --set gateway.receipts.existingSecretKey=ed25519-seed --set gateway.receipts.keyId=gateway-receipts-2 \
    --set gateway.receipts.autoSeed=true >"$gateway_receipts_key_rendered"
assert_contains "$gateway_receipts_key_rendered" 'key: "ed25519-seed"'
if ! grep -qE '^ *- name: HELM_GATEWAY_RECEIPT_KEY_ID$' "$gateway_receipts_key_rendered"; then
    echo "::error::gateway.receipts.keyId is not set verbatim as HELM_GATEWAY_RECEIPT_KEY_ID"
    exit 1
fi
assert_contains "$gateway_receipts_key_rendered" 'value: "gateway-receipts-2"'
assert_not_contains "$gateway_receipts_key_rendered" "HELM_GATEWAY_RECEIPT_KEY_ID_PREFIX"
# existingSecret wins over autoSeed: no generated Secret.
assert_not_contains "$gateway_receipts_key_rendered" "# Source: helm-ai-kernel/templates/gateway-receipts-secret.yaml"
# autoSeed: the chart creates the seed Secret once, kept across upgrades
# (lookup) and uninstalls, holding base64 of 32 random bytes; only the gateway
# Deployment mounts it. The release chart's default is false (the
# missing-existingSecret render below fails), and the charts-dev chart turns
# it on (scripts/release/prepare_dev_chart.py).
gateway_args_without gateway.receipts.existingSecret
gateway_autoseed_rendered="$RENDER_DIR/rendered-gateway-autoseed.yaml"
helm_runner template "$RELEASE" "$CHART" --namespace "$NAMESPACE" "${GATEWAY_ARGS_WITHOUT[@]}" \
    --set gateway.receipts.autoSeed=true >"$gateway_autoseed_rendered"
assert_contains "$gateway_autoseed_rendered" "# Source: helm-ai-kernel/templates/gateway-receipts-secret.yaml"
assert_contains "$gateway_autoseed_rendered" "name: ${GATEWAY_NAME}-receipts"
assert_contains "$gateway_autoseed_rendered" "helm.sh/resource-policy: keep"
assert_contains "$gateway_autoseed_rendered" "secretName: \"${GATEWAY_NAME}-receipts\""
assert_contains "$gateway_autoseed_rendered" 'value: "/var/run/secrets/helm-gateway-receipts/seed"'
gateway_autoseed_docs="$(docs_containing "$gateway_autoseed_rendered" "${GATEWAY_NAME}-receipts" | sort | tr '\n' ' ')"
if [ "$gateway_autoseed_docs" != "helm-ai-kernel/templates/gateway-deployment.yaml helm-ai-kernel/templates/gateway-receipts-secret.yaml " ]; then
    echo "::error::the generated receipt Secret is referenced outside the gateway Deployment: ${gateway_autoseed_docs}"
    exit 1
fi
python3 - "$gateway_autoseed_rendered" <<'PYSEED'
import base64
import sys

import yaml

secrets = [d for d in yaml.safe_load_all(open(sys.argv[1], encoding="utf-8"))
           if d and d.get("kind") == "Secret" and d["metadata"]["name"].endswith("-gateway-receipts")]
if len(secrets) != 1 or set(secrets[0]["data"]) != {"seed"}:
    sys.exit(f"::error::want one receipt Secret holding only seed, got {secrets}")
seed = base64.b64decode(base64.b64decode(secrets[0]["data"]["seed"], validate=True), validate=True)
if len(seed) != 32:
    sys.exit(f"::error::the generated receipt seed is {len(seed)} bytes, want 32")
PYSEED

# Without the bootstrap, migrate runs with the runtime DSN, or the migrate DSN.
gateway_plain_rendered="$RENDER_DIR/rendered-gateway-plain.yaml"
helm_runner template "$RELEASE" "$CHART" --namespace "$NAMESPACE" "${GATEWAY_ARGS[@]}" >"$gateway_plain_rendered"
assert_not_contains "$gateway_plain_rendered" "- name: roles"
assert_not_contains "$gateway_plain_rendered" "name: PGOPTIONS"
assert_not_contains "$gateway_plain_rendered" "HELM_GATEWAY_GITHUB_"
assert_equals_count "$gateway_plain_rendered" 'name: "gw-db"' 2
gateway_migrate_dsn_rendered="$RENDER_DIR/rendered-gateway-migrate-dsn.yaml"
helm_runner template "$RELEASE" "$CHART" --namespace "$NAMESPACE" "${GATEWAY_ARGS[@]}" \
    --set gateway.database.migrate.existingSecret=gw-db-owner >"$gateway_migrate_dsn_rendered"
assert_contains "$gateway_migrate_dsn_rendered" 'name: "gw-db-owner"'
assert_contains "$gateway_migrate_dsn_rendered" 'key: "HELM_GATEWAY_MIGRATE_DATABASE_URL"'

# Development: plain HTTP on the Pod loopback, never with production.
gateway_dev_rendered="$RENDER_DIR/rendered-gateway-dev.yaml"
gateway_args_without gateway.tls.existingSecret
helm_runner template "$RELEASE" "$CHART" --namespace "$NAMESPACE" \
    "${GATEWAY_ARGS_WITHOUT[@]}" \
    --set gateway.tls.devInsecureLoopback=true >"$gateway_dev_rendered"
assert_contains "$gateway_dev_rendered" "- --dev-insecure-listen=127.0.0.1:8443"
assert_not_contains "$gateway_dev_rendered" "HELM_TLS_CLIENT_AUTH"

# expect_gateway_render_failure NAME MESSAGE ARGS... renders with ARGS and
# requires the render to fail with MESSAGE.
expect_gateway_render_failure() {
    local name="$1" message="$2" log="$RENDER_DIR/gateway-$1.log"
    shift 2
    if helm_runner template "$RELEASE" "$CHART" --namespace "$NAMESPACE" "$@" >"$RENDER_DIR/gateway-$name.yaml" 2>"$log"; then
        echo "::error::gateway render ${name} unexpectedly succeeded"
        exit 1
    fi
    if [ "$message" = 'is required' ]; then
        if ! grep -qF 'is required' "$log" && ! grep -qF 'missing property' "$log"; then
            echo "::error::gateway render $name did not reject the missing property"
            cat "$log"
            exit 1
        fi
    elif [[ "$message" =~ ^[[:alnum:]_]+(\.[[:alnum:]_]+)+$ ]]; then
        assert_schema_path "$log" "$message"
    else
        assert_contains "$log" "$message"
    fi
}
for required in \
    "gateway.tls.existingSecret|requires gateway.tls.existingSecret" \
    "gateway.controlPlaneIdentity.jwksURL|requires gateway.controlPlaneIdentity.jwksURL" \
    "gateway.controlPlaneIdentity.issuer|requires gateway.controlPlaneIdentity.issuer" \
    "gateway.controlPlaneIdentity.audience|requires gateway.controlPlaneIdentity.audience" \
    "gateway.controlPlaneIdentity.actor|requires gateway.controlPlaneIdentity.actor" \
    "gateway.database.existingSecret|requires gateway.database.existingSecret" \
    "gateway.receipts.existingSecret|requires gateway.receipts.existingSecret" \
    "gateway.networkPolicy.controlPlane.namespaceSelector|requires gateway.networkPolicy.controlPlane.namespaceSelector or podSelector" \
    "gateway.networkPolicy.database.to|requires gateway.networkPolicy.database.to"; do
    key="${required%%|*}"
    gateway_args_without "$key"
    expect_gateway_render_failure "missing-${key##*.}" "${required#*|}" "${GATEWAY_ARGS_WITHOUT[@]}"
done
expect_gateway_render_failure bootstrap-without-secret "requires gateway.database.bootstrap.existingSecret" \
    "${GATEWAY_ARGS[@]}" --set gateway.database.bootstrap.enabled=true
expect_gateway_render_failure bootstrap-and-migrate-dsn "are mutually exclusive" \
    "${GATEWAY_ARGS[@]}" --set gateway.database.bootstrap.enabled=true \
    --set gateway.database.bootstrap.existingSecret=gw-db-admin --set gateway.database.migrate.existingSecret=gw-db-owner
expect_gateway_render_failure bootstrap-same-roles "ownerRole and runtimeRole must differ" \
    "${GATEWAY_ARGS[@]}" --set gateway.database.bootstrap.enabled=true \
    --set gateway.database.bootstrap.existingSecret=gw-db-admin --set gateway.database.bootstrap.ownerRole=helm_gateway
expect_gateway_render_failure receipts-without-key "requires gateway.receipts.existingSecretKey" \
    "${GATEWAY_ARGS[@]}" --set-string gateway.receipts.existingSecretKey=
expect_gateway_render_failure receipts-bad-key-id "gateway.receipts.keyId" \
    "${GATEWAY_ARGS[@]}" --set gateway.receipts.keyId=key=1
expect_gateway_render_failure cnf-without-client-auth "requireCNF requires gateway.tls.clientAuth" \
    "${GATEWAY_ARGS[@]}" --set gateway.tls.clientAuth= --set gateway.controlPlaneIdentity.requireCNF=true
# The GitHub App files are all or none, and the installations file has the
# custody's exact shape.
expect_gateway_render_failure github-secret-only "are set together or not at all" \
    "${GATEWAY_ARGS[@]}" --set gateway.github.existingSecret=gw-github-app
expect_gateway_render_failure github-installations-only "are set together or not at all" \
    "${GATEWAY_ARGS[@]}" --set-file gateway.github.installationsFile="$GATEWAY_TESTDATA/installations.json"
expect_gateway_render_failure github-api-url-alone "gateway.github.apiURL requires" \
    "${GATEWAY_ARGS[@]}" --set gateway.github.apiURL=https://ghe.example.internal/api/v3
for bad in extra short; do
    expect_gateway_render_failure "installations-${bad}" "exactly tenant_id, owner, installation_id and repositories are allowed" \
        "${GATEWAY_ARGS[@]}" --set gateway.github.existingSecret=gw-github-app \
        --set-file gateway.github.installationsFile="$GATEWAY_TESTDATA/installations-${bad}.json"
done
expect_gateway_render_failure installations-top 'must be {"installations": [...]}' \
    "${GATEWAY_ARGS[@]}" --set gateway.github.existingSecret=gw-github-app \
    --set-file gateway.github.installationsFile="$GATEWAY_TESTDATA/installations-top.json"

gateway_production_args=(
    --set helm.production=true
    --set helm.signing.key="$SIGNING_KEY"
    --set helm.auth.adminAPIKey="$ADMIN_KEY"
    --set helm.auth.serviceAPIKey="$SERVICE_KEY"
)
gateway_production_log="$RENDER_DIR/gateway-production-dev.log"
gateway_args_without gateway.tls.existingSecret
if production_controlplane_helm_runner template "$RELEASE" "$CHART" --namespace "$NAMESPACE" \
    "${gateway_production_args[@]}" "${GATEWAY_ARGS_WITHOUT[@]}" \
    --set gateway.tls.devInsecureLoopback=true \
    --set gateway.database.migrate.existingSecret=gw-db-owner >"$RENDER_DIR/gateway-production-dev.yaml" 2>"$gateway_production_log"; then
    echo "::error::a production gateway render with plain HTTP unexpectedly succeeded"
    exit 1
fi
assert_contains "$gateway_production_log" "gateway.tls.devInsecureLoopback is refused when helm.production=true"
gateway_production_owner_log="$RENDER_DIR/gateway-production-owner.log"
if production_controlplane_helm_runner template "$RELEASE" "$CHART" --namespace "$NAMESPACE" \
    "${gateway_production_args[@]}" "${GATEWAY_ARGS[@]}" >"$RENDER_DIR/gateway-production-owner.yaml" 2>"$gateway_production_owner_log"; then
    echo "::error::a production gateway render migrating with the runtime DSN unexpectedly succeeded"
    exit 1
fi
assert_contains "$gateway_production_owner_log" "requires an owner DSN for migrate"
gateway_production_rendered="$RENDER_DIR/rendered-gateway-production.yaml"
production_controlplane_helm_runner template "$RELEASE" "$CHART" --namespace "$NAMESPACE" \
    "${gateway_production_args[@]}" "${GATEWAY_ARGS[@]}" \
    --set gateway.database.bootstrap.enabled=true \
    --set gateway.database.bootstrap.existingSecret=gw-db-admin >"$gateway_production_rendered"
assert_contains "$gateway_production_rendered" "image: \"ghcr.io/mindburn-labs/helm-ai-kernel@${PRODUCTION_IMAGE_DIGEST}\""
assert_equals_count "$gateway_production_rendered" "@${PRODUCTION_IMAGE_DIGEST}" 4
