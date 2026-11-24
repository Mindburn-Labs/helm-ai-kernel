# shellcheck shell=bash

# A composed executable runs in the existing serving container. Compare the
# complete render after replacing only that container's image and command, so
# migration, Kernel, ports, audiences, TLS/CNF/JWKS, custody and policy cannot drift.
assert_gateway_serving_override() {
    python3 - "$1" "$2" "$GATEWAY_NAME" "$3" /app/helm-model-gateway <<'PYSERVING'
import re
import sys
from pathlib import Path

before, after = [Path(p).read_text() for p in sys.argv[1:3]]
name, image, executable = sys.argv[3:]
objects = before.split('\n---\n')
matches = [i for i, obj in enumerate(objects)
           if re.search(r'^kind: Deployment$', obj, re.M)
           and re.search(r'^  name: ' + re.escape(name) + r'$', obj, re.M)]
assert len(matches) == 1, matches
i = matches[0]
objects[i], count = re.subn(r'^          image: "[^"]+"$',
                          f'          image: "{image}"', objects[i], flags=re.M)
assert count == 1, count
objects[i], count = re.subn(r'^          command: \["/usr/local/bin/helm-gateway"\]$',
                          f'          command: ["{executable}"]', objects[i], flags=re.M)
assert count == 1, count
assert '\n---\n'.join(objects) == after, 'serving override changed fields beyond image and command'
PYSERVING
}
gateway_serving_args=(
    "${episode_args[@]}"
    --set helm.signing.key="$SIGNING_KEY"
    --set image.digest="$PRODUCTION_IMAGE_DIGEST"
    --set gateway.database.bootstrap.enabled=true
    --set gateway.database.bootstrap.existingSecret=gw-db-admin
    --set gateway.controlPlaneIdentity.requireCNF=true
    --set gateway.controlPlaneIdentity.caBundleConfigMap=cp-jwks-ca
    --set gateway.github.existingSecret=gw-github-app
    --set-file gateway.github.installationsFile="$GATEWAY_TESTDATA/installations.json"
)
serving_repository=ghcr.io/mindburn-labs/svc-helm-control-plane
serving_digest=sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
gateway_serving_selection=(
    --set-string gateway.serving.image.repository="$serving_repository"
    --set-string gateway.serving.executable=/app/helm-model-gateway
)
serving_base="$RENDER_DIR/rendered-gateway-serving-base.yaml"
helm_runner template "$RELEASE" "$CHART" --namespace "$NAMESPACE" "${gateway_serving_args[@]}" >"$serving_base"
serving_tagged="$RENDER_DIR/rendered-gateway-serving-tagged.yaml"
helm_runner template "$RELEASE" "$CHART" --namespace "$NAMESPACE" "${gateway_serving_args[@]}" \
    "${gateway_serving_selection[@]}" --set-string gateway.serving.image.tag=chart-smoke >"$serving_tagged"
assert_gateway_serving_override "$serving_base" "$serving_tagged" "$serving_repository:chart-smoke"
assert_equals_count "$serving_tagged" "@${PRODUCTION_IMAGE_DIGEST}" 3
serving_registry_port="$RENDER_DIR/rendered-gateway-serving-registry-port.yaml"
helm_runner template "$RELEASE" "$CHART" --namespace "$NAMESPACE" "${gateway_serving_args[@]}" \
    "${gateway_serving_selection[@]}" --set-string gateway.serving.image.repository=registry.example.internal:5000/team/model-gateway \
    --set-string gateway.serving.image.digest="$serving_digest" >"$serving_registry_port"
assert_gateway_serving_override "$serving_base" "$serving_registry_port" "registry.example.internal:5000/team/model-gateway@$serving_digest"

serving_production_base="$RENDER_DIR/rendered-gateway-serving-production-base.yaml"
production_controlplane_helm_runner template "$RELEASE" "$CHART" --namespace "$NAMESPACE" \
    "${gateway_production_args[@]}" "${gateway_serving_args[@]}" >"$serving_production_base"
serving_production="$RENDER_DIR/rendered-gateway-serving-production.yaml"
production_controlplane_helm_runner template "$RELEASE" "$CHART" --namespace "$NAMESPACE" \
    "${gateway_production_args[@]}" "${gateway_serving_args[@]}" "${gateway_serving_selection[@]}" \
    --set-string gateway.serving.image.digest="$serving_digest" >"$serving_production"
assert_gateway_serving_override "$serving_production_base" "$serving_production" "$serving_repository@$serving_digest"
assert_equals_count "$serving_production" "@${PRODUCTION_IMAGE_DIGEST}" 3
assert_equals_count "$serving_production" "@$serving_digest" 1

expect_gateway_render_failure serving-repository-only 'requires image.repository' "${GATEWAY_ARGS[@]}" \
    --set-string gateway.serving.image.repository="$serving_repository"
expect_gateway_render_failure serving-executable-only 'requires image.repository' "${GATEWAY_ARGS[@]}" \
    --set-string gateway.serving.executable=/app/helm-model-gateway
expect_gateway_render_failure serving-image-only 'requires image.repository' "${GATEWAY_ARGS[@]}" \
    --set-string gateway.serving.image.repository="$serving_repository" --set-string gateway.serving.image.tag=chart-smoke
expect_gateway_render_failure serving-no-own-selector 'requires exactly one' "${gateway_serving_args[@]}" "${gateway_serving_selection[@]}"
expect_gateway_render_failure serving-ambiguous-selectors 'requires exactly one' "${GATEWAY_ARGS[@]}" "${gateway_serving_selection[@]}" \
    --set-string gateway.serving.image.tag=chart-smoke --set-string gateway.serving.image.digest="$serving_digest"
expect_gateway_render_failure serving-invalid-digest 'must be a sha256 digest' "${GATEWAY_ARGS[@]}" "${gateway_serving_selection[@]}" \
    --set-string gateway.serving.image.digest=sha256:not-a-digest
serving_case=0
for bad_repository in "$serving_repository:other" "$serving_repository@$serving_digest" "https://$serving_repository" 'Invalid/repository' 'registry..example/team/model-gateway'; do
    serving_case=$((serving_case + 1))
    expect_gateway_render_failure "serving-invalid-repository-$serving_case" 'must be a lowercase image repository' "${GATEWAY_ARGS[@]}" "${gateway_serving_selection[@]}" \
        --set-string gateway.serving.image.repository="$bad_repository" --set-string gateway.serving.image.tag=chart-smoke
done
for bad_tag in 'bad:tag' 'bad tag'; do
    serving_case=$((serving_case + 1))
    expect_gateway_render_failure "serving-invalid-tag-$serving_case" 'must be a valid image tag' "${GATEWAY_ARGS[@]}" "${gateway_serving_selection[@]}" \
        --set-string gateway.serving.image.tag="$bad_tag"
done
for bad_executable in 'app/helm-model-gateway' '/app/helm-model-gateway serve' '/app/../helm-model-gateway' '/app/helm-model-gateway/'; do
    serving_case=$((serving_case + 1))
    expect_gateway_render_failure "serving-invalid-executable-$serving_case" 'must be an absolute executable path' "${GATEWAY_ARGS[@]}" "${gateway_serving_selection[@]}" \
        --set-string gateway.serving.image.tag=chart-smoke --set-string gateway.serving.executable="$bad_executable"
done
for null_field in serving serving.image serving.image.repository serving.image.tag serving.image.digest serving.executable; do
    expect_gateway_render_failure "serving-null-${null_field##*.}" 'is required' "${GATEWAY_ARGS[@]}" --set-json "gateway.$null_field=null"
done
expect_gateway_render_failure serving-command-array 'gateway.serving.executable' "${GATEWAY_ARGS[@]}" \
    --set-json 'gateway.serving.executable=["/app/helm-model-gateway"]'
expect_gateway_render_failure serving-unknown-field 'command' "${GATEWAY_ARGS[@]}" --set gateway.serving.command=ignored
expect_gateway_render_failure serving-unknown-image-field 'pullPolicy' "${GATEWAY_ARGS[@]}" --set gateway.serving.image.pullPolicy=Always
serving_production_tag_log="$RENDER_DIR/gateway-serving-production-tag.log"
if production_controlplane_helm_runner template "$RELEASE" "$CHART" --namespace "$NAMESPACE" \
    "${gateway_production_args[@]}" "${gateway_serving_args[@]}" "${gateway_serving_selection[@]}" \
    --set-string gateway.serving.image.tag=chart-smoke >"$RENDER_DIR/gateway-serving-production-tag.yaml" 2>"$serving_production_tag_log"; then
    echo '::error::a production serving override without its own digest unexpectedly succeeded'
    exit 1
fi
assert_contains "$serving_production_tag_log" 'requires gateway.serving.image.digest pinned by immutable sha256 digest'
