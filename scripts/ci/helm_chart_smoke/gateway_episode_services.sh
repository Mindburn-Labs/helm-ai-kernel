# shellcheck shell=bash

# D24: distinct episode services and peers; the edge cannot reach the worker
# or privileged listener through an executor service. Provider keys mount only
# on the gateway Deployment, never the kernel/migrate containers.
episode_args=(
    "${GATEWAY_ARGS[@]}"
    --set gateway.worker.enabled=true
    --set gateway.worker.audience=helm-gateway-worker:smoke
    --set gateway.networkPolicy.worker.namespaceSelector.matchLabels.helm-workers=enabled
    --set gateway.executor.enabled=true
    --set gateway.executor.audience=helm-gateway-executor:smoke
    --set gateway.networkPolicy.executor.namespaceSelector.matchLabels.helm-edge=enabled
    --set gateway.models.routesConfigMap=gw-model-routes
    --set gateway.models.credentialsSecret=gw-model-providers
)
episode_rendered="$RENDER_DIR/rendered-gateway-episodes.yaml"
helm_runner template "$RELEASE" "$CHART" --namespace "$NAMESPACE" "${episode_args[@]}" >"$episode_rendered"
for value in '--worker-listen=:8444' '--executor-listen=:8445' 'HELM_GATEWAY_WORKER_AUDIENCE' 'HELM_GATEWAY_EXECUTOR_AUDIENCE' 'HELM_GATEWAY_MODEL_ROUTES_FILE' 'value: "3600s"' 'value: "900s"' 'targetPort: worker' 'targetPort: executor'; do
    assert_contains "$episode_rendered" "$value"
done
assert_equals_count "$episode_rendered" 'secretName: "gw-model-providers"' 1
assert_equals_count "$episode_rendered" 'mountPath: /var/run/secrets/helm-gateway-model-providers' 1
assert_contains "$episode_rendered" "name: ${GATEWAY_NAME}-executor"
assert_contains "$episode_rendered" "name: ${GATEWAY_NAME}-worker"
assert_not_contains "$gateway_plain_rendered" 'targetPort: executor'
assert_not_contains "$gateway_plain_rendered" 'targetPort: worker'
python3 - "$episode_rendered" "$GATEWAY_NAME" <<'PYTEST'
import sys, re
text=open(sys.argv[1]).read()
objects=text.split('\n---\n')
name=sys.argv[2]
def obj(kind, resource):
    return next(x for x in objects if re.search(r'^kind: '+kind+r'$',x,re.M) and re.search(r'^  name: '+re.escape(resource)+r'$',x,re.M))
for profile,port in [('worker',8444),('executor',8445)]:
    svc=obj('Service',name+'-'+profile)
    assert '  type: ClusterIP\n' in svc
    assert re.findall(r'^    - port: (\d+)$',svc,re.M)==[str(port)]
    assert f'      targetPort: {profile}\n' in svc
    assert 'targetPort: https' not in svc
np=obj('NetworkPolicy',name)
for port,label in [(8443,'helm-cp'),(8444,'helm-workers'),(8445,'helm-edge')]:
    peer=f"    - from:\n        - namespaceSelector:\n            matchLabels:\n              {label}: enabled\n      ports:\n        - protocol: TCP\n          port: {port}\n"
    assert peer in np, (label,port)
for value in objects:
    if 'secretName: "gw-model-providers"' in value:
        assert value==obj('Deployment',name)

PYTEST
expect_gateway_render_failure executor-worker-audience 'must use its own helm-gateway-executor' "${episode_args[@]}" --set gateway.executor.audience=helm-gateway-worker:smoke
expect_gateway_render_failure executor-main-audience 'must differ from the privileged' "${episode_args[@]}" --set gateway.controlPlaneIdentity.audience=helm-gateway-executor:smoke
expect_gateway_render_failure executor-no-peers 'requires explicit' "${GATEWAY_ARGS[@]}" --set gateway.executor.enabled=true --set gateway.executor.audience=helm-gateway-executor:smoke
expect_gateway_render_failure worker-no-peers 'requires explicit' "${GATEWAY_ARGS[@]}" --set gateway.worker.enabled=true --set gateway.worker.audience=helm-gateway-worker:smoke
expect_gateway_render_failure executor-no-routes 'requires gateway.models.routesConfigMap' "${GATEWAY_ARGS[@]}" --set gateway.executor.enabled=true --set gateway.executor.audience=helm-gateway-executor:smoke --set gateway.networkPolicy.executor.podSelector.matchLabels.helm-edge=enabled
long_name="$(printf 'gateway%.0s' {1..9})"
helm_runner template "$RELEASE" "$CHART" --namespace "$NAMESPACE" "${episode_args[@]}" --set fullnameOverride="$long_name" >"$RENDER_DIR/rendered-long-episodes.yaml"
python3 - "$RENDER_DIR/rendered-long-episodes.yaml" <<'PYNAMES'
import sys,re
services=[x for x in open(sys.argv[1]).read().split('\n---\n') if re.search(r'^kind: Service$',x,re.M)]
names=[re.search(r'^  name: (.+)$',x,re.M).group(1) for x in services]
assert all(len(n)<=63 for n in names), names
profiles=[n for n in names if n.endswith(('-worker','-executor'))]
assert len(profiles)==2 and len(set(profiles))==2, profiles
assert any(n.endswith('-worker') for n in profiles)
assert any(n.endswith('-executor') for n in profiles)
PYNAMES
expect_gateway_render_failure executor-too-long 'gateway.executor.maxTTLSeconds' "${episode_args[@]}" --set gateway.executor.maxTTLSeconds=901
expect_gateway_render_failure worker-too-long 'gateway.worker.maxTTLSeconds' "${episode_args[@]}" --set gateway.worker.maxTTLSeconds=3601
expect_gateway_render_failure executor-audience-only 'requires that listener' "${GATEWAY_ARGS[@]}" --set gateway.executor.audience=helm-gateway-executor:smoke
expect_gateway_render_failure model-routes-no-listener 'requires a worker or executor listener' "${GATEWAY_ARGS[@]}" --set gateway.models.routesConfigMap=gw-model-routes
expect_gateway_render_failure model-secret-no-routes 'requires gateway.models.routesConfigMap' "${GATEWAY_ARGS[@]}" --set gateway.models.credentialsSecret=gw-model-providers
