#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
GO_BIN="${GO:-go}"

fail() {
  printf 'launch-api-truth: %s\n' "$*" >&2
  exit 1
}

if awk '/^launch-api-truth:/,/^[[:alnum:]_.-]+:/' "$ROOT/Makefile" | grep -Eiq 'mock|skip'; then
  fail "Makefile launch-api-truth target still contains mock/skip language"
fi

(cd "$ROOT/core" && "$GO_BIN" test ./cmd/helm-ai-kernel -run 'TestOpenAPIPathsAreRegisteredByHelmServeRuntime|TestRuntimeRouteRegistryMatchesOpenAPI|TestProtectedPublicRoutesDeclareOpenAPISecurity|TestProtectedRuntimeHandlersAreDeclaredInRouteRegistry' -count=1)

grep -q '"/api/v1/agent-ui/run"' "$ROOT/apps/console/src/api/schema.ts" \
  || fail "generated Console schema is missing canonical Agent UI route"
grep -q '"/api/ag-ui/run"' "$ROOT/apps/console/src/api/schema.ts" \
  || fail "generated Console schema is missing AG-UI compatibility route"
grep -qi 'compatibility route' "$ROOT/api/openapi/helm.openapi.yaml" \
  || fail "OpenAPI lacks compatibility-route language for legacy public routes"
grep -q 'RuntimeRouteSpecs' "$ROOT/core/cmd/helm-ai-kernel/route_registry.go" \
  || fail "runtime route registry is missing"

if grep -RIE 'TBD endpoint|orphan public route|hand[- ]maintained endpoint list|stale compatibility route' "$ROOT/apps/console/src/api" "$ROOT/sdk/go" "$ROOT/sdk/python" "$ROOT/sdk/rust" "$ROOT/sdk/java" >/tmp/helm-api-truth-orphans.$$ 2>/dev/null; then
  cat /tmp/helm-api-truth-orphans.$$ >&2
  rm -f /tmp/helm-api-truth-orphans.$$
  fail "API client surfaces contain unresolved endpoint-list placeholders"
fi
rm -f /tmp/helm-api-truth-orphans.$$

printf 'launch-api-truth: passed\n'
