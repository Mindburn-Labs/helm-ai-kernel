#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
GO_BIN="${GO:-go}"

fail() {
  printf 'launch-security: %s\n' "$*" >&2
  exit 1
}

run_go_test() {
  local pkg="$1"
  local pattern="$2"
  (cd "$ROOT/core" && "$GO_BIN" test "$pkg" -run "$pattern" -count=1)
}

if awk '/^launch-security:/,/^[[:alnum:]_.-]+:/' "$ROOT/Makefile" | grep -Eiq 'mock|skip'; then
  fail "Makefile launch-security target still contains mock/skip language"
fi

run_go_test ./pkg/api 'TestCORS'
run_go_test ./cmd/helm-ai-kernel 'TestTenantScopedRuntimeAuth|TestServiceInternalRuntimeAuth'
run_go_test ./cmd/helm-ai-kernel 'TestRuntimeRouteRegistryHasExplicitSecurityMetadata|TestProtectedRuntimeHandlersAreDeclaredInRouteRegistry'

grep -q 'RouteAuthService' "$ROOT/core/cmd/helm-ai-kernel/policy_reconcile_routes.go" \
  || fail "internal policy reconcile route is not service-auth protected"
grep -q 'RouteAuthTenant' "$ROOT/core/cmd/helm-ai-kernel/console_agui_routes.go" \
  || fail "AG-UI runtime is not tenant-auth protected"
grep -q 'ai-kernel-read-only' "$ROOT/core/cmd/helm-ai-kernel/console_agui_routes.go" \
  || fail "AG-UI runtime no longer declares HELM AI Kernel read-only scope"
if grep -Eq 'GeneratedSpec|CompanyArtifactGraph|CreateArtifact|CreateEdge|Approve|Close' "$ROOT/core/cmd/helm-ai-kernel/console_agui_routes.go"; then
  fail "AG-UI runtime references authoritative commercial or mutation concepts"
fi
grep -q '"@ag-ui/client": "0.0.53"' "$ROOT/apps/console/package.json" \
  || fail "@ag-ui/client version is not pinned in apps/console/package.json"
grep -q '"node_modules/@ag-ui/client"' "$ROOT/apps/console/package-lock.json" \
  || fail "@ag-ui/client is missing from the npm lockfile"
grep -q '@ag-ui/client@0.0.53' "$ROOT/apps/console/pnpm-lock.yaml" \
  || fail "@ag-ui/client is missing from the pnpm lockfile"

if command -v gitleaks >/dev/null 2>&1; then
  (cd "$ROOT" && gitleaks detect --no-git --source . --redact --verbose)
else
  if grep -RIE --line-number --exclude-dir=.git --exclude-dir=node_modules --exclude='*.lock' \
    'BEGIN (RSA|OPENSSH|EC|DSA) PRIVATE KEY|AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9_]{36,}|sk_live_[A-Za-z0-9]+' \
    "$ROOT/bin" "$ROOT/dist" "$ROOT/release" 2>/dev/null; then
    fail "secret-like material found in release artifact directories"
  fi
  printf 'launch-security: gitleaks not installed; used fallback release-artifact regex scan\n'
fi

printf 'launch-security: passed\n'
