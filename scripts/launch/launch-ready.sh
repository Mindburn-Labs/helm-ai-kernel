#!/usr/bin/env bash
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

WRITE=0
if [[ "${1:-}" == "--write" ]]; then
  WRITE=1
fi

LOG_DIR="${HELM_LAUNCH_READY_LOG_DIR:-$(mktemp -d "${TMPDIR:-/tmp}/helm-launch-ready.XXXXXX")}"
mkdir -p "$LOG_DIR"

declare -A STATUS
declare -A DETAIL
ORDER=()

record() {
  local key="$1"
  local label="$2"
  local command="$3"
  local log="$LOG_DIR/${key}.log"
  ORDER+=("$key")
  printf '==> %s\n' "$label"
  if bash -c "$command" >"$log" 2>&1; then
    STATUS["$key"]="x"
    DETAIL["$key"]="$label"
    printf '    ok\n'
  else
    STATUS["$key"]=" "
    DETAIL["$key"]="$label (see $log)"
    printf '    failed (see %s)\n' "$log"
  fi
}

record pr_boundary "PR Boundary: No open PRs contain commercial infrastructure terminology." "python3 scripts/launch/pr_boundary_check.py"
record config_boundary "Config Boundary: wrangler.toml does not enforce hosted domains." "! rg -n 'custom_domains\\s*=|oss\\.mindburn\\.org' apps/console/wrangler.toml"
record terminology_boundary "Terminology Boundary: VERDICT_CANONICALIZATION.md exists and resolves the ALLOW/DENY/ESCALATE vs. DEFER drift." "test -f docs/VERDICT_CANONICALIZATION.md && rg -q 'ALLOW' docs/VERDICT_CANONICALIZATION.md && rg -q 'DENY' docs/VERDICT_CANONICALIZATION.md && rg -q 'ESCALATE' docs/VERDICT_CANONICALIZATION.md && rg -q 'DEFER' docs/VERDICT_CANONICALIZATION.md"
record version "Version: VERSION is set to launch target 0.5.0." "test \"\$(cat VERSION)\" = '0.5.0'"
record homebrew "Homebrew: README points to canonical mindburnlabs/tap/helm." "rg -q 'brew install mindburnlabs/tap/helm' README.md && ! rg -q 'brew install (mindburn|Mindburn-Labs|mindburn-labs)/homebrew-tap/helm|brew install mindburn-labs/tap/helm' README.md"

record build "Build: make build completes cleanly." "make build"
record test "Test: make test completes cleanly." "make test"
record demos "Demos: examples/launch suite is present." "test -d examples/launch && test -f examples/launch/README.md && test -x scripts/launch/smoke.sh && test -x scripts/launch/demo-local.sh && test -x scripts/launch/demo-proof.sh && test -x scripts/launch/demo-mcp.sh && test -x scripts/launch/demo-openai-proxy.sh && test -x scripts/launch/demo-console.sh"
record console "Console: apps/console builds and runs locally without remote dependencies." "bash scripts/launch/demo-console.sh"
record mcp "MCP: MCP quarantine demo path is verified." "bash scripts/launch/demo-mcp.sh"
record proxy "Proxy: OpenAI base-url proxy demo path is verified." "bash scripts/launch/demo-openai-proxy.sh"
record proof "Proof: Evidence verification and tamper-failure paths are documented and verifiable." "bash scripts/launch/demo-proof.sh && rg -qi 'tamper' docs/VERIFICATION.md examples/launch/README.md"

record issue_templates "Issue Templates: bug_report, feature_request, docs_gap, integration_request, policy_example_request are present." "test -f .github/ISSUE_TEMPLATE/bug_report.yml && test -f .github/ISSUE_TEMPLATE/feature_request.yml && test -f .github/ISSUE_TEMPLATE/docs_gap.yml && test -f .github/ISSUE_TEMPLATE/integration_request.yml && test -f .github/ISSUE_TEMPLATE/policy_example_request.yml"
record docs_sync "Docs Sync: docs-coverage and docs-truth checks pass." "make docs-coverage docs-truth"
record security "Security: make launch-security (vuln, secret, sbom) passes." "make launch-security"
record release "Release: Dry-run release script confirms artifacts can be generated." "make launch-release-dry-run"

final_state="READY"
for key in "${ORDER[@]}"; do
  if [[ "${STATUS[$key]}" != "x" ]]; then
    final_state="NOT READY"
    break
  fi
done

if [[ "$WRITE" -eq 1 ]]; then
  cat > docs/launch/LAUNCH_READINESS.md <<EOF
# HELM OSS Launch Readiness Checklist

This document tracks the final launch-readiness state of the \`helm-oss\` repository. It is updated mechanically by the \`scripts/launch/launch-ready.sh\` verification tool.

Last verification: $(date -u +%Y-%m-%dT%H:%M:%SZ)
Verification logs are emitted by the tool for each run and are intentionally
not committed to the repository.

## Phase 0: Boundary Hardening
- [${STATUS[pr_boundary]}] **${DETAIL[pr_boundary]}**
- [${STATUS[config_boundary]}] **${DETAIL[config_boundary]}**
- [${STATUS[terminology_boundary]}] **${DETAIL[terminology_boundary]}**
- [${STATUS[version]}] **${DETAIL[version]}**
- [${STATUS[homebrew]}] **${DETAIL[homebrew]}**

## Phase 1: Implementation & Proof
- [${STATUS[build]}] **${DETAIL[build]}**
- [${STATUS[test]}] **${DETAIL[test]}**
- [${STATUS[demos]}] **${DETAIL[demos]}**
- [${STATUS[console]}] **${DETAIL[console]}**
- [${STATUS[mcp]}] **${DETAIL[mcp]}**
- [${STATUS[proxy]}] **${DETAIL[proxy]}**
- [${STATUS[proof]}] **${DETAIL[proof]}**

## Phase 2: Community & Release
- [${STATUS[issue_templates]}] **${DETAIL[issue_templates]}**
- [${STATUS[docs_sync]}] **${DETAIL[docs_sync]}**
- [${STATUS[security]}] **${DETAIL[security]}**
- [${STATUS[release]}] **${DETAIL[release]}**

## Final Status
**CURRENT STATE: $final_state**
EOF
fi

printf '\nFinal status: %s\n' "$final_state"
printf 'Logs: %s\n' "$LOG_DIR"

if [[ "$final_state" != "READY" ]]; then
  exit 1
fi
