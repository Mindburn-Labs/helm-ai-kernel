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
LAUNCH_TARGET_VERSION="${HELM_LAUNCH_TARGET_VERSION:-$(cat VERSION)}"
MIN_GO_VERSION="$(awk '/^go / {print $2; exit}' core/go.mod)"

go_version_ok() {
  local bin="$1"
  local version
  version="$("$bin" version 2>/dev/null | awk '{print $3}' | sed 's/^go//')" || return 1
  if [[ -z "$version" ]]; then
    return 1
  fi
  python3 - "$MIN_GO_VERSION" "$version" <<'PY'
import sys

required = [int(part) for part in sys.argv[1].split(".")]
actual = [int(part) for part in sys.argv[2].split(".")]
while len(required) < 3:
    required.append(0)
while len(actual) < 3:
    actual.append(0)
raise SystemExit(0 if actual >= required else 1)
PY
}

select_go_bin() {
  local candidate
  if [[ -n "${HELM_GO_BIN:-}" ]]; then
    if [[ -x "$HELM_GO_BIN" ]] && go_version_ok "$HELM_GO_BIN"; then
      printf '%s\n' "$HELM_GO_BIN"
      return 0
    fi
    printf 'HELM_GO_BIN does not point to Go >= %s: %s\n' "$MIN_GO_VERSION" "$HELM_GO_BIN" >&2
    return 1
  fi

  for candidate in /usr/local/go/bin/go /opt/homebrew/bin/go "$(command -v go 2>/dev/null || true)"; do
    if [[ -n "$candidate" && -x "$candidate" ]] && go_version_ok "$candidate"; then
      printf '%s\n' "$candidate"
      return 0
    fi
  done

  printf 'Go >= %s is required for launch readiness.\n' "$MIN_GO_VERSION" >&2
  return 1
}

if ! GO_BIN="$(select_go_bin)"; then
  exit 1
fi
export PATH="$(dirname "$GO_BIN"):$PATH"
unset GOROOT
printf 'Using Go: %s\n' "$("$GO_BIN" version)"

ORDER=()
STATUS=()
DETAIL=()

lookup_index() {
  local wanted="$1"
  local i
  for i in "${!ORDER[@]}"; do
    if [[ "${ORDER[$i]}" == "$wanted" ]]; then
      printf '%s\n' "$i"
      return 0
    fi
  done
  return 1
}

status_for() {
  local idx
  idx="$(lookup_index "$1")"
  printf '%s' "${STATUS[$idx]}"
}

detail_for() {
  local idx
  idx="$(lookup_index "$1")"
  printf '%s' "${DETAIL[$idx]}"
}

record() {
  local key="$1"
  local label="$2"
  local command="$3"
  local log="$LOG_DIR/${key}.log"
  local idx="${#ORDER[@]}"
  ORDER[$idx]="$key"
  printf '==> %s\n' "$label"
  if bash -c "$command" >"$log" 2>&1; then
    STATUS[$idx]="x"
    DETAIL[$idx]="$label"
    printf '    ok\n'
  else
    STATUS[$idx]=" "
    DETAIL[$idx]="$label (see $log)"
    printf '    failed (see %s)\n' "$log"
  fi
}

record pr_boundary "PR Boundary: No open PRs contain commercial infrastructure terminology." "python3 scripts/launch/pr_boundary_check.py"
record terminology_boundary "Terminology Boundary: VERDICT_CANONICALIZATION.md exists and resolves the ALLOW/DENY/ESCALATE vs. DEFER drift." "test -f docs/VERDICT_CANONICALIZATION.md && rg -q 'ALLOW' docs/VERDICT_CANONICALIZATION.md && rg -q 'DENY' docs/VERDICT_CANONICALIZATION.md && rg -q 'ESCALATE' docs/VERDICT_CANONICALIZATION.md && rg -q 'DEFER' docs/VERDICT_CANONICALIZATION.md"
record version "Version: VERSION is set to launch target ${LAUNCH_TARGET_VERSION}." "test \"\$(cat VERSION)\" = '${LAUNCH_TARGET_VERSION}'"
record homebrew "Homebrew: README points to canonical mindburnlabs/tap/helm-ai-kernel." "rg -q 'brew install mindburnlabs/tap/helm-ai-kernel' README.md && ! rg -q 'brew install (mindburn|Mindburn-Labs|mindburn-labs)/homebrew-tap/helm|brew install mindburn-labs/tap/helm' README.md"

record build "Build: make build completes cleanly." "make build"
record test "Test: make test completes cleanly." "make test"
record demos "Demos: examples/launch headless suite is present." "test -d examples/launch && test -f examples/launch/README.md && test -x scripts/launch/smoke.sh && test -x scripts/launch/demo-local.sh && test -x scripts/launch/demo-proof.sh && test -x scripts/launch/demo-mcp.sh && test -x scripts/launch/demo-openai-proxy.sh"
record mcp "MCP: MCP quarantine demo path is verified." "bash scripts/launch/demo-mcp.sh"
record proxy "Proxy: OpenAI base-url proxy demo path is verified." "bash scripts/launch/demo-openai-proxy.sh"
record proof "Proof: Evidence verification and tamper-failure paths are documented and verifiable." "bash scripts/launch/demo-proof.sh && rg -qi 'tamper' docs/VERIFICATION.md examples/launch/README.md"

record issue_templates "Issue Templates: bug_report, feature_request, docs_gap, integration_request, policy_example_request are present." "test -f .github/ISSUE_TEMPLATE/bug_report.yml && test -f .github/ISSUE_TEMPLATE/feature_request.yml && test -f .github/ISSUE_TEMPLATE/docs_gap.yml && test -f .github/ISSUE_TEMPLATE/integration_request.yml && test -f .github/ISSUE_TEMPLATE/policy_example_request.yml"
record docs_sync "Docs Sync: docs-coverage and docs-truth checks pass." "make docs-coverage docs-truth"
record release "Release: Dry-run release script confirms artifacts can be generated." "make launch-release-dry-run"

final_state="READY"
for idx in "${!ORDER[@]}"; do
  if [[ "${STATUS[$idx]}" != "x" ]]; then
    final_state="NOT READY"
    break
  fi
done

if [[ "$WRITE" -eq 1 ]]; then
  REPORT_FILE="${HELM_LAUNCH_READY_REPORT:-$LOG_DIR/launch-readiness.txt}"
  mkdir -p "$(dirname "$REPORT_FILE")"
  cat > "$REPORT_FILE" <<EOF
# HELM AI Kernel Launch Readiness Checklist

This report tracks the final launch-readiness state of the \`helm-ai-kernel\` repository. It is updated mechanically by the \`scripts/launch/launch-ready.sh\` verification tool.

Last verification: $(date -u +%Y-%m-%dT%H:%M:%SZ)
Verification logs are emitted by the tool for each run and are intentionally
not committed to the repository.

## Phase 0: Boundary Hardening
- [$(status_for pr_boundary)] **$(detail_for pr_boundary)**
- [$(status_for terminology_boundary)] **$(detail_for terminology_boundary)**
- [$(status_for version)] **$(detail_for version)**
- [$(status_for homebrew)] **$(detail_for homebrew)**

## Phase 1: Implementation & Proof
- [$(status_for build)] **$(detail_for build)**
- [$(status_for test)] **$(detail_for test)**
- [$(status_for demos)] **$(detail_for demos)**
- [$(status_for mcp)] **$(detail_for mcp)**
- [$(status_for proxy)] **$(detail_for proxy)**
- [$(status_for proof)] **$(detail_for proof)**

## Phase 2: Community & Release
- [$(status_for issue_templates)] **$(detail_for issue_templates)**
- [$(status_for docs_sync)] **$(detail_for docs_sync)**
- [$(status_for release)] **$(detail_for release)**

## Final Status
**CURRENT STATE: $final_state**
EOF
  printf 'Report: %s\n' "$REPORT_FILE"
fi

printf '\nFinal status: %s\n' "$final_state"
printf 'Logs: %s\n' "$LOG_DIR"

if [[ "$final_state" != "READY" ]]; then
  exit 1
fi
