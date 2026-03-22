#!/usr/bin/env bash
# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║  HELM OSS End-to-End Repo Audit                                 ║
# ║  Adapted for the open-source repository (helm-oss)                         ║
# ║                                                                            ║
# ║  Usage:                                                                    ║
# ║    bash scripts/ci/repo_audit.sh                   # run all sections      ║
# ║    bash scripts/ci/repo_audit.sh --section <name>  # run single section    ║
# ║    bash scripts/ci/repo_audit.sh --list            # list all sections     ║
# ║                                                                            ║
# ║  Exit code = number of FAIL verdicts (0 = clean repo)                      ║
# ╚══════════════════════════════════════════════════════════════════════════════╝
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
EVIDENCE_DIR="$REPO_ROOT/data/evidence/repo_audit"
BASELINES_DIR="$REPO_ROOT/scripts/ci/baselines"
TIMESTAMP="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
GIT_SHA="$(git -C "$REPO_ROOT" rev-parse HEAD 2>/dev/null || echo "unknown")"

# ── Colors ────────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; DIM='\033[2m'; NC='\033[0m'

# ── Counters ──────────────────────────────────────────────────────────────────
TOTAL_SECTIONS=0
PASS_COUNT=0
FAIL_COUNT=0
SKIP_COUNT=0
WARN_COUNT=0

mkdir -p "$EVIDENCE_DIR"

# ══════════════════════════════════════════════════════════════════════════════
# FRAMEWORK
# ══════════════════════════════════════════════════════════════════════════════

section_start() {
    local name="$1" description="$2"
    CURRENT_SECTION="$name"
    ((TOTAL_SECTIONS++)) || true
    echo ""
    echo -e "${BOLD}${CYAN}┌─────────────────────────────────────────────────────────────┐${NC}"
    echo -e "${BOLD}${CYAN}│  §${TOTAL_SECTIONS} ${name}${NC}"
    echo -e "${DIM}│  ${description}${NC}"
    echo -e "${BOLD}${CYAN}└─────────────────────────────────────────────────────────────┘${NC}"
}

verdict() {
    local status="$1" detail="${2:-}"
    case "$status" in
        PASS) echo -e "  ${GREEN}✅ PASS${NC} ${detail}"; ((PASS_COUNT++)) || true ;;
        FAIL) echo -e "  ${RED}❌ FAIL${NC} ${detail}"; ((FAIL_COUNT++)) || true ;;
        SKIP) echo -e "  ${YELLOW}⏭️  SKIP${NC} ${detail}"; ((SKIP_COUNT++)) || true ;;
        WARN) echo -e "  ${YELLOW}⚠️  WARN${NC} ${detail}"; ((WARN_COUNT++)) || true ;;
    esac
    cat > "$EVIDENCE_DIR/${CURRENT_SECTION}.json" <<EOF
{"section":"$CURRENT_SECTION","status":"$status","detail":"$detail","timestamp":"$TIMESTAMP","git_sha":"$GIT_SHA"}
EOF
}

in_array() {
    local needle="$1"; shift || true
    local item
    for item in "$@"; do
        [[ "$item" == "$needle" ]] && return 0
    done
    return 1
}

load_allowlist() {
    local file="$1"
    [[ -f "$file" ]] || return 1
    grep -vE '^[[:space:]]*(#|$)' "$file" | sort -u
}

# ══════════════════════════════════════════════════════════════════════════════
# PRE-FLIGHT TOOL CHECK
# ══════════════════════════════════════════════════════════════════════════════

preflight_check() {
    echo ""
    echo -e "${BOLD}${CYAN}┌─────────────────────────────────────────────────────────────┐${NC}"
    echo -e "${BOLD}${CYAN}│  Pre-Flight Tool Check                                      │${NC}"
    echo -e "${BOLD}${CYAN}└─────────────────────────────────────────────────────────────┘${NC}"

    local required_tools=("go" "git" "python3")
    local optional_tools=("staticcheck" "golangci-lint" "shellcheck")
    local missing_required=()
    local missing_optional=()

    for tool in "${required_tools[@]}"; do
        if command -v "$tool" &>/dev/null; then
            echo -e "  ${GREEN}✅${NC} $tool $(command -v "$tool")"
        else
            missing_required+=("$tool")
            echo -e "  ${RED}❌${NC} $tool ${RED}(REQUIRED — audit cannot proceed)${NC}"
        fi
    done

    for tool in "${optional_tools[@]}"; do
        if command -v "$tool" &>/dev/null; then
            echo -e "  ${GREEN}✅${NC} $tool"
        else
            missing_optional+=("$tool")
            echo -e "  ${YELLOW}⚠️${NC}  $tool ${DIM}(optional — related sections will SKIP)${NC}"
        fi
    done

    if [[ ${#missing_required[@]} -gt 0 ]]; then
        echo ""
        echo -e "  ${RED}FATAL: Missing required tools: ${missing_required[*]}${NC}"
        exit 1
    fi

    echo -e "  ${DIM}Required: ${#required_tools[@]}/${#required_tools[@]} ✅  Optional: $((${#optional_tools[@]} - ${#missing_optional[@]}))/${#optional_tools[@]}${NC}"
    echo ""
}

preflight_check

# ══════════════════════════════════════════════════════════════════════════════
# §1: GO MOD TIDY
# ══════════════════════════════════════════════════════════════════════════════
audit_go_mod_tidy() {
    section_start "go_mod_tidy" "Verify go.mod/go.sum are clean — no uncommitted dependency drift"
    cd "$REPO_ROOT"
    local dirty=()
    while IFS= read -r modfile; do
        local moddir; moddir="$(dirname "$modfile")"
        # -diff checks tidiness without mutating go.mod/go.sum.
        if ! (cd "$moddir" && go mod tidy -diff >/dev/null 2>&1); then
            dirty+=("$moddir")
        fi
    done < <(find "$REPO_ROOT" -name "go.mod" -not -path "*/vendor/*" -not -path "*/node_modules/*" 2>/dev/null)
    [[ ${#dirty[@]} -eq 0 ]] && verdict PASS "All go.mod files are tidy" || verdict FAIL "Dirty go.mod in: ${dirty[*]}"
}

# ══════════════════════════════════════════════════════════════════════════════
# §2: GO VET
# ══════════════════════════════════════════════════════════════════════════════
audit_go_vet() {
    section_start "go_vet" "Static analysis for suspicious constructs across all Go code"
    cd "$REPO_ROOT/core"
    local vet_output; vet_output=$(go vet ./... 2>&1) || true
    local issues; issues=$(echo "$vet_output" | grep -cE "\.go:[0-9]+:" 2>/dev/null || true)
    issues=$(echo "$issues" | tr -d '[:space:]'); issues=${issues:-0}
    [[ "$issues" -eq 0 ]] && verdict PASS "go vet clean" || { echo "$vet_output" | head -20; verdict FAIL "$issues issues found by go vet"; }
}

# ══════════════════════════════════════════════════════════════════════════════
# §3: GOVULNCHECK
# ══════════════════════════════════════════════════════════════════════════════
audit_govulncheck() {
    section_start "govulncheck" "Check for known vulnerabilities in dependencies (CVE database)"
    cd "$REPO_ROOT"
    local toolchain="${GOTOOLCHAIN:-go1.25.7}"
    local vuln_total=0
    local exec_fail=0
    local scanned=0

    while IFS= read -r modfile; do
        local moddir; moddir="$(dirname "$modfile")"
        local out exit_code=0
        out=$(cd "$moddir" && GOWORK=off GOTOOLCHAIN="$toolchain" go run golang.org/x/vuln/cmd/govulncheck@latest ./... 2>&1) || exit_code=$?
        ((scanned++)) || true

        if echo "$out" | grep -q "Vulnerability #"; then
            local c; c=$(echo "$out" | grep -c "Vulnerability #" || echo 0)
            vuln_total=$((vuln_total + c))
            echo "  [${moddir#$REPO_ROOT/}]"
            echo "$out" | grep -A2 "Vulnerability #" | head -30
            continue
        fi

        if [[ "$exit_code" -ne 0 ]]; then
            ((exec_fail++)) || true
            echo "  [${moddir#$REPO_ROOT/}] govulncheck execution failed (exit $exit_code)"
            echo "$out" | head -10
        fi
    done < <(find "$REPO_ROOT" -name "go.mod" -not -path "*/vendor/*" -not -path "*/node_modules/*" 2>/dev/null)

    echo "  Modules scanned: $scanned"
    if [[ "$vuln_total" -gt 0 ]]; then
        verdict FAIL "$vuln_total called vulnerabilities"
    elif [[ "$exec_fail" -gt 0 ]]; then
        verdict FAIL "govulncheck execution failed in $exec_fail modules"
    else
        verdict PASS "No called vulnerabilities"
    fi
}

# ══════════════════════════════════════════════════════════════════════════════
# §4: GOLANGCI-LINT
# ══════════════════════════════════════════════════════════════════════════════
audit_golangci_lint() {
    section_start "golangci_lint" "Deterministic Go lint baseline (govet, staticcheck, ineffassign)"
    cd "$REPO_ROOT/core"
    if ! command -v golangci-lint &>/dev/null; then verdict SKIP "golangci-lint not installed"; return; fi
    local out exit_code=0
    out=$(golangci-lint run --timeout=5m --default=none -E govet -E staticcheck -E ineffassign ./... 2>&1) || exit_code=$?
    if [[ "$exit_code" -eq 0 ]]; then verdict PASS "golangci-lint clean"
    else local c; c=$(echo "$out" | grep -cE "\.go:" || echo 0); echo "$out" | tail -20; verdict FAIL "$c lint issues"; fi
}

# ══════════════════════════════════════════════════════════════════════════════
# §5: COVERAGE GATE
# ══════════════════════════════════════════════════════════════════════════════
audit_coverage_gate() {
    section_start "coverage_gate" "Enforce minimum test coverage per package (30% floor)"
    cd "$REPO_ROOT"
    local MIN=30 below=() below_pkgs=()
    local tested_pkgs=0
    local out; out=$(go test -short -cover -count=1 ./core/pkg/... 2>&1) || true
    while IFS= read -r line; do
        if echo "$line" | grep -q "coverage:"; then
            local pkg cov; pkg=$(echo "$line" | awk '{print $2}')
            cov=$(echo "$line" | grep -oE '[0-9]+\.[0-9]+%' | head -1 | sed 's/%//')
            [[ -z "$cov" ]] && continue
            ((tested_pkgs++)) || true
            local ci; ci=$(echo "$cov" | awk '{print int($1)}')
            if [[ "$ci" -lt "$MIN" ]]; then
                below+=("$pkg (${cov}%)")
                below_pkgs+=("$pkg")
            fi
        fi
    done <<< "$out"

    local allow_file="$BASELINES_DIR/no_test_packages.allowlist"
    local coverage_allow_file="$BASELINES_DIR/coverage_floor_exceptions.allowlist"
    [[ -f "$allow_file" ]] || { verdict FAIL "Missing baseline file: ${allow_file#$REPO_ROOT/}"; return; }
    [[ -f "$coverage_allow_file" ]] || { verdict FAIL "Missing baseline file: ${coverage_allow_file#$REPO_ROOT/}"; return; }

    local no_test_pkgs=()
    while IFS= read -r pkg; do
        [[ -z "$pkg" ]] && continue
        local rel="${pkg#github.com/Mindburn-Labs/helm-oss/}"
        local dir="$REPO_ROOT/$rel"
        find "$dir" -maxdepth 1 -name "*_test.go" -type f 2>/dev/null | grep -q . || no_test_pkgs+=("$rel")
    done < <(go list ./core/pkg/... 2>/dev/null)

    local allowed_no_test=()
    while IFS= read -r line; do
        [[ -n "$line" ]] && allowed_no_test+=("$line")
    done < <(load_allowlist "$allow_file" || true)

    local allowed_low_cov=()
    while IFS= read -r line; do
        [[ -n "$line" ]] && allowed_low_cov+=("$line")
    done < <(load_allowlist "$coverage_allow_file" || true)

    local unexpected_no_test=()
    local pkg
    for pkg in "${no_test_pkgs[@]}"; do
        in_array "$pkg" "${allowed_no_test[@]}" || unexpected_no_test+=("$pkg")
    done

    local unexpected_below=()
    for pkg in "${below_pkgs[@]}"; do
        in_array "$pkg" "${allowed_low_cov[@]}" || unexpected_below+=("$pkg")
    done

    local resolved_baseline=0
    for pkg in "${allowed_no_test[@]}"; do
        in_array "$pkg" "${no_test_pkgs[@]}" || ((resolved_baseline++)) || true
    done
    local resolved_low_cov=0
    for pkg in "${allowed_low_cov[@]}"; do
        in_array "$pkg" "${below_pkgs[@]}" || ((resolved_low_cov++)) || true
    done

    echo "  Tested packages: $tested_pkgs, Below ${MIN}%: ${#below[@]}"
    echo "  No-test packages: ${#no_test_pkgs[@]}, Unexpected: ${#unexpected_no_test[@]}, Baseline resolved: $resolved_baseline"
    echo "  Low-coverage baseline: ${#allowed_low_cov[@]}, Unexpected below floor: ${#unexpected_below[@]}, Baseline resolved: $resolved_low_cov"

    if [[ ${#unexpected_no_test[@]} -gt 0 ]]; then
        printf '    %s\n' "${unexpected_no_test[@]}" | head -15
        verdict FAIL "${#unexpected_no_test[@]} unallowlisted packages without tests"
    elif [[ ${#unexpected_below[@]} -gt 0 ]]; then
        printf '    %s\n' "${unexpected_below[@]}" | head -15
        verdict FAIL "${#unexpected_below[@]} unallowlisted packages below ${MIN}% coverage"
    elif [[ ${#below[@]} -gt 0 ]]; then
        printf '    %s\n' "${below[@]}" | head -15
        verdict PASS "Coverage floor stable with approved exceptions"
    else
        verdict PASS "Coverage floor met; no unexpected test gaps"
    fi
}

# ══════════════════════════════════════════════════════════════════════════════
# §6: STRUCTURED LOGGING
# ══════════════════════════════════════════════════════════════════════════════
audit_structured_logging() {
    section_start "structured_logging" "Ban direct fmt.Print* and legacy log.* in runtime Go code"
    cd "$REPO_ROOT"
    local v; v=$(grep -rnE '(fmt\.Print(f|ln)?\(|log\.(Print(f|ln)?|Fatal(f|ln)?|Panic(f|ln)?)\()' \
        --include="*.go" core/pkg/ tools/helm-node/ 2>/dev/null | grep -v "_test.go" | grep -v "// nolint" | grep -v "//nolint" || true)
    local c; c=$(printf '%s' "$v" | grep -c "\.go:" 2>/dev/null || true)
    c=${c:-0}
    [[ "$c" -eq 0 ]] && verdict PASS "No direct print/log calls in runtime code" || { echo "$v" | head -20; verdict FAIL "$c direct print/log calls detected"; }
}

# ══════════════════════════════════════════════════════════════════════════════
# §7: SECRET SCAN
# ══════════════════════════════════════════════════════════════════════════════
audit_secret_scan() {
    section_start "secret_scan" "Detect hardcoded secrets, keys, tokens in tracked files"
    cd "$REPO_ROOT"
    local patterns=('AKIA[0-9A-Z]{16}' '-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----' 'ghp_[A-Za-z0-9]{36}' 'sk-[A-Za-z0-9]{48}' '"type":\s*"service_account"')
    local findings=0
    for p in "${patterns[@]}"; do
        local hits; hits=$(git grep -lPn "$p" -- ':!vendor' ':!node_modules' ':!*.md' 2>/dev/null || true)
        [[ -n "$hits" ]] && { echo "  ⚠️  Match: $p"; ((findings++)) || true; }
    done
    [[ "$findings" -eq 0 ]] && verdict PASS "No hardcoded secrets" || verdict FAIL "$findings secret patterns matched"
}

# ══════════════════════════════════════════════════════════════════════════════
# §8: SCHEMA VALIDATION
# ══════════════════════════════════════════════════════════════════════════════
audit_schema_validation() {
    section_start "schema_validation" "Verify all JSON schemas are well-formed"
    cd "$REPO_ROOT"
    local total=0 failed=0
    while IFS= read -r f; do
        ((total++)) || true
        python3 -c "import json; json.load(open('$f'))" 2>/dev/null || ((failed++)) || true
    done < <(find "$REPO_ROOT/schemas" -name "*.json" -type f 2>/dev/null)
    echo "  Schemas: $total"
    [[ "$failed" -eq 0 ]] && verdict PASS "All $total schemas valid" || verdict FAIL "$failed/$total malformed"
}

# ══════════════════════════════════════════════════════════════════════════════
# §9: DOCKERFILE BEST PRACTICES
# ══════════════════════════════════════════════════════════════════════════════
audit_dockerfile() {
    section_start "dockerfile_audit" "Check Dockerfiles for best practices"
    cd "$REPO_ROOT"
    local issues=0
    while IFS= read -r df; do
        local rel="${df#$REPO_ROOT/}"; echo "  Checking: $rel"
        grep -qE '^FROM .+:latest' "$df" 2>/dev/null && { echo "    ⚠️  :latest tag"; ((issues++)) || true; }
        grep -q '^USER ' "$df" 2>/dev/null || { echo "    ⚠️  No USER directive"; ((issues++)) || true; }
        grep -qE '^ADD https?://' "$df" 2>/dev/null && { echo "    ⚠️  ADD with URL"; ((issues++)) || true; }
    done < <(find "$REPO_ROOT" -name "Dockerfile*" -not -path "*/node_modules/*" -not -path "*/.git/*" 2>/dev/null)
    [[ "$issues" -eq 0 ]] && verdict PASS "Dockerfiles clean" || verdict FAIL "$issues issues"
}

# ══════════════════════════════════════════════════════════════════════════════
# §10: FORBIDDEN PATTERNS
# ══════════════════════════════════════════════════════════════════════════════
audit_forbidden_patterns() {
    section_start "forbidden_patterns" "Detect tracked files that should never be in git"
    cd "$REPO_ROOT"
    local forbidden=(".env" "*.pem" "*.key" "id_rsa" "*.p12" "__pycache__" ".DS_Store")
    local violations=0
    for p in "${forbidden[@]}"; do
        local hits; hits=$(git ls-files "$p" 2>/dev/null | grep -v ".example" || true)
        [[ -n "$hits" ]] && { echo "  ❌ Tracked: $p"; ((violations++)) || true; }
    done
    [[ "$violations" -eq 0 ]] && verdict PASS "No forbidden files tracked" || verdict FAIL "$violations forbidden patterns"
}

# ══════════════════════════════════════════════════════════════════════════════
# §11: DOC LINK INTEGRITY
# ══════════════════════════════════════════════════════════════════════════════
audit_doc_links() {
    section_start "doc_link_integrity" "Scan docs/*.md for broken internal links"
    cd "$REPO_ROOT"
    local broken=0 checked=0
    while IFS= read -r mdfile; do
        while IFS= read -r link; do
            ((checked++)) || true
            local resolved="$(dirname "$mdfile")/$link"
            resolved="${resolved%%#*}"; resolved="${resolved%%\?*}"
            [[ -n "$resolved" ]] && [[ ! -e "$resolved" ]] && { echo "  BROKEN: $mdfile → $link"; ((broken++)) || true; }
        done < <(grep -oE '\[([^]]*)\]\(([^)]+)\)' "$mdfile" 2>/dev/null | sed -E 's/.*\]\(([^)]+)\).*/\1/' | grep -vE '^(https?://|mailto:|#)' || true)
    done < <(find "$REPO_ROOT/docs" -name "*.md" -type f 2>/dev/null | head -200)
    echo "  Links checked: $checked"
    [[ "$broken" -eq 0 ]] && verdict PASS "All doc links resolve" || verdict FAIL "$broken broken links"
}

# ══════════════════════════════════════════════════════════════════════════════
# §12: BINARY SIZE BUDGET
# ══════════════════════════════════════════════════════════════════════════════
audit_binary_size() {
    section_start "binary_size_budget" "Enforce max binary size (60MB) to detect dependency bloat"
    cd "$REPO_ROOT"
    local MAX=60 binary="$REPO_ROOT/helm"
    if [[ ! -f "$binary" ]]; then
        CGO_ENABLED=0 go build -ldflags="-s -w" -o "$binary" ./core/cmd/helm 2>/dev/null || { verdict SKIP "Could not build"; return; }
    fi
    local bytes; bytes=$(wc -c < "$binary" 2>/dev/null || echo 0)
    local mb=$((bytes / 1048576)); echo "  Binary: ${mb}MB"
    [[ "$mb" -lt "$MAX" ]] && verdict PASS "${mb}MB within ${MAX}MB budget" || verdict FAIL "${mb}MB exceeds budget"
}

# ══════════════════════════════════════════════════════════════════════════════
# §13: ORPHAN PACKAGES
# ══════════════════════════════════════════════════════════════════════════════
audit_orphan_packages() {
    section_start "orphan_packages" "Detect Go packages never imported by anything"
    cd "$REPO_ROOT"
    local all_pkgs; all_pkgs=$(go list ./... 2>/dev/null | grep -v "_test" || true)
    local all_imports; all_imports=$(go list -f '{{range .Imports}}{{.}} {{end}}' ./... 2>/dev/null | tr ' ' '\n' | sort -u || true)
    local test_imports; test_imports=$(go list -f '{{range .TestImports}}{{.}} {{end}}{{range .XTestImports}}{{.}} {{end}}' ./... 2>/dev/null | tr ' ' '\n' | sort -u || true)
    local combined; combined=$(printf '%s\n%s' "$all_imports" "$test_imports" | sort -u)
    local orphans=()
    while IFS= read -r pkg; do
        [[ "$pkg" == *"/cmd/"* || "$pkg" == *"/tests"* || "$pkg" == *"/e2e/"* || "$pkg" == *"/tools/"* || "$pkg" == *"/examples/"* ]] && continue
        echo "$combined" | grep -qF "$pkg" || orphans+=("$pkg")
    done <<< "$all_pkgs"
    echo "  Total: $(echo "$all_pkgs" | wc -l | tr -d ' '), Orphans: ${#orphans[@]}"
    [[ ${#orphans[@]} -gt 0 ]] && printf '    %s\n' "${orphans[@]}" | head -15
    [[ ${#orphans[@]} -eq 0 ]] && verdict PASS "No orphans" || verdict FAIL "${#orphans[@]} orphan packages"
}

# ══════════════════════════════════════════════════════════════════════════════
# §14: INTERFACE-IMPLEMENTATION DRIFT
# ══════════════════════════════════════════════════════════════════════════════
audit_interface_drift() {
    section_start "interface_impl_drift" "Detect interfaces with no implementation"
    cd "$REPO_ROOT"
    local allow_file="$BASELINES_DIR/interface_drift.allowlist"
    [[ -f "$allow_file" ]] || { verdict FAIL "Missing baseline file: ${allow_file#$REPO_ROOT/}"; return; }

    local interfaces; interfaces=$(grep -rnE '^type [A-Z][A-Za-z0-9]+ interface \{' --include="*.go" core/ 2>/dev/null | grep -v "_test.go" || true)
    local total; total=$(echo "$interfaces" | grep -c "interface" 2>/dev/null || echo 0)
    local unimpl=() unimpl_keys=()
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        local name; name=$(echo "$line" | grep -oE 'type [A-Z][A-Za-z0-9]+' | awk '{print $2}')
        [[ -z "$name" || "$name" =~ ^(Stringer|Error|Reader|Writer|Closer|Handler)$ ]] && continue
        local refs; refs=$(grep -rlF "$name" --include="*.go" core/ 2>/dev/null | grep -v "_test.go" | wc -l | tr -d ' ')
        if [[ "$refs" -le 1 ]]; then
            local file; file=$(echo "$line" | cut -d: -f1)
            unimpl+=("${name} (${file})")
            unimpl_keys+=("${name}|${file}")
        fi
    done <<< "$interfaces"

    local allowed=()
    while IFS= read -r line; do
        [[ -n "$line" ]] && allowed+=("$line")
    done < <(load_allowlist "$allow_file" || true)

    local unexpected=()
    local item
    for item in "${unimpl_keys[@]}"; do
        in_array "$item" "${allowed[@]}" || unexpected+=("$item")
    done

    local resolved_baseline=0
    for item in "${allowed[@]}"; do
        in_array "$item" "${unimpl_keys[@]}" || ((resolved_baseline++)) || true
    done

    echo "  Interfaces: $total, Flagged: ${#unimpl_keys[@]}, Unexpected: ${#unexpected[@]}, Baseline resolved: $resolved_baseline"
    [[ ${#unexpected[@]} -gt 0 ]] && printf '    %s\n' "${unexpected[@]}" | head -15

    if [[ ${#unexpected[@]} -eq 0 ]]; then
        verdict PASS "No unexpected interface drift"
    else
        verdict FAIL "${#unexpected[@]} unexpected interface drift findings"
    fi
}

# ══════════════════════════════════════════════════════════════════════════════
# §15: ENV VAR DRIFT
# ══════════════════════════════════════════════════════════════════════════════
audit_env_drift() {
    section_start "env_var_drift" "Detect env vars used in code but undocumented"
    cd "$REPO_ROOT"
    local env_file=""
    for f in ".env.example" ".env.release"; do
        [[ -f "$REPO_ROOT/$f" ]] && env_file="$REPO_ROOT/$f" && break
    done
    [[ -z "$env_file" ]] && { verdict SKIP "No .env.example or .env.release found"; return; }
    local code_vars; code_vars=$(grep -rohE '(os\.Getenv|os\.LookupEnv)\("([A-Z_][A-Z0-9_]+)"\)' --include="*.go" core/ apps/ 2>/dev/null | grep -oE '"[A-Z_][A-Z0-9_]+"' | tr -d '"' | sort -u || true)
    local doc_vars; doc_vars=$(grep -oE '^[A-Z_][A-Z0-9_]+' "$env_file" | sort -u)
    local undoc=()
    while IFS= read -r var; do
        [[ -z "$var" || "$var" =~ ^(HOME|PATH|USER|SHELL|TERM|LANG|TZ|TMPDIR|GOPATH|GOROOT)$ ]] && continue
        echo "$doc_vars" | grep -qF "$var" || undoc+=("$var")
    done <<< "$code_vars"
    echo "  In code: $(echo "$code_vars" | wc -l | tr -d ' '), Documented: $(echo "$doc_vars" | wc -l | tr -d ' '), Undocumented: ${#undoc[@]}"
    [[ ${#undoc[@]} -gt 0 ]] && printf '    %s\n' "${undoc[@]}" | head -15
    [[ ${#undoc[@]} -eq 0 ]] && verdict PASS "All documented" || verdict FAIL "${#undoc[@]} env vars missing from docs"
}

# ══════════════════════════════════════════════════════════════════════════════
# §16: SCHEMA-CODE DRIFT
# ══════════════════════════════════════════════════════════════════════════════
audit_schema_code_drift() {
    section_start "schema_code_drift" "Detect schemas never referenced in code"
    cd "$REPO_ROOT"
    [[ ! -d "$REPO_ROOT/schemas" ]] && { verdict SKIP "No schemas/"; return; }
    local unreferenced=() total=0
    while IFS= read -r f; do
        ((total++)) || true
        local bn; bn=$(basename "$f" .json)
        local refs; refs=$(grep -rlF "$bn" --include="*.go" --include="*.ts" core/ apps/ 2>/dev/null | head -1 || true)
        [[ -z "$refs" ]] && unreferenced+=("${f#$REPO_ROOT/}")
    done < <(find "$REPO_ROOT/schemas" -name "*.json" -type f 2>/dev/null)
    echo "  Total: $total, Unreferenced: ${#unreferenced[@]}"
    [[ ${#unreferenced[@]} -eq 0 ]] && verdict PASS "All referenced" || verdict FAIL "${#unreferenced[@]}/$total unreferenced schemas"
}

# ══════════════════════════════════════════════════════════════════════════════
# §17: TEST ORPHANS
# ══════════════════════════════════════════════════════════════════════════════
audit_test_orphans() {
    section_start "test_orphans" "Detect test files testing code that no longer exists"
    cd "$REPO_ROOT"
    local orphans=()
    while IFS= read -r t; do
        local dir; dir="$(dirname "$t")"
        local has_src; has_src=$(find "$dir" -maxdepth 1 -name "*.go" -not -name "*_test.go" 2>/dev/null | head -1)
        [[ -z "$has_src" ]] && orphans+=("${t#$REPO_ROOT/}")
    done < <(find "$REPO_ROOT/core" -name "*_test.go" -type f 2>/dev/null)
    [[ ${#orphans[@]} -eq 0 ]] && verdict PASS "No orphan tests" || { printf '    %s\n' "${orphans[@]}"; verdict FAIL "${#orphans[@]} orphan test files"; }
}

# ══════════════════════════════════════════════════════════════════════════════
# §18: API ROUTE COVERAGE
# ══════════════════════════════════════════════════════════════════════════════
audit_api_route_coverage() {
    section_start "api_route_coverage" "Detect API routes never exercised in tests"
    cd "$REPO_ROOT"
    local allow_file="$BASELINES_DIR/untested_routes.allowlist"
    [[ -f "$allow_file" ]] || { verdict FAIL "Missing baseline file: ${allow_file#$REPO_ROOT/}"; return; }

    local routes; routes=$(grep -rnE '(HandleFunc|Handle\(|\.GET\(|\.POST\(|\.PUT\(|\.DELETE\(|\.PATCH\()' --include="*.go" core/ 2>/dev/null | grep -v "_test.go" || true)
    local paths; paths=$(echo "$routes" | grep -oE '"(/[^"]*)"' | tr -d '"' | sort -u || true)
    local untested=()
    while IFS= read -r p; do
        [[ -z "$p" ]] && continue
        local t; t=$(grep -rlF "$p" --include="*_test.go" core/ 2>/dev/null | head -1 || true)
        [[ -z "$t" ]] && untested+=("$p")
    done <<< "$paths"

    local allowed=()
    while IFS= read -r line; do
        [[ -n "$line" ]] && allowed+=("$line")
    done < <(load_allowlist "$allow_file" || true)

    local unexpected=()
    local p
    for p in "${untested[@]}"; do
        in_array "$p" "${allowed[@]}" || unexpected+=("$p")
    done

    local resolved_baseline=0
    for p in "${allowed[@]}"; do
        in_array "$p" "${untested[@]}" || ((resolved_baseline++)) || true
    done

    echo "  Paths: $(echo "$paths" | wc -l | tr -d ' '), Untested: ${#untested[@]}, Unexpected: ${#unexpected[@]}, Baseline resolved: $resolved_baseline"
    [[ ${#unexpected[@]} -gt 0 ]] && printf '    %s\n' "${unexpected[@]}" | head -15

    if [[ ${#unexpected[@]} -eq 0 ]]; then
        verdict PASS "No unexpected untested API routes"
    else
        verdict FAIL "${#unexpected[@]} unexpected untested API routes"
    fi
}

# ══════════════════════════════════════════════════════════════════════════════
# §19: STALE TODOs
# ══════════════════════════════════════════════════════════════════════════════
audit_stale_todos() {
    section_start "stale_todos" "Surface TODO/FIXME/HACK comments"
    cd "$REPO_ROOT"
    local todo fixme hack
    todo=$(grep -rcE '(//|#)\s*TODO' --include="*.go" --include="*.ts" --include="*.sh" core/ scripts/ 2>/dev/null | awk -F: '{s+=$NF}END{print s+0}')
    fixme=$(grep -rcE '(//|#)\s*FIXME' --include="*.go" --include="*.ts" --include="*.sh" core/ scripts/ 2>/dev/null | awk -F: '{s+=$NF}END{print s+0}')
    hack=$(grep -rcE '(//|#)\s*(HACK|XXX)' --include="*.go" --include="*.ts" --include="*.sh" core/ scripts/ 2>/dev/null | awk -F: '{s+=$NF}END{print s+0}')
    local total=$((todo + fixme + hack))
    echo "  TODO: $todo, FIXME: $fixme, HACK/XXX: $hack, Total: $total"
    [[ "$total" -eq 0 ]] && verdict PASS "0 markers" || verdict FAIL "$total markers — tech debt"
}

# ══════════════════════════════════════════════════════════════════════════════
# §20: SDK PARITY
# ══════════════════════════════════════════════════════════════════════════════
audit_sdk_parity() {
    section_start "sdk_parity" "Check that all SDK languages exist and have basic structure"
    cd "$REPO_ROOT"
    local sdk_dir="$REPO_ROOT/sdk"
    [[ ! -d "$sdk_dir" ]] && { verdict SKIP "No sdk/ directory"; return; }
    local expected=("go" "ts" "python" "rust")
    local missing=()
    for lang in "${expected[@]}"; do
        [[ ! -d "$sdk_dir/$lang" ]] && missing+=("$lang")
    done
    echo "  Expected SDKs: ${expected[*]}"
    echo "  Missing: ${missing[*]:-none}"
    [[ ${#missing[@]} -eq 0 ]] && verdict PASS "All SDK languages present" || verdict FAIL "${#missing[@]} SDK languages missing: ${missing[*]}"
}

# ══════════════════════════════════════════════════════════════════════════════
# §21: EXAMPLES SMOKE CHECK
# ══════════════════════════════════════════════════════════════════════════════
audit_examples() {
    section_start "examples_check" "Verify examples/ directory has runnable content"
    cd "$REPO_ROOT"
    [[ ! -d "$REPO_ROOT/examples" ]] && { verdict SKIP "No examples/"; return; }
    local count; count=$(find "$REPO_ROOT/examples" -type f -not -name "*.md" | wc -l | tr -d ' ')
    local has_readme=false
    [[ -f "$REPO_ROOT/examples/README.md" ]] && has_readme=true
    echo "  Example files: $count, Has README: $has_readme"
    [[ "$count" -gt 0 ]] && verdict PASS "$count example files present" || verdict FAIL "examples/ exists but is empty"
}

# ══════════════════════════════════════════════════════════════════════════════
# §22: DEPENDENCY FRESHNESS
# ══════════════════════════════════════════════════════════════════════════════
audit_dep_freshness() {
    section_start "dep_freshness" "Check for deprecated dependencies"
    cd "$REPO_ROOT"
    local gomod; gomod=$(find "$REPO_ROOT" -maxdepth 2 -name "go.mod" -not -path "*/vendor/*" | head -1)
    [[ -z "$gomod" ]] && { verdict SKIP "No go.mod found"; return; }
    local direct; direct=$(grep -cE '^\t[a-z]' "$gomod" | head -1 || echo 0)
    echo "  Direct dependencies: $direct"
    local deprecated=()
    for dep in "github.com/pkg/errors" "io/ioutil"; do
        grep -q "$dep" "$gomod" 2>/dev/null && deprecated+=("$dep (in go.mod)")
    done
    local ioutil; ioutil=$(grep -rlF "io/ioutil" --include="*.go" core/ 2>/dev/null | wc -l | tr -d ' ')
    [[ "$ioutil" -gt 0 ]] && deprecated+=("io/ioutil ($ioutil files)")
    [[ ${#deprecated[@]} -eq 0 ]] && verdict PASS "No deprecated deps" || { printf '    %s\n' "${deprecated[@]}"; verdict FAIL "${#deprecated[@]} deprecated dependencies"; }
}

# ══════════════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════════════

declare -a ALL_SECTIONS=(
    audit_go_mod_tidy
    audit_go_vet
    audit_govulncheck
    audit_golangci_lint
    audit_coverage_gate
    audit_structured_logging
    audit_secret_scan
    audit_schema_validation
    audit_dockerfile
    audit_forbidden_patterns
    audit_doc_links
    audit_binary_size
    audit_orphan_packages
    audit_interface_drift
    audit_env_drift
    audit_schema_code_drift
    audit_test_orphans
    audit_api_route_coverage
    audit_stale_todos
    audit_sdk_parity
    audit_examples
    audit_dep_freshness
)

print_summary() {
    echo ""
    echo -e "${BOLD}╔══════════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BOLD}║                OSS AUDIT SUMMARY                               ║${NC}"
    echo -e "${BOLD}╠══════════════════════════════════════════════════════════════════════════╣${NC}"
    echo -e "${BOLD}║${NC}  Sections:  ${BOLD}$TOTAL_SECTIONS${NC}"
    echo -e "${BOLD}║${NC}  ${GREEN}PASS${NC}: $PASS_COUNT  ${RED}FAIL${NC}: $FAIL_COUNT  ${YELLOW}WARN${NC}: $WARN_COUNT  ${YELLOW}SKIP${NC}: $SKIP_COUNT"
    echo -e "${BOLD}║${NC}  Git SHA:   $GIT_SHA"
    echo -e "${BOLD}║${NC}  Timestamp: $TIMESTAMP"
    echo -e "${BOLD}╠══════════════════════════════════════════════════════════════════════════╣${NC}"
    [[ "$FAIL_COUNT" -eq 0 ]] && echo -e "${BOLD}║${NC}  ${GREEN}${BOLD}VERDICT: OSS REPO IS COMPLIANT${NC}" || echo -e "${BOLD}║${NC}  ${RED}${BOLD}VERDICT: $FAIL_COUNT FAILURES — NOT COMPLIANT${NC}"
    echo -e "${BOLD}╚══════════════════════════════════════════════════════════════════════════╝${NC}"
    cat > "$EVIDENCE_DIR/_summary.json" <<EOF
{"timestamp":"$TIMESTAMP","git_sha":"$GIT_SHA","sections":$TOTAL_SECTIONS,"pass":$PASS_COUNT,"fail":$FAIL_COUNT,"warn":$WARN_COUNT,"skip":$SKIP_COUNT,"verdict":"$([ "$FAIL_COUNT" -eq 0 ] && echo "COMPLIANT" || echo "NOT_COMPLIANT")"}
EOF
}

main() {
    echo -e "${BOLD}${CYAN}"
    echo "╔══════════════════════════════════════════════════════════════════════════╗"
    echo "║         HELM OSS — Repository Audit                          ║"
    echo "║         Open-source edition (no commercial tier)                        ║"
    echo "╚══════════════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    cd "$REPO_ROOT"
    case "${1:-all}" in
        --list) echo "Available sections:"; for fn in "${ALL_SECTIONS[@]}"; do echo "  ${fn#audit_}"; done; exit 0 ;;
        --section) local fn="audit_${2:-}"; declare -f "$fn" &>/dev/null && { "$fn"; print_summary; } || { echo "Unknown: ${2:-}"; exit 1; } ;;
        all|"") for fn in "${ALL_SECTIONS[@]}"; do "$fn" || true; done; print_summary ;;
        *) echo "Usage: $0 [--list | --section <name> | all]"; exit 1 ;;
    esac
    exit "$FAIL_COUNT"
}

main "$@"
