#!/usr/bin/env bash
# Blocking security gates, each with a positive control that runs first.
#
#   security_gates.sh gosec        golangci-lint (gosec only) over core and sdk/go
#   security_gates.sh gitleaks     secret scan of the tracked tree
#   security_gates.sh govulncheck  reachable Go vulnerabilities in every go.mod
#   security_gates.sh pip-audit    Python SDK runtime requirements
#
# Before scanning the repo, each gate scans a throwaway fixture that contains
# exactly what it exists to catch, and exits 2 unless the fixture is flagged. A
# scanner that reports nothing because it broke, was misconfigured, or lost a
# rule is then a failure, not a clean result.
#
# Findings present when a gate landed are listed in a frozen allowlist
# (scripts/ci/<gate>-allowlist.txt; gosec and gitleaks only). A finding not on
# the list fails the gate, and so does a listed finding that no longer occurs:
# the list can only shrink. govulncheck and pip-audit had no findings and have
# no allowlist.
#
# Tools are pinned by version and, for downloaded binaries, by sha256. They are
# cached under ${HELM_CI_TOOLS:-$HOME/.cache/helm-ci-tools}.
#
# quantum_posture: this gate scans for leaked key material; it makes no
# cryptographic algorithm choice.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TOOLS="${HELM_CI_TOOLS:-$HOME/.cache/helm-ci-tools}"
FINDINGS="$ROOT/scripts/ci/security_findings.py"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/helm-security-gate.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

GITLEAKS_VERSION=8.30.1
GOLANGCI_VERSION=2.13.2
GOVULNCHECK_VERSION=v1.3.0

platform() {
    case "$(uname -s)/$(uname -m)" in
        Linux/x86_64) echo linux-amd64 ;;
        Darwin/arm64) echo darwin-arm64 ;;
        *) echo "::error::no pinned security tools for $(uname -s)/$(uname -m)" >&2; return 1 ;;
    esac
}

# fetch URL SHA256 DEST: download once, verify, keep.
fetch() {
    local url="$1" sha="$2" dest="$3"
    if [ ! -f "$dest" ]; then
        mkdir -p "$(dirname "$dest")"
        curl -fsSL -o "$dest.partial" "$url"
        mv "$dest.partial" "$dest"
    fi
    if ! printf '%s  %s\n' "$sha" "$dest" | shasum -a 256 -c - >/dev/null; then
        rm -f "$dest"
        echo "::error::sha256 mismatch for $url" >&2
        return 1
    fi
}

tool_gitleaks() {
    local plat sha asset
    plat="$(platform)"
    case "$plat" in
        linux-amd64) asset=linux_x64; sha=551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb ;;
        darwin-arm64) asset=darwin_arm64; sha=b40ab0ae55c505963e365f271a8d3846efbc170aa17f2607f13df610a9aeb6a5 ;;
    esac
    local dir="$TOOLS/gitleaks-$GITLEAKS_VERSION-$plat"
    fetch "https://github.com/gitleaks/gitleaks/releases/download/v$GITLEAKS_VERSION/gitleaks_${GITLEAKS_VERSION}_${asset}.tar.gz" "$sha" "$dir/gitleaks.tar.gz" >&2
    [ -x "$dir/gitleaks" ] || tar -xzf "$dir/gitleaks.tar.gz" -C "$dir" gitleaks
    echo "$dir/gitleaks"
}

tool_golangci() {
    local plat sha
    plat="$(platform)"
    case "$plat" in
        linux-amd64) sha=2277d43b98ec0054280f2ac26b53268bae97682444678a59a657dd565da021d6 ;;
        darwin-arm64) sha=f4bf83f0b64f055c42b28fc9a38861839f69c096e61c788e72dfaae412011789 ;;
    esac
    local dir="$TOOLS/golangci-lint-$GOLANGCI_VERSION-$plat"
    fetch "https://github.com/golangci/golangci-lint/releases/download/v$GOLANGCI_VERSION/golangci-lint-$GOLANGCI_VERSION-$plat.tar.gz" "$sha" "$dir/golangci-lint.tar.gz" >&2
    [ -x "$dir/golangci-lint" ] || tar -xzf "$dir/golangci-lint.tar.gz" -C "$dir" --strip-components 1 "golangci-lint-$GOLANGCI_VERSION-$plat/golangci-lint"
    echo "$dir/golangci-lint"
}

tool_govulncheck() {
    local dir="$TOOLS/govulncheck-$GOVULNCHECK_VERSION"
    [ -x "$dir/govulncheck" ] || GOBIN="$dir" GOWORK=off go install "golang.org/x/vuln/cmd/govulncheck@$GOVULNCHECK_VERSION" >&2
    echo "$dir/govulncheck"
}

tool_pip_audit() {
    local requirements="$ROOT/.github/pip-audit-requirements.txt"
    local dir
    dir="$TOOLS/pip-audit-$(shasum -a 256 "$requirements" | cut -c1-12)"
    if [ ! -x "$dir/bin/pip-audit" ]; then
        python3 -m venv "$dir" >&2
        "$dir/bin/python" -m pip install --quiet --only-binary=:all: --require-hashes -r "$requirements" >&2
    fi
    echo "$dir/bin/pip-audit"
}

control_failed() {
    echo "::error::$1 positive control failed: $2. The gate cannot tell a finding from a clean tree, so it reports nothing." >&2
    exit 2
}

# ---------------------------------------------------------------------------

gate_gosec() {
    local lint
    lint="$(tool_golangci)"
    # golangci-lint only: a report with the given modules' gosec findings.
    run_gosec() { # module_dir report
        (cd "$1" && GOOS=linux GOARCH=amd64 CGO_ENABLED=0 "$lint" run --enable-only gosec --path-mode abs --timeout 20m \
            --max-issues-per-linter 0 --max-same-issues 0 --issues-exit-code 0 \
            --output.json.path "$2" --output.text.path /dev/null ./...)
    }

    local control="$WORK/gosec-control"
    mkdir -p "$control"
    printf 'module example.com/goseccontrol\n\ngo 1.25\n' >"$control/go.mod"
    cat >"$control/main.go" <<'GO'
package main

import (
	"crypto/md5"
	"os"
	"os/exec"
)

func main() {
	_ = exec.Command(os.Args[1]).Run()
	_ = md5.Sum([]byte(os.Args[2]))
}
GO
    GOWORK=off run_gosec "$control" "$WORK/gosec-control.json"
    local rules
    rules="$(python3 "$FINDINGS" gosec-keys "$WORK/gosec-control.json" "$control" | cut -d' ' -f1 | sort -u | tr '\n' ' ')"
    for rule in G204 G401; do
        case " $rules" in *" $rule "*) ;; *) control_failed gosec "the fixture's $rule was not reported (got: $rules)" ;; esac
    done
    echo "gosec control: flagged $rules"

    : >"$WORK/gosec.keys"
    for module in core sdk/go; do
        echo "==> gosec $module"
        run_gosec "$ROOT/$module" "$WORK/gosec.json"
        python3 "$FINDINGS" gosec-keys "$WORK/gosec.json" "$ROOT" >>"$WORK/gosec.keys"
    done
    python3 "$FINDINGS" compare "$ROOT/scripts/ci/gosec-allowlist.txt" "$WORK/gosec.keys"
}

gate_gitleaks() {
    local gitleaks config="$ROOT/.gitleaks.toml"
    gitleaks="$(tool_gitleaks)"

    # Synthetic keys, generated here so the repository never contains one.
    local control="$WORK/gitleaks-control"
    mkdir -p "$control"
    python3 - "$control/leak.env" <<'PY'
import secrets, string, sys
alnum = string.ascii_letters + string.digits
word = alnum + "_"
def rand(chars, n): return "".join(secrets.choice(chars) for _ in range(n))
body = "\n".join(rand(alnum, 64) for _ in range(4))
with open(sys.argv[1], "w") as fh:
    fh.write(f"OPENROUTER_API_KEY=sk-or-v1-{secrets.token_hex(32)}\n")
    fh.write(f"OPENAI_API_KEY=sk-proj-{rand(alnum + '_-', 58)}T3BlbkFJ{rand(alnum + '_-', 58)}\n")
    fh.write(f"GITHUB_TOKEN=github_pat_{rand(word, 82)}\n")
    fh.write(f"HELM_SIGNING_KEY={secrets.token_hex(32)}\n")
    fh.write(f"-----BEGIN PGP PRIVATE KEY BLOCK-----\n\n{body}\n-----END PGP PRIVATE KEY BLOCK-----\n")
PY
    "$gitleaks" dir "$control" --config "$config" --no-banner --log-level error \
        --report-format json --report-path "$WORK/gitleaks-control.json" --exit-code 0
    local rules
    rules="$(python3 "$FINDINGS" gitleaks-keys "$WORK/gitleaks-control.json" | cut -d' ' -f1 | sort -u | tr '\n' ' ')"
    for rule in openrouter-api-key openai-project-key github-fine-grained-pat helm-signing-seed private-key; do
        case " $rules" in *" $rule "*) ;; *) control_failed gitleaks "the planted $rule key was not reported (got: $rules)" ;; esac
    done
    echo "gitleaks control: flagged $rules"

    # Scan exactly the tracked files, at their working-tree content.
    local tree="$WORK/tree"
    mkdir -p "$tree"
    (cd "$ROOT" && git ls-files -z | tar --null -T - -cf -) | tar -xf - -C "$tree"
    (cd "$tree" && "$gitleaks" dir . --config "$config" --no-banner --log-level error \
        --report-format json --report-path "$WORK/gitleaks.json" --exit-code 0)
    python3 "$FINDINGS" gitleaks-keys "$WORK/gitleaks.json" >"$WORK/gitleaks.keys"
    python3 "$FINDINGS" compare "$ROOT/scripts/ci/gitleaks-allowlist.txt" "$WORK/gitleaks.keys"
}

gate_govulncheck() {
    local govulncheck
    govulncheck="$(tool_govulncheck)"

    # golang.org/x/text before v0.3.7 has GO-2021-0113 in language.Parse.
    local control="$WORK/govulncheck-control"
    mkdir -p "$control"
    printf 'module example.com/govulncheckcontrol\n\ngo 1.25\n\nrequire golang.org/x/text v0.3.6\n' >"$control/go.mod"
    printf 'package main\n\nimport "golang.org/x/text/language"\n\nfunc main() { _, _ = language.Parse("en") }\n' >"$control/main.go"
    (cd "$control" && GOWORK=off GOFLAGS=-mod=mod go mod tidy >/dev/null 2>&1) || control_failed govulncheck "could not resolve the fixture module"
    (cd "$control" && GOWORK=off "$govulncheck" -format json ./... >"$WORK/govulncheck-control.json") || true
    local called
    called="$(python3 "$FINDINGS" govulncheck-called "$WORK/govulncheck-control.json" | tr '\n' ' ')"
    case " $called" in *" GO-2021-0113 "*) ;; *) control_failed govulncheck "GO-2021-0113 in the fixture was not reported (got: $called)" ;; esac
    echo "govulncheck control: flagged $called"

    local modules status=0 count=0
    modules="$(git -C "$ROOT" ls-files ':(glob)**/go.mod' | xargs -n1 dirname | sort -u)"
    for module in $modules; do
        count=$((count + 1))
        echo "==> govulncheck $module"
        (cd "$ROOT/$module" && GOWORK=off "$govulncheck" -format json ./... >"$WORK/govulncheck.json") || true
        called="$(python3 "$FINDINGS" govulncheck-called "$WORK/govulncheck.json")" || { status=1; continue; }
        if [ -n "$called" ]; then
            echo "::error::$module calls vulnerable code: $(echo "$called" | tr '\n' ' ')"
            (cd "$ROOT/$module" && GOWORK=off "$govulncheck" ./...) || true
            status=1
        fi
    done
    [ "$count" -gt 0 ] || { echo "::error::no go.mod files found"; exit 2; }
    echo "govulncheck: $count module(s) scanned"
    return "$status"
}

gate_pip_audit() {
    local pip_audit
    pip_audit="$(tool_pip_audit)"

    # Jinja2 2.10 has several published advisories.
    printf 'jinja2==2.10\n' >"$WORK/pip-audit-control.txt"
    if "$pip_audit" -r "$WORK/pip-audit-control.txt" --no-deps --disable-pip --progress-spinner off >"$WORK/pip-audit-control.log" 2>&1; then
        control_failed pip-audit "jinja2==2.10 was reported clean"
    fi
    grep -q 'jinja2' "$WORK/pip-audit-control.log" || control_failed pip-audit "the audit failed without naming jinja2: $(tail -3 "$WORK/pip-audit-control.log")"
    echo "pip-audit control: flagged jinja2==2.10"

    # --disable-pip audits exactly the pinned, hashed versions without installing them.
    "$pip_audit" -r "$ROOT/sdk/python/requirements-runtime.txt" --require-hashes --disable-pip --progress-spinner off
}

case "${1:-}" in
    gosec) gate_gosec ;;
    gitleaks) gate_gitleaks ;;
    govulncheck) gate_govulncheck ;;
    pip-audit) gate_pip_audit ;;
    *) sed -n '2,8p' "$0" >&2; exit 2 ;;
esac
