#!/usr/bin/env bash
# HELM-151 / GATE 1 — contract breaking-change gate.
#
# Diffs an API contract surface against its required baseline and fails on a
# backward-incompatible change, so a break cannot merge or release silently
# while the version number claims compatibility. A source-controlled version
# bump remains the only compatibility escape: a major bump, or a minor bump
# while the version is still 0.y.z (semver §4). Mutable PR labels and
# environment variables never downgrade this gate.
#
# Usage: contract_breaking.sh <openapi|proto> [base|release]
# "base" (default) compares against the exact remote PR base named by
# GITHUB_BASE_REF (default: main). "release" compares against the commit
# resolved from the nearest prior version tag, never current origin/main.
set -euo pipefail

kind="${1:?usage: contract_breaking.sh <openapi|proto>}"
baseline_mode="${2:-base}"
base_ref="${GITHUB_BASE_REF:-main}"

case "$kind" in
openapi | proto) ;;
*)
  echo "unknown kind: ${kind} (expected: openapi | proto)" >&2
  exit 2
  ;;
esac

case "$baseline_mode" in
base | release) ;;
*)
  echo "unknown contract-gate baseline mode: ${baseline_mode} (expected: base | release)" >&2
  exit 2
  ;;
esac

resolve_pr_base() {
  if ! git check-ref-format --branch "$base_ref" >/dev/null 2>&1; then
    echo "::error::invalid contract-gate base ref: ${base_ref}" >&2
    exit 2
  fi

  base="origin/${base_ref}"
  if ! git fetch --quiet --no-tags origin "refs/heads/${base_ref}:refs/remotes/origin/${base_ref}"; then
    echo "::error::unable to resolve contract-gate base ref origin/${base_ref}" >&2
    exit 2
  fi
  if ! git rev-parse --verify --quiet "${base}^{commit}" >/dev/null 2>&1; then
    echo "::error::resolved contract-gate base ref is not a commit: ${base}" >&2
    exit 2
  fi
  base_label="$base"
}

resolve_release_base() {
  if ! head="$(git rev-parse --verify 'HEAD^{commit}')"; then
    echo "::error::unable to resolve release contract-gate HEAD" >&2
    exit 2
  fi
  if ! current_version="$(tr -d '[:space:]' < VERSION)"; then
    echo "::error::missing VERSION for release contract-gate baseline" >&2
    exit 2
  fi

  current_tag="v${current_version}"
  start="$head"
  if current_tag_commit="$(git rev-parse --verify --quiet "${current_tag}^{commit}")"; then
    if [ "$current_tag_commit" = "$head" ]; then
      if ! start="$(git rev-parse --verify "${head}^")"; then
        echo "::error::release contract-gate has no commit before ${current_tag}" >&2
        exit 2
      fi
    fi
  fi
  if ! prior_tag="$(git describe --tags --abbrev=0 --match 'v[0-9]*' "$start" 2>/dev/null)"; then
    echo "::error::unable to resolve an immutable prior release tag for contract-gate" >&2
    exit 2
  fi
  if ! base="$(git rev-parse --verify --quiet "${prior_tag}^{commit}")"; then
    echo "::error::prior release tag ${prior_tag} does not resolve to a commit" >&2
    exit 2
  fi
  base_label="${prior_tag} (${base})"
  echo "contract release baseline: ${base_label}"
}

case "$baseline_mode" in
base) resolve_pr_base ;;
release) resolve_release_base ;;
esac

major() { printf '%s' "${1%%.*}"; }              # "1.4.0" -> "1"

# break_allowed <current> <base>: succeeds when the version bump permits a
# backward-incompatible change. A major bump always does. While both versions
# are 0.y.z, a minor bump does too: semver §4 reserves 0.y.z for initial
# development, where the minor is the compatibility boundary. A patch bump
# never does, and a non-numeric version never does.
break_allowed() {
  local cur_major base_major cur_minor base_minor
  cur_major="$(major "$1")"
  base_major="$(major "$2")"
  [[ "$cur_major" =~ ^[0-9]+$ && "$base_major" =~ ^[0-9]+$ ]] || return 1
  [ "$cur_major" -gt "$base_major" ] && return 0
  [ "$cur_major" -eq 0 ] && [ "$base_major" -eq 0 ] || return 1
  cur_minor="$(major "${1#*.}")"
  base_minor="$(major "${2#*.}")"
  [[ "$cur_minor" =~ ^[0-9]+$ && "$base_minor" =~ ^[0-9]+$ ]] || return 1
  [ "$cur_minor" -gt "$base_minor" ]
}

# $1 = surface label, $2 = differ output. Approval must be represented by
# source-controlled compatibility/versioning policy, not mutable PR data.
report_break() {
  printf '::error::%s: backward-incompatible contract change without a major bump (or a minor bump in 0.y.z)\n' "$1"
  printf '%s\n' "$2"
  printf 'Fix it or make an intentional, source-controlled version bump (major; minor while in 0.y.z).\n'
  return 1
}

# $1 = surface label, $2 = tool exit status, $3 = tool output.
report_tool_error() {
  printf '::error::%s failed with exit %s; refusing to treat a tool failure as a contract break\n' "$1" "$2"
  printf '%s\n' "$3"
}

# Buf emits exit 100 for file-annotation findings, including blocking
# compatibility results. Normalize that class to the same gate exit as an
# OpenAPI compatibility finding; all other non-zero exits are tool failures.
report_buf_finding() {
  printf '::error::%s reported a blocking contract finding\n' "$1"
  printf '%s\n' "$2"
}

# Reads the whole input (no early awk exit): under pipefail an early exit
# SIGPIPEs the writer and fails the assignment that calls this.
openapi_version() {                              # <ref-or-WORKTREE> <spec-path>; "" if absent
  { if [ "$1" = "WORKTREE" ]; then cat "$2" 2>/dev/null; else git show "$1:$2" 2>/dev/null; fi; } |
    awk '/^[^[:space:]]/ { in_info = ($1 == "info:") }
         in_info && $1 == "version:" && !found { v = $2; gsub(/["'"'"' ]/, "", v); print v; found = 1 }'
}

case "$kind" in
openapi)
  command -v oasdiff >/dev/null 2>&1 || {
    echo "::error::oasdiff is required for the openapi breaking gate (brew install oasdiff, or go install github.com/oasdiff/oasdiff@latest)"
    exit 2
  }
  specs=(api/openapi/helm.openapi.yaml protocols/specs/effects/openapi.yaml)
  broke=0
  for spec in "${specs[@]}"; do
    if ! git cat-file -e "${base}:${spec}" 2>/dev/null; then
      echo "openapi ${spec}: new on this branch (no baseline spec to diff) — skip"
      continue
    fi
    cur_version="$(openapi_version WORKTREE "$spec")"
    base_version="$(openapi_version "$base" "$spec")"
    if break_allowed "$cur_version" "$base_version"; then
      echo "openapi ${spec}: ${base_version} -> ${cur_version} — break allowed by version bump"
      continue
    fi
    base_file="$(mktemp)"
    if ! git show "${base}:${spec}" >"$base_file"; then
      rm -f "$base_file"
      echo "::error::unable to read openapi ${spec} from contract-gate baseline ${base_label}" >&2
      exit 2
    fi
    # oasdiff breaking prints changes but exits 0 by default; --fail-on ERR
    # exits 1 for an ERR-level compatibility finding. Require that exit 1 to
    # carry a non-empty JSON finding list; otherwise it is an operational
    # failure and must not be misreported as a diff.
    if out="$(oasdiff breaking "$base_file" "$spec" --fail-on ERR --format json 2>&1)"; then
      echo "openapi ${spec}: no backward-incompatible changes vs ${base_label}"
    else
      tool_exit=$?
      rm -f "$base_file"
      if [ "$tool_exit" -eq 1 ] && printf '%s' "$out" | python3 -c 'import json, sys; report = json.load(sys.stdin); raise SystemExit(0 if isinstance(report, list) and report else 1)' >/dev/null 2>&1; then
        report_break "openapi ${spec}" "$out" || broke=1
        continue
      fi
      report_tool_error "oasdiff for openapi ${spec}" "$tool_exit" "$out"
      exit 2
    fi
    rm -f "$base_file"
  done
  [ "$broke" -ne 0 ] && exit 1
  echo "GATE 1 (openapi): pass"
  ;;
proto)
  command -v buf >/dev/null 2>&1 || { echo "::error::buf is required for the proto breaking gate"; exit 2; }
  if ! current_version="$(cat VERSION 2>/dev/null)"; then
    echo "::error::missing VERSION in contract-gate worktree" >&2
    exit 2
  fi
  if ! base_version="$(git show "${base}:VERSION" 2>/dev/null)"; then
    echo "::error::missing VERSION in contract-gate baseline ${base_label}" >&2
    exit 2
  fi
  if break_allowed "$current_version" "$base_version"; then
    echo "proto: ${base_version} -> ${current_version} — break allowed by version bump"
    exit 0
  fi
  # protocols/proto is the IDL every SDK binding is generated from (HELM-747);
  # protocols/policy-schema is the CPI schema module. Each is diffed with its
  # own buf.yaml breaking rules.
  broke=0
  for module in protocols/policy-schema protocols/proto; do
    against=".git#ref=${base},subdir=${module}"
    if out="$(buf breaking "$module" --against "$against" 2>&1)"; then
      echo "proto ${module}: no backward-incompatible changes vs ${base_label}"
    else
      tool_exit=$?
      if [ "$tool_exit" -eq 100 ]; then
        report_buf_finding "buf breaking for ${module}" "$out"
        broke=1
        continue
      fi
      report_tool_error "buf breaking for ${module}" "$tool_exit" "$out"
      exit 2
    fi
  done
  [ "$broke" -ne 0 ] && exit 1
  echo "GATE 1 (proto): pass — no backward-incompatible changes vs ${base_label}"
  ;;
esac
