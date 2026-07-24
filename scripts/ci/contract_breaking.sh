#!/usr/bin/env bash
# HELM-151 / GATE 1 — contract breaking-change gate.
#
# Diffs an API contract surface against the PR's base branch and fails on a
# backward-incompatible change, so a break cannot merge silently while the
# version number claims compatibility. A source-controlled major-version bump
# remains the only compatibility escape; mutable PR labels and environment
# variables never downgrade this gate.
#
# Usage: contract_breaking.sh <openapi|proto>
# Base ref comes from GITHUB_BASE_REF (default: main). Runs locally and in CI.
set -euo pipefail

kind="${1:?usage: contract_breaking.sh <openapi|proto>}"
base_ref="${GITHUB_BASE_REF:-main}"

case "$kind" in
openapi | proto) ;;
*)
  echo "unknown kind: ${kind} (expected: openapi | proto)" >&2
  exit 2
  ;;
esac

# Resolve exactly the remote PR base. An unavailable or malformed base means
# the comparison is unknown, never that every contract is new and safe to skip.
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

major() { printf '%s' "${1%%.*}"; }              # "1.4.0" -> "1"

# $1 = surface label, $2 = differ output. Always blocks; approval must be
# represented by source-controlled compatibility/versioning policy, not PR data.
report_break() {
  printf '::error::%s: backward-incompatible contract change without a major bump\n' "$1"
  printf '%s\n' "$2"
  printf 'Fix it or make an intentional, source-controlled major-version bump.\n'
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

openapi_version() {                              # <ref-or-WORKTREE> <spec-path>; "" if absent
  { if [ "$1" = "WORKTREE" ]; then cat "$2" 2>/dev/null; else git show "$1:$2" 2>/dev/null; fi; } |
    awk '/^[^[:space:]]/ { in_info = ($1 == "info:") }
         in_info && $1 == "version:" { v = $2; gsub(/["'"'"' ]/, "", v); print v; exit }'
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
      echo "openapi ${spec}: new on this branch (no base to diff) — skip"
      continue
    fi
    cur_major="$(major "$(openapi_version WORKTREE "$spec")")"
    base_major="$(major "$(openapi_version "$base" "$spec")")"
    if [[ "$cur_major" =~ ^[0-9]+$ && "$base_major" =~ ^[0-9]+$ && "$cur_major" -gt "$base_major" ]]; then
      echo "openapi ${spec}: major ${base_major} -> ${cur_major} — break allowed by version bump"
      continue
    fi
    base_file="$(mktemp)"
    git show "${base}:${spec}" >"$base_file"
    # oasdiff `breaking` prints changes but exits 0 by default; --fail-on ERR
    # exits 1 for an ERR-level (backward-incompatible) change. Other non-zero
    # exits are execution failures and must not be misreported as a diff.
    if out="$(oasdiff breaking "$base_file" "$spec" --fail-on ERR 2>&1)"; then
      echo "openapi ${spec}: no backward-incompatible changes vs ${base}"
    else
      status=$?
      rm -f "$base_file"
      if [ "$status" -eq 1 ]; then
        report_break "openapi ${spec}" "$out" || broke=1
        continue
      fi
      report_tool_error "oasdiff for openapi ${spec}" "$status" "$out"
      exit 2
    fi
    rm -f "$base_file"
  done
  [ "$broke" -ne 0 ] && exit 1
  echo "GATE 1 (openapi): pass"
  ;;
proto)
  command -v buf >/dev/null 2>&1 || { echo "::error::buf is required for the proto breaking gate"; exit 2; }
  cur_major="$(major "$(cat VERSION 2>/dev/null || echo 0)")"
  if ! base_version="$(git show "${base}:VERSION" 2>/dev/null)"; then
    echo "::error::missing VERSION in contract-gate base ${base}" >&2
    exit 2
  fi
  base_major="$(major "$base_version")"
  if [[ "$cur_major" =~ ^[0-9]+$ && "$base_major" =~ ^[0-9]+$ && "$cur_major" -gt "$base_major" ]]; then
    echo "proto: major ${base_major} -> ${cur_major} — break allowed by version bump"
    exit 0
  fi
  against=".git#ref=${base},subdir=protocols/policy-schema"
  if out="$(buf breaking protocols/policy-schema --against "$against" 2>&1)"; then
    echo "GATE 1 (proto): pass — no backward-incompatible changes vs ${base}"
  else
    status=$?
    if [ "$status" -eq 100 ]; then
      report_buf_finding "buf breaking for protocols/policy-schema" "$out"
      exit 1
    fi
    report_tool_error "buf breaking for protocols/policy-schema" "$status" "$out"
    exit 2
  fi
  ;;
esac
