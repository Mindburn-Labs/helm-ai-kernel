#!/usr/bin/env bash
# HELM-151 / GATE 1 — contract breaking-change gate.
#
# Diffs an API contract surface against the PR's base branch and fails on a
# backward-incompatible change, so a break cannot merge silently while the
# version number claims compatibility. Two escapes, both explicit and visible:
#   * major bump   — if the contract's major version was raised, the break is
#                    intended and signalled by the version, so the gate passes.
#   * label override — CONTRACT_BREAKING_APPROVED=1 (set by CI from the
#                    `contract:breaking-approved` PR label) downgrades a failure
#                    to a warning for deliberate pre-1.0 / pre-GA churn.
#
# Usage: contract_breaking.sh <openapi|proto>
# Base ref comes from GITHUB_BASE_REF (default: main). Runs locally and in CI.
set -euo pipefail

kind="${1:?usage: contract_breaking.sh <openapi|proto>}"
base_ref="${GITHUB_BASE_REF:-main}"
approved="${CONTRACT_BREAKING_APPROVED:-0}"

# Resolve the base to something git can read (prefer the remote-tracking ref).
git fetch --quiet origin "$base_ref" 2>/dev/null || true
base="origin/${base_ref}"
git rev-parse --verify --quiet "${base}^{commit}" >/dev/null 2>&1 || base="$base_ref"

major() { printf '%s' "${1%%.*}"; }              # "1.4.0" -> "1"

is_approved() {                                  # portable lower-case (macOS bash 3.2 has no ${x,,})
  case "$(printf '%s' "$approved" | tr '[:upper:]' '[:lower:]')" in
  1 | true | yes | on) return 0 ;;
  *) return 1 ;;
  esac
}

# $1 = surface label, $2 = differ output. Blocks unless the label override is set.
report_break() {
  if is_approved; then
    printf '::warning::%s: backward-incompatible change present, overridden by the contract:breaking-approved label\n' "$1"
    printf '%s\n' "$2"
    return 0
  fi
  printf '::error::%s: backward-incompatible contract change without a major bump\n' "$1"
  printf '%s\n' "$2"
  # shellcheck disable=SC2016  # backticks are literal markdown, not a shell expansion
  printf 'Fix it, bump the major version, or add the `contract:breaking-approved` label to override.\n'
  return 1
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
  broke=1
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
    # makes it exit non-zero on an ERR-level (backward-incompatible) change.
    if out="$(oasdiff breaking "$base_file" "$spec" --fail-on ERR 2>&1)"; then
      echo "openapi ${spec}: no backward-incompatible changes vs ${base}"
    else
      report_break "openapi ${spec}" "$out" || broke=0
    fi
    rm -f "$base_file"
  done
  [ "$broke" -eq 0 ] && exit 1
  echo "GATE 1 (openapi): pass"
  ;;
proto)
  command -v buf >/dev/null 2>&1 || { echo "::error::buf is required for the proto breaking gate"; exit 2; }
  cur_major="$(major "$(cat VERSION 2>/dev/null || echo 0)")"
  base_major="$(major "$(git show "${base}:VERSION" 2>/dev/null || echo "$cur_major")")"
  if [[ "$cur_major" =~ ^[0-9]+$ && "$base_major" =~ ^[0-9]+$ && "$cur_major" -gt "$base_major" ]]; then
    echo "proto: major ${base_major} -> ${cur_major} — break allowed by version bump"
    exit 0
  fi
  against=".git#ref=${base},subdir=protocols/policy-schema"
  if out="$(buf breaking protocols/policy-schema --against "$against" 2>&1)"; then
    echo "GATE 1 (proto): pass — no backward-incompatible changes vs ${base}"
  else
    report_break "proto (protocols/policy-schema)" "$out"
  fi
  ;;
*)
  echo "unknown kind: ${kind} (expected: openapi | proto)" >&2
  exit 2
  ;;
esac
