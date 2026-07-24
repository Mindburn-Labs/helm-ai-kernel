#!/usr/bin/env bash
# Hermetic regression coverage for HELM-151 contract-breaking gate behavior.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

fail() {
  printf 'contract-breaking self-test failed: %s\n' "$*" >&2
  exit 1
}

assert_status() {
  [ "$actual_status" -eq "$1" ] || fail "expected exit $1, got $actual_status for $case_name"
}

assert_contains() {
  grep -Fq "$1" "$case_output" || fail "expected $case_name output to contain: $1"
}

assert_not_contains() {
  if grep -Fq "$1" "$case_output"; then
    fail "expected $case_name output not to contain: $1"
  fi
}

assert_invocations() {
  actual_invocations="$(wc -l < "$oasdiff_log" | tr -d '[:space:]')"
  [ "$actual_invocations" = "$1" ] || fail "expected $1 oasdiff invocation(s), got $actual_invocations for $case_name"
}

write_openapi() {
  mkdir -p "$(dirname "$1")"
  printf '%s\n' \
    'openapi: 3.0.3' \
    'info:' \
    '  title: contract gate fixture' \
    '  version: 1.0.0' \
    'paths: {}' > "$1"
}

origin="$work/origin.git"
seed="$work/seed"
feature="$work/feature"
fake_bin="$work/fake-bin"
oasdiff_log="$work/oasdiff.log"
buf_log="$work/buf.log"

git init --bare "$origin" >/dev/null
git clone "$origin" "$seed" >/dev/null
(
  cd "$seed"
  git config user.name 'HELM contract gate test'
  git config user.email 'contract-gate-test@example.invalid'
  write_openapi api/openapi/helm.openapi.yaml
  write_openapi protocols/specs/effects/openapi.yaml
  mkdir -p protocols/policy-schema
  printf '%s\n' '1.0.0' > VERSION
  git add VERSION api/openapi/helm.openapi.yaml protocols/specs/effects/openapi.yaml protocols/policy-schema
  git commit -m 'test: seed contract base' >/dev/null
  git branch -M main
  git push origin main >/dev/null
)
git clone --branch main "$origin" "$feature" >/dev/null
mkdir -p "$fake_bin"
# shellcheck disable=SC2016 # Intentional literal expansion in the generated fake executable.
printf '%s\n' \
  '#!/usr/bin/env bash' \
  'set -euo pipefail' \
  'printf "%s\\n" "$*" >> "$OASDIFF_LOG"' \
  'exit "${FAKE_OASDIFF_EXIT:-0}"' > "$fake_bin/oasdiff"
chmod 0755 "$fake_bin/oasdiff"
# shellcheck disable=SC2016 # Intentional literal expansion in the generated fake executable.
printf '%s\n' \
  '#!/usr/bin/env bash' \
  'set -euo pipefail' \
  'printf "%s\\n" "$*" >> "$BUF_LOG"' \
  'exit "${FAKE_BUF_EXIT:-0}"' > "$fake_bin/buf"
chmod 0755 "$fake_bin/buf"

run_openapi() {
  case_name="$1"
  base_ref="$2"
  fake_exit="$3"
  case_output="$work/${case_name}.out"
  : > "$oasdiff_log"
  set +e
  (
    cd "$feature"
    PATH="$fake_bin:$PATH" \
      OASDIFF_LOG="$oasdiff_log" \
      FAKE_OASDIFF_EXIT="$fake_exit" \
      GITHUB_BASE_REF="$base_ref" \
      CONTRACT_BREAKING_APPROVED=1 \
      bash "$root/scripts/ci/contract_breaking.sh" openapi
  ) > "$case_output" 2>&1
  actual_status=$?
  set -e
}

run_proto() {
  case_name="$1"
  fake_exit="$2"
  case_output="$work/${case_name}.out"
  : > "$buf_log"
  set +e
  (
    cd "$feature"
    PATH="$fake_bin:$PATH" \
      BUF_LOG="$buf_log" \
      FAKE_BUF_EXIT="$fake_exit" \
      GITHUB_BASE_REF=main \
      CONTRACT_BREAKING_APPROVED=1 \
      bash "$root/scripts/ci/contract_breaking.sh" proto
  ) > "$case_output" 2>&1
  actual_status=$?
  set -e
}

run_openapi pass main 0
assert_status 0
assert_contains 'GATE 1 (openapi): pass'
assert_invocations 2

run_openapi compatibility_break main 1
assert_status 1
assert_contains 'backward-incompatible contract change without a major bump'
assert_not_contains 'overridden by the contract:breaking-approved label'
assert_invocations 2

run_openapi tool_error main 2
assert_status 2
assert_contains 'oasdiff for openapi'
assert_not_contains 'backward-incompatible contract change without a major bump'
assert_invocations 1

run_openapi missing_base missing-base 0
assert_status 2
assert_contains 'unable to resolve contract-gate base ref origin/missing-base'
assert_invocations 0

run_proto buf_finding 100
assert_status 1
assert_contains 'reported a blocking contract finding'
assert_not_contains 'refusing to treat a tool failure'
actual_invocations="$(wc -l < "$buf_log" | tr -d '[:space:]')"
[ "$actual_invocations" = 1 ] || fail "expected 1 buf invocation, got $actual_invocations for $case_name"

run_proto buf_tool_error 2
assert_status 2
assert_contains 'buf breaking for protocols/policy-schema failed with exit 2'
assert_not_contains 'reported a blocking contract finding'
actual_invocations="$(wc -l < "$buf_log" | tr -d '[:space:]')"
[ "$actual_invocations" = 1 ] || fail "expected 1 buf invocation, got $actual_invocations for $case_name"

printf 'contract-breaking self-test passed\n'
