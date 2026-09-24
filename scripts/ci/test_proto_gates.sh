#!/usr/bin/env bash
# HELM-747: positive controls for the protocols/proto buf gates.
#
# Runs the real buf binary against copies of protocols/proto that carry its
# real buf.yaml, and runs the real release-baseline gate command against a
# tagged fixture repository. Every gate must accept a known-good tree and
# reject a known-bad one: a gate that cannot fail proves nothing (target
# architecture §13.1).
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
module="$root/protocols/proto"
check_exemptions="$root/scripts/ci/check_proto_lint_exemptions.sh"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

command -v buf >/dev/null 2>&1 || {
  echo "::error::buf is required for the proto gate self-test" >&2
  exit 2
}

fail() {
  printf 'proto gate self-test failed: %s\n' "$1" >&2
  if [ -n "${2:-}" ]; then printf '%s\n' "$2" >&2; fi
  exit 1
}

# expect <exit> <case> <needle> <command...>: run the command and require its
# exit status and, when the needle is non-empty, a substring of its output.
expect() {
  local want="$1" name="$2" needle="$3" out status
  shift 3
  set +e
  out="$("$@" 2>&1)"
  status=$?
  set -e
  [ "$status" -eq "$want" ] || fail "$name: expected exit $want, got $status" "$out"
  if [ -n "$needle" ] && [[ "$out" != *"$needle"* ]]; then
    fail "$name: output does not contain: $needle" "$out"
  fi
  printf 'ok  %s\n' "$name"
}

# copy <name>: a fresh copy of the module, buf.yaml included.
copy() {
  cp -R "$module" "$work/$1"
  printf '%s\n' "$work/$1"
}

lint() { buf lint "$1" --error-format=json; }
breaking() { buf breaking "$1" --against "$module" --error-format=json; }
drop_receipt_reason_code() { perl -ni -e 'print unless /^\s*ReasonCode reason_code = 15;/' "$1/helm/kernel/v1/helm.proto"; }

# --- lint ---------------------------------------------------------------------

expect 0 'lint accepts protocols/proto' '' lint "$module"
expect 0 'lint exemptions are exactly the recorded legacy findings' '' bash "$check_exemptions" "$module"

d="$(copy new-rpc)"
mkdir -p "$d/helm/fixture/v1"
cat >"$d/helm/fixture/v1/fixture.proto" <<'EOF'
syntax = "proto3";

package helm.fixture.v1;

message Thing {}

service FixtureService {
  rpc Do(Thing) returns (Thing);
}
EOF
expect 100 'lint rejects a new file with non-standard RPC names' '"type":"RPC_REQUEST_STANDARD_NAME"' lint "$d"

d="$(copy misplaced)"
mkdir -p "$d/misplaced/v1"
printf 'syntax = "proto3";\n\npackage helm.misplaced.v1;\n\nmessage Misplaced {}\n' >"$d/misplaced/v1/misplaced.proto"
expect 100 'lint rejects a new package outside its directory' '"type":"PACKAGE_DIRECTORY_MATCH"' lint "$d"

d="$(copy legacy-other-rule)"
printf '\nmessage lower_snake {}\n' >>"$d/helm/kernel/v1/helm.proto"
expect 100 'lint rejects another rule in an exempted file' '"type":"MESSAGE_PASCAL_CASE"' lint "$d"

# ignore_only is file-scoped, so buf lint alone accepts this; the exemption
# check is what rejects it.
d="$(copy legacy-new-rpc)"
perl -0pi -e 's/(service PolicyDecisionPointService \{\n)/$1  rpc Recheck(RecheckInput) returns (RecheckOutput);\n/' "$d/helm/kernel/v1/helm.proto"
printf '\nmessage RecheckInput {}\n\nmessage RecheckOutput {}\n' >>"$d/helm/kernel/v1/helm.proto"
expect 1 'exemption check rejects a new badly named RPC in an exempted file' 'helm/kernel/v1/helm.proto RPC_REQUEST_STANDARD_NAME 4' bash "$check_exemptions" "$d"

d="$(copy legacy-fixed)"
perl -ni -e 'print unless /^\s*rpc GetLatest\(/' "$d/helm/truth/v1/truth.proto"
expect 1 'exemption check rejects an unrecorded change to the legacy findings' 'helm/truth/v1/truth.proto RPC_REQUEST_STANDARD_NAME 2' bash "$check_exemptions" "$d"

# --- breaking -----------------------------------------------------------------

d="$(copy additive)"
perl -0pi -e 's/(message Receipt \{\n)/$1  string fixture_note = 999;\n/' "$d/helm/kernel/v1/helm.proto"
expect 0 'breaking accepts an additive field' '' breaking "$d"

d="$(copy field-delete)"
drop_receipt_reason_code "$d"
expect 100 'breaking rejects a deleted field' '"type":"FIELD_NO_DELETE"' breaking "$d"

# FILE_NO_DELETE is in the FILE category only: this case fails if the module
# is downgraded to the WIRE or WIRE_JSON rules, which ignore generated-code breaks.
d="$(copy file-delete)"
rm "$d/helm/truth/v1/truth.proto"
expect 100 'breaking rejects a deleted file' '"type":"FILE_NO_DELETE"' breaking "$d"

# --- the release gate end to end ----------------------------------------------
# `contract_breaking.sh proto release` is the command the CI IDL job runs. The
# fixture's v1.0.0 tag has no protocols/proto/buf.yaml, like v0.8.5.

repo="$work/repo"
git init -q "$repo"
(
  cd "$repo"
  git config user.name 'HELM proto gate test'
  git config user.email 'proto-gate-test@example.invalid'
  git config commit.gpgsign false
  mkdir -p protocols
  cp -R "$root/protocols/policy-schema" protocols/policy-schema
  cp -R "$module" protocols/proto
  rm protocols/proto/buf.yaml
  printf '1.0.0\n' >VERSION
  git add -A
  git commit -qm 'test: release baseline'
  git tag v1.0.0
  cp "$module/buf.yaml" protocols/proto/buf.yaml
  printf '1.0.1\n' >VERSION
  git add -A
  git commit -qm 'test: release candidate'
)
release_gate() { (cd "$repo" && bash "$root/scripts/ci/contract_breaking.sh" proto release); }

expect 0 'release gate accepts an unchanged IDL' 'GATE 1 (proto): pass' release_gate

drop_receipt_reason_code "$repo/protocols/proto"
git -C "$repo" commit -qam 'test: drop Receipt.reason_code'
expect 1 'release gate rejects a deleted field vs the last release tag' 'buf breaking for protocols/proto reported a blocking contract finding' release_gate

printf 'proto gate self-test passed\n'
