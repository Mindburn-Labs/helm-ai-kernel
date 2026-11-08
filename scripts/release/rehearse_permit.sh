#!/usr/bin/env bash
# Rehearse the release-permit gate of release.yml without a model call.
#
# Builds release-permit-verify from HEAD, binds a context to HEAD, feeds the
# recorded answers in release/permit-fixtures through the real reducer and
# requires ALLOW, then feeds the recorded blocking answer and requires the
# reducer to DENY (exit 3). No network call goes to a model provider and no
# secret is read. It needs GITHUB_TOKEN to look up the merged pull request.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "${work}"' EXIT
cd "${root}"

(cd core && GOWORK=off go build -trimpath -o "${work}/release-permit-verify" ./cmd/release-permit-verify)
commit="$(git rev-parse HEAD)"
python3 scripts/release/release_permit.py context --output "${work}/context.json" --commit "${commit}"

reduce() {
  local fixtures="$1" outdir="$2"
  mkdir -p "${outdir}"
  python3 scripts/release/release_permit.py review --context "${work}/context.json" --outdir "${outdir}/reviews" --fixtures "${fixtures}" || return 1
  local args=()
  for review in "${outdir}"/reviews/review-*.json; do args+=(--review "${review}"); done
  (cd "${outdir}" && "${work}/release-permit-verify" --context "${work}/context.json" "${args[@]}" --output release-permit.json > /dev/null)
}

reduce release/permit-fixtures "${work}/allow"
jq -e '.decision == "ALLOW"' "${work}/allow/release-permit.json" > /dev/null
"${work}/release-permit-verify" --context "${work}/context.json" --verify-permit "${work}/allow/release-permit.json" > /dev/null
echo "PASS release permit rehearsal: recorded quorum reduces to ALLOW and validates"

status=0
reduce release/permit-fixtures/deny "${work}/deny" || status=$?
if [ "${status}" -ne 3 ] || ! jq -e '.decision == "DENY"' "${work}/deny/release-permit.json" > /dev/null; then
  echo "FAIL release permit rehearsal: a blocking review did not produce a DENY permit (exit ${status})" >&2
  exit 1
fi
echo "PASS release permit rehearsal: a blocking review reduces to DENY and fails the gate"
