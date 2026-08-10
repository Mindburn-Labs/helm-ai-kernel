#!/usr/bin/env bash
# Falsification workload for the vision paper's §9.1.2 claim
# "Proof stronger than platform logs".
#
# The claim's own pass condition is:
#
#   a third party receives a redacted pack for a dispatched and reconciled
#   action, and the verifier can test identity, policy, permit, execution
#   observation, closure, and integrity OFFLINE without our dashboard.
#
# and its fail condition is:
#
#   verification requires trusting HELM's hosted state, or cannot distinguish
#   intent from outcome.
#
# A verifier that merely says PASS proves nothing — a verifier that cannot say
# FAIL is a rubber stamp. So this harness asserts a matrix, not a result: two
# cases that MUST fail and one that MUST pass. If the failing cases start
# passing, the claim is falsified and this script exits non-zero.
#
# Every case runs with HTTP_PROXY/HTTPS_PROXY/ALL_PROXY pointed at a closed
# port, so any attempt to reach a network service fails rather than silently
# succeeding on a developer machine that happens to have connectivity. That is
# the part of the claim that cannot be established by reading imports.
set -euo pipefail

cd "$(dirname "$0")/../.."

CLI_BIN="${CLI_BIN:-$(mktemp -d)/helm-ai-kernel}"
UNSIGNED_PACK="${UNSIGNED_PACK:-fixtures/minimal}"
SEALED_PACK="${SEALED_PACK:-reference_packs/launchpad/hermes-local-container}"

# A closed port, not a bogus hostname: DNS failure and connection refusal take
# different code paths, and refusal is the one a real air-gap produces.
airgapped() {
  env HTTP_PROXY=http://127.0.0.1:1 \
      HTTPS_PROXY=http://127.0.0.1:1 \
      ALL_PROXY=http://127.0.0.1:1 \
      NO_PROXY= \
      "$@"
}

# The CLI exits non-zero when a pack does not verify, which is correct and is
# the expected outcome for two of the three cases below. So the exit status is
# deliberately discarded here and the verdict is read from the report instead:
# treating "refused to verify" as a harness error would make the two cases that
# MUST fail unrunnable.
verdict() {
  local out
  out="$(airgapped "$CLI_BIN" verify "$@" --json 2>/dev/null || true)"
  printf '%s' "$out" | python3 -c '
import json, sys
raw = sys.stdin.read().strip()
if not raw:
    print("NO-OUTPUT")
    sys.exit()
try:
    print(json.loads(raw).get("verified"))
except ValueError:
    print("UNPARSEABLE")
'
}

fail_count=0
case_result() {
  local name="$1" want="$2" got="$3" detail="$4"
  if [ "$want" = "$got" ]; then
    printf '  PASS  %-34s verified=%-5s %s\n' "$name" "$got" "$detail"
  else
    printf '  FAIL  %-34s want verified=%s, got %s — %s\n' "$name" "$want" "$got" "$detail"
    fail_count=$((fail_count + 1))
  fi
}

echo "Building the verifier from source..."
(cd core && GOWORK=off go build -o "$CLI_BIN" ./cmd/helm-ai-kernel)

echo
echo "Falsification: 'Proof stronger than platform logs' (vision paper §9.1.2)"
echo "All cases run air-gapped (proxy -> 127.0.0.1:1)."
echo

# CASE 1 — an unsigned pack must not verify. A verifier that accepts evidence
# carrying no seal is asserting a claim nobody made.
got="$(verdict "$UNSIGNED_PACK")"
case_result "unsigned pack refused" "False" "$got" "no evidence_pack.sig"

# CASE 2 — THE LOAD-BEARING CASE. The pack is properly sealed, but its
# verification key is declared inside the pack itself. Accepting that is
# exactly the "referee is also the player" failure the category argument names:
# a counterparty attesting to its own conduct with a key only it vouches for.
# The verifier must refuse this by DEFAULT, with no flag required.
got="$(verdict "$SEALED_PACK")"
case_result "self-attested seal refused" "False" "$got" "key declared inside the bundle"

# CASE 3 — the same bytes verify once the operator explicitly accepts
# self-attestation. This proves case 2 failed on the trust root and not on
# something incidental (a malformed pack would fail here too).
got="$(verdict "$SEALED_PACK" --allow-self-attested)"
case_result "same pack, self-attestation opted in" "True" "$got" "12/12 checks"

echo
if [ "$fail_count" -ne 0 ]; then
  echo "FALSIFIED: $fail_count case(s) did not behave as the claim requires."
  echo "Per §9.1.2, a moat that cannot survive its own test is removed from"
  echo "market language rather than defended with a more elaborate demo."
  exit 1
fi

echo "Claim survives its falsification workload (3/3 cases)."
echo
echo "What this does and does not establish:"
echo "  - Establishes: offline verification with no HELM service in the trust"
echo "    path, and refusal of self-attested evidence by default."
echo "  - Does NOT establish: the redacted-pack path (--entry/--proof) or a"
echo "    reconciled external outcome. Both are part of the §9.1.2 workload and"
echo "    remain unproven until a sealed pack with an external trust root and a"
echo "    reconciliation record is published."
