# Autonomous Bounty Crucible

Status: Kernel v0 source gate. This document does not claim a deployed or
production-complete autonomous bug-bounty service.

Tracking: HELM-205 (program) and HELM-206 (Kernel v0 gate).

quantum_posture: Kernel v0 campaign authorization and report attestations use
classical Ed25519. This surface makes no post-quantum assurance claim.

## Trust boundary

The adversarial suites in `core/pkg/conform/adversarial` are deterministic
detectors over supplied artifacts. A detector pass means only that the supplied
artifacts did not trigger that suite. Missing artifacts are therefore not proof
of correct behavior.

`helm-ai-kernel conform adversarial` is the authoritative campaign entrypoint.
It fails closed in this order:

1. require a sealed EvidencePack, explicit trust profile, campaign trust root,
   evaluation time, exact Kernel commit, and report-attestation key;
2. snapshot directory inputs into an owned, symlink-free temporary tree,
   bounded to 32 MiB and 4,096 filesystem entries;
3. run the canonical offline EvidencePack verifier, including canonical-layout
   and configured signature checks;
4. prove positive-control coverage for all ten detectors from indexed pack
   artifacts;
5. skip all adversarial suites if bundle verification or coverage fails;
6. run all ten mandatory suites only over the same verified snapshot;
7. write a deterministic, provenance-bound Ed25519-attested report outside the
   sealed pack;
8. exit nonzero if verification, coverage, suite completeness, or any suite
   fails.

The report omits implicit wall-clock generation timestamps and known
machine-local input paths, while recording the caller-supplied evaluation time.
It binds the result to the EvidencePack index root, Merkle root, trust profile,
verifier version, ordered checks, and ordered suite results. Repeated offline
runs produce the same report bytes when the sealed pack, verifier version, and
explicit trust/provenance inputs are unchanged.

Campaign-only tool fixtures live under the declared
`99_EXT/adversarial/tools/` extension. Receipt-emission panic evidence uses the
canonical `06_LOGS/receipt_emission_panic.json` sink. Legacy detector fixtures
under `10_TOOLS/` or top-level `panic.json` remain readable by unit tests but
cannot pass the strict canonical EvidencePack structure gate.

ADV-02 and ADV-10 require authorization receipts to precede the effect, share
its decision and envelope binding, sit on its receipt ancestry, and verify under
an externally supplied Ed25519 campaign key. ADV-08 verifies RFC 8785 canonical
tool-manifest bytes under the same external trust root. ADV-06 recomputes the
SHA-256 digest of the decoded tape value instead of trusting a claimed hash.

## Usage

```bash
make bounty-kernel \
  HELM_BOUNTY_EVIDENCEPACK=/absolute/path/to/evidence-pack \
  HELM_BOUNTY_PROFILE=team \
  HELM_BOUNTY_CONFIG=/absolute/path/to/evidence-pack-trust.json \
  HELM_BOUNTY_CAMPAIGN_PUBLIC_KEY=<ed25519-public-key-hex> \
  HELM_BOUNTY_EVALUATION_TIME=2026-07-15T12:00:00Z \
  HELM_SIGNING_KEY_HEX=<attestation-private-key-hex> \
  HELM_BOUNTY_REPORT=/absolute/path/to/kernel-adversarial-campaign.json
```

Direct CLI equivalent:

```bash
helm-ai-kernel conform adversarial \
  --bundle /absolute/path/to/evidence-pack \
  --profile team \
  --config /absolute/path/to/evidence-pack-trust.json \
  --campaign-public-key <ed25519-public-key-hex> \
  --evaluation-time 2026-07-15T12:00:00Z \
  --kernel-commit <exact-40-character-commit> \
  --report /absolute/path/to/kernel-adversarial-campaign.json \
  --json
```

Valid profiles are `dev-local`, `team`, `customer`, and `high-assurance`.
Strict campaigns never silently default to `dev-local`. Customer and
high-assurance campaigns require the external trust, anchor, and immutable
storage evidence enforced by the EvidencePack verifier.
Non-dev profiles also require an applicable trust config or trusted-key
environment; the examples make that prerequisite explicit with `--config`.
`HELM_SIGNING_KEY_HEX` supplies the current Ed25519 report-attestation signer
and must be injected through the campaign runner's protected secret boundary,
never stored inside the candidate EvidencePack.

The report path must be outside the EvidencePack. Writing a new file into a
sealed pack would invalidate its index and seal, so the command rejects that
configuration, including attempts to overwrite an archive input.

Verify a report independently before any downstream use:

```bash
helm-ai-kernel conform adversarial verify-report \
  --report /absolute/path/to/kernel-adversarial-campaign.json \
  --trusted-public-key <attestation-public-key-hex> \
  --expected-kernel-commit <exact-40-character-commit>
```

Verification rejects reports larger than 8 MiB, unknown fields, duplicate
object keys, and trailing JSON values before signature validation. With
`--json`, it emits a freshly encoded typed report only after validation.

The signature binds the evaluation time, input roots, ordered checks and suite
results, campaign trust-key ID, exact Kernel commit, runner executable SHA-256,
detector revision, and detector-definition digest. Downstream release policy
must also match the executable digest to source-owned build provenance.
The fixed key used by the repository CI reference campaign is derivable and
authorizes only that same-job contract test. It must never be trusted for
release or production evidence.

## Result semantics

- `passed`: the pack verified under the selected profile and all ten suites ran
  and passed.
- `bundle_verification_failed`: the pack was empty, incomplete, malformed,
  tampered, incorrectly signed, or failed the selected trust profile. No suites
  ran because unverified input cannot support a campaign verdict.
- `coverage_incomplete`: the pack verified, but one or more suites lacked the
  positive-control artifacts needed to exercise their detector. No suites ran;
  absence of relevant evidence is never a pass.
- `adversarial_failed`: the pack verified, all ten suites ran, and at least one
  suite found a violation.

Exit code `0` means `passed`, `1` means a verification or adversarial failure,
and `2` means invalid configuration or a runtime/report-writing error.

## Claim limits and next closure gates

A passing Kernel v0 report is conformance evidence, not proof that HELM is
bug-free or production-ready. The report always names the untested regions:
model/provider clean-room execution, independent SecurityFinding verification,
patch and regression validation, and staging/production smoke and soak.

The production loop must continue outside this command:

1. import a finder/scanner/model result only as a candidate SecurityFinding;
2. reproduce it in a pinned clean-room sandbox;
3. verify it with a separate agent/run identity and VerificationScope;
4. constrain any patch through GeneratedSpec; use the existing draft-PR runner
   only for eligible repositories, while Kernel changes stay on the governed
   specialist/manual Kernel review path until a separately authorized runner
   exists;
5. prove failed-before/passed-after regression and variant scan;
6. seal and verify the SecurityEvidencePack with Kernel EvidencePack tooling,
   then bind the verified seal hash and closure refs into the control-plane
   event chain;
7. pass exact-head release, deployment, runtime smoke, and soak authority.

No scanner, model, bounty producer, RLM handoff, fixture pack, or this offline
command may self-promote a finding to `verified`, `fixed`, or `sealed`.
