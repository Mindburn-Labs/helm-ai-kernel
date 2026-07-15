# Autonomous Bounty Crucible

Status: Kernel v0 source gate. This document does not claim a deployed or
production-complete autonomous bug-bounty service.

Tracking: HELM-205 (program) and HELM-206 (Kernel v0 gate).

## Trust boundary

The adversarial suites in `core/pkg/conform/adversarial` are deterministic
detectors over supplied artifacts. A detector pass means only that the supplied
artifacts did not trigger that suite. Missing artifacts are therefore not proof
of correct behavior.

`helm-ai-kernel conform adversarial` is the authoritative campaign entrypoint.
It fails closed in this order:

1. require a sealed EvidencePack and an explicit trust profile;
2. run the canonical offline EvidencePack verifier, including canonical-layout
   and configured signature checks;
3. prove positive-control coverage for all ten detectors from indexed pack
   artifacts;
4. skip all adversarial suites if bundle verification or coverage fails;
5. run all ten mandatory suites only over a verified, fully covered pack;
6. write a deterministic report outside the sealed pack;
7. exit nonzero if verification, coverage, suite completeness, or any suite
   fails.

The report deliberately omits timestamps and machine-local paths. It binds the
result to the EvidencePack index root, Merkle root, trust profile, verifier
version, ordered checks, and ordered suite results. Repeating the command over
the same pack with the same Kernel version produces the same report bytes.

Campaign-only tool fixtures live under the declared
`99_EXT/adversarial/tools/` extension. Receipt-emission panic evidence uses the
canonical `06_LOGS/receipt_emission_panic.json` sink. Legacy detector fixtures
under `10_TOOLS/` or top-level `panic.json` remain readable by unit tests but
cannot pass the strict canonical EvidencePack structure gate.

## Usage

```bash
make bounty-kernel \
  HELM_BOUNTY_EVIDENCEPACK=/absolute/path/to/evidence-pack \
  HELM_BOUNTY_PROFILE=team \
  HELM_BOUNTY_REPORT=/absolute/path/to/kernel-adversarial-campaign.json
```

Direct CLI equivalent:

```bash
helm-ai-kernel conform adversarial \
  --bundle /absolute/path/to/evidence-pack \
  --profile team \
  --report /absolute/path/to/kernel-adversarial-campaign.json \
  --json
```

Valid profiles are `dev-local`, `team`, `customer`, and `high-assurance`.
Strict campaigns never silently default to `dev-local`. Customer and
high-assurance campaigns require the external trust, anchor, and immutable
storage evidence enforced by the EvidencePack verifier.

The report path must be outside the EvidencePack. Writing a new file into a
sealed pack would invalidate its index and seal, so the command rejects that
configuration.

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
4. constrain any patch through GeneratedSpec and the existing draft-PR runner;
5. prove failed-before/passed-after regression and variant scan;
6. seal the SecurityEvidencePack through the control-plane event chain;
7. pass exact-head release, deployment, runtime smoke, and soak authority.

No scanner, model, bounty producer, RLM handoff, fixture pack, or this offline
command may self-promote a finding to `verified`, `fixed`, or `sealed`.
