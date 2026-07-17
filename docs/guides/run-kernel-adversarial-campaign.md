---
title: Run a Kernel Adversarial Campaign
last_reviewed: 2026-07-17
---

<!-- quantum_posture: this guide documents classical Ed25519 campaign and
report authentication; it does not claim post-quantum campaign signing. -->

# Run a Kernel Adversarial Campaign

This guide runs the source-owned Kernel portion of the HELM bug-bounty loop
against one sealed EvidencePack. It is an offline conformance boundary, not a
claim that the wider clean-room agent campaign, finding triage, patching,
staging, production smoke, or soak has completed.

The command first invokes the canonical EvidencePack verifier. Only a verified
pack advances to the ten mandatory adversarial suites. Every suite must pass on
the unchanged positive control and reject its source-owned deterministic
negative mutation. The source EvidencePack is never modified.

## Trust roles

Keep these keys distinct in production:

| Role | Input | What it authorizes |
| --- | --- | --- |
| Campaign root | `HELM_BOUNTY_CAMPAIGN_PUBLIC_KEY_HEX` | Signed policy/approval receipts and tool manifests for one campaign/run |
| Existing conformance verifier | `HELM_VERIFY_PUBLIC_KEY_HEX` or `--trusted-public-key` on the campaign command | Optional detached `conformance_report.sig` already present in the pack |
| Campaign report attestor | `HELM_BOUNTY_REPORT_SIGNING_KEY_HEX` | The final deterministic adversarial campaign report |
| Campaign report verifier | `HELM_BOUNTY_REPORT_PUBLIC_KEY_HEX` | Offline verification of that final report |

Embedded keys inside the candidate pack do not establish any of these trust
roots. `dev-local` uses a local EvidencePack seal and is not production
evidence. Use the required external signer, anchor, storage, and receipt inputs
for `team`, `customer`, or `high-assurance` as defined by the EvidencePack trust
profile.

## Inspect the detector contract

Build from the exact source commit that will run the campaign:

```bash
make build
./bin/helm-ai-kernel conform adversarial definition
```

The output includes the detector revision, compatibility digest, and the
ordered binding for every suite:

```text
suite_id -> mutation_id -> expected_test_id
```

Pin the revision, definition digest, full Kernel commit, and executable SHA-256
in campaign policy. A detector change requires a new source-owned definition
digest.

## Prepare a clean campaign input

Use a newly created workspace with no project documentation, task history,
operator home directory, or model memory mounted into it. Give the runner only:

1. the sealed candidate EvidencePack or archive;
2. explicit trust configuration and public verification roots;
3. one stable campaign ID and one unique run ID;
4. an explicit RFC3339 evaluation time (fractional seconds are preserved); and
5. a report output path outside the candidate pack.

Campaign authorization receipts and tool manifests inside the pack must bind
the same `campaign_id` and `run_id`. Receipt and tool-manifest Ed25519
signatures are domain separated. The final report has a third signature domain,
`helm.bounty.campaign-report-signature/v1`.

For directory inputs, the runner creates a bounded read-only snapshot, rejects
symlinks and non-regular files, reopens and rehashes every source file to detect
torn reads, and caps the input at 4,096 entries and 32 MiB. Archive extraction
uses the same byte ceiling. The detector mutation workspace must reproduce the
index hash, Merkle root, and entry count returned by the canonical verifier.

## Run the campaign

Set secrets through the environment rather than shell history:

```bash
export HELM_BOUNTY_CAMPAIGN_PUBLIC_KEY_HEX='<external-campaign-public-key>'
export HELM_BOUNTY_CAMPAIGN_ID='kernel-cleanroom-2026-07'
export HELM_BOUNTY_RUN_ID='run-0001'
export HELM_BOUNTY_EVALUATION_TIME_RFC3339='2026-07-17T12:00:00Z'
export HELM_BOUNTY_REPORT_SIGNING_KEY_HEX='<dedicated-report-signing-seed-or-key>'

make bounty-kernel \
  BOUNTY_BUNDLE=/cleanroom/input/evidence-pack \
  BOUNTY_PROFILE=high-assurance \
  BOUNTY_REPORT=/cleanroom/output/kernel-campaign.json
```

If the EvidencePack contains an externally signed detached conformance report,
also provide its trusted public key through `HELM_VERIFY_PUBLIC_KEY_HEX`. The
runner permits only the already verified
`07_ATTESTATIONS/conformance_report.sig` to remain outside the index; any other
unindexed file fails closed.

Exit codes are stable:

| Code | Meaning |
| --- | --- |
| `0` | canonical verification, mutation coverage, and every executed suite passed |
| `1` | authenticated evidence or an adversarial requirement failed |
| `2` | configuration, bounded input, runtime, or report-writing error |

The report status distinguishes `bundle_verification_failed`,
`coverage_incomplete`, `adversarial_failed`, and `passed`. A pre-failing
positive control is `coverage_incomplete`; it cannot masquerade as proof that a
mutation detector works.

## Verify the report in a pinned checkout

Move the report, never the private attestation key, to an independent verifier.
Use a checkout of the exact expected Kernel commit and provide independently
recorded roots from campaign orchestration:

```bash
export HELM_BOUNTY_CAMPAIGN_PUBLIC_KEY_HEX='<expected-campaign-public-key>'
export HELM_BOUNTY_CAMPAIGN_ID='kernel-cleanroom-2026-07'
export HELM_BOUNTY_RUN_ID='run-0001'
export HELM_BOUNTY_REPORT_PUBLIC_KEY_HEX='<trusted-report-public-key>'

make bounty-kernel-verify \
  BOUNTY_REPORT=/verifier/input/kernel-campaign.json \
  BOUNTY_PROFILE=high-assurance \
  BOUNTY_EVIDENCE_ROOT='<expected-00_INDEX-sha256>' \
  BOUNTY_MERKLE_ROOT='<expected-evidence-merkle-root>'
```

Verification is fail-closed on unknown or duplicate JSON fields, extra JSON
values, reports above 8 MiB, nesting deeper than 128 containers, signature or
key-ID mismatch, campaign/run replay, campaign-root substitution, source
detector drift, counter contradictions, missing mutation evidence, reordered
suites, or changed limitation text.

The public structural contract is
`protocols/json-schemas/certification/adversarial_campaign_report.v2.schema.json`.
The CLI additionally enforces semantic relationships that JSON Schema cannot
fully express.

## What this receipt does and does not prove

A `passed` report proves that this exact binary and detector definition
verified this exact EvidencePack root and exercised all mandatory positive and
negative controls for the declared campaign/run. It does not prove:

- that model/provider execution occurred in a clean room;
- that independent agents reproduced and triaged a SecurityFinding;
- that a patch was generated or its regression suite passed;
- that staging or production accepted the build; or
- that a soak window completed without incident.

Those are separate control-plane, OCI, deployment, runtime, and EvidencePack
receipts. Do not collapse them into the Kernel campaign verdict.
