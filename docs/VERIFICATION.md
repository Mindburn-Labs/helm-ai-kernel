---
title: Receipts
last_reviewed: 2026-09-24
---

<!-- quantum_posture: this page documents classical Ed25519 receipt checks and adds no post-quantum cryptographic control. -->

# Receipts

Every governed action should leave a local record. For public HELM, that record
is the proof path: show what was proposed, what HELM decided, why it decided
that, and where the receipt was written.

## What Gets Written

For MCP and boundary decisions, HELM records:

- `decision_id`
- verdict: `ALLOW`, `DENY`, or `ESCALATE`
- reason code
- server id, tool name, and effect scope when available
- receipt path
- approval hint when a credential-verified admission path is available
- policy epoch and record hash

Approvals and revocations also write receipts. A later evaluation must fail
closed when an admission is expired, revoked, or outside its server, tool, or
effect scope.

## Inspect Local Receipts

```bash
helm-ai-kernel mcp receipts --json
helm-ai-kernel mcp pending --json
helm-ai-kernel boundary records --json
helm-ai-kernel receipts status --format json
helm-ai-kernel receipts list --format json
```

For a Kernel evaluate `receipt.v5` file copied off-box (Foundation/offline
verify, not AI OS live, not #859, not self-attested EvidencePack):

```bash
helm-ai-kernel verify receipt \
  --receipt <receipt.v5.json> \
  --trusted-public-key-file <expected-ed25519.pub>
```

Exit 0 only when integrity and signer trust both hold against the
caller-supplied key. Hop fixtures are labeled DENY / no permit.

For a single workstation receipt:

```bash
helm-ai-kernel workstation verify-decision \
  --receipt ~/.helm-ai-kernel/receipts/hooks/wpd_<decision>.json
```

This workstation command reports `integrity` and `trusted` independently.
`integrity: true` alone only means the contents match the receipt's declared
public key. A zero exit status requires `trusted: true` against the expected
local key or an explicit `--trusted-public-key-file`; use the latter for a
receipt copied between machines.

For an EvidencePack, name the trust root that says whose signing key you
expect:

```bash
helm-ai-kernel verify evidence-pack.tar --config <trust-config.yaml>
```

Compatibility form:

```bash
helm-ai-kernel verify --bundle evidence-pack.tar --config <trust-config.yaml>
```

The verifier takes its trust root, meaning the trusted signing keys and the
active profile, from one of these sources, in this order:

1. `--config <path>`
2. `HELM_EVIDENCE_TRUST_CONFIG`
3. your own `$HELM_DATA_DIR/trust/evidence-pack.json` (default
   `~/.helm/trust/evidence-pack.json`), as written by
   `helm-ai-kernel evidence trust init`

A single trusted key can also be supplied with
`HELM_EVIDENCE_TRUSTED_PUBLIC_KEY_HEX`. The verifier never reads a trust config
from the working directory. A `helm/helm.yaml` shipped next to a pack is
ignored unless you pass it with `--config` yourself, because a file that
travels with the pack cannot vouch for it.

When no trust root names the pack's signer, the result is `UNVERIFIABLE`
(exit 1): the content matches its seal, but nothing you configured vouches for
who signed it. A pack whose content does not match its seal is `FAILED`.
`--allow-self-attested` accepts a dev-local seal checked against the key it
carries; that shows internal consistency only, so use it only for packs you
produced yourself.

Offline verification is the default. If a pack has no public anchor, HELM
reports that directly; it does not invent one. Under the `customer` and
`high-assurance` profiles an anchor receipt must name this pack's root: a
Rekor entry's hash and integrated time must match the receipt, and an RFC 3161
token's message imprint must match the root. The RFC 3161 check does not yet
validate the TSA's signature or certificate chain.

## Read A Decision

Start with these fields:

| Field | Meaning |
| --- | --- |
| `decision_id` | The decision to cite when debugging or rerunning |
| `verdict` | `ALLOW`, `DENY`, or `ESCALATE` |
| `reason_code` | Why the boundary returned that verdict |
| `receipt_path` | Local file written for the decision |
| `record_hash` | Tamper-evidence handle for the boundary record |

An `ESCALATE` receipt is not permission to continue. Obtain a
credential-verified durable dispatch admission for the exact scope, then
rerun the original action so HELM evaluates it again. Local `mcp approve`
does not mint that authority.

## Export Evidence

Use an EvidencePack when you need to move proof material between machines or
review it later:

```bash
helm-ai-kernel evidence export \
  --receipts ~/.helm-ai-kernel/receipts \
  --out evidence-pack.tar

helm-ai-kernel verify evidence-pack.tar --config <trust-config.yaml>
```

EvidencePacks are portable proof bundles for local review and offline replay.

## Release Evidence

Current source release target: `v0.9.0`.

The `v0.9.0` release is complete only after the listed local verification
assets appear on the GitHub release and verify locally.

Check the GitHub release and local verification artifacts together:

- release: `https://github.com/Mindburn-Labs/helm-ai-kernel/releases/tag/v0.9.0`
- v0.9.0 Asset Contract
- `v0.9.0.openvex.json`
- `v0.9.0.json`

### Verify Release Assets Locally

Download the release assets into one directory, then check their keyless
signatures against the exact release identity:

```bash
KERNEL_RELEASE_TAG=v0.8.5 make verify-cosign COSIGN_ARTIFACT_DIR=<download-dir>
```

`make verify-cosign` runs `scripts/release/verify_cosign.sh`. It accepts only
`release.yml` on the `refs/tags/v*` ref and fails when it verifies zero bundles
or finds a bundle without its artifact.

`make release-smoke` rebuilds the release surface from source: reproducible
binaries, the SBOM and the OpenVEX document, plus cosign verification when
bundles are present. It is the same smoke the release workflow runs.
