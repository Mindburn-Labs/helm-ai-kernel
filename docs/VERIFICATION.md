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

Integrity here is the `receipt.v5` signature over its 13 signed members, not
the whole file. The report lists those as `signed_members` and the file's
other members (`tool_name`, `timestamp`, `key_id` among them) as
`unsigned_members`: no signature covers them, and rewriting them changes
neither `integrity_valid` nor the exit status. The file is read by the parser
`receipt_verify` uses, so the rules under
[Verify A Receipt Chain Offline](#verify-a-receipt-chain-offline) apply.

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
helm-ai-kernel export \
  --evidence <evidence-pack-dir> \
  --out evidence-pack.tar

helm-ai-kernel verify evidence-pack.tar --config <trust-config.yaml>
```

`export` copies an existing EvidencePack directory into a deterministic tar;
it does not build a pack from loose receipt files. `mcp proof` writes such a
directory under `<out>/<run-id>/evidencepacks/<run-id>`.

EvidencePacks are portable proof bundles for local review and offline
verification.

## Release Evidence

Current source release target: `v0.12.0`.

The `v0.12.0` release is complete only after the listed local verification
assets appear on the GitHub release and verify locally.

Check the GitHub release and local verification artifacts together:

- release: `https://github.com/Mindburn-Labs/helm-ai-kernel/releases/tag/v0.12.0`
- v0.12.0 Asset Contract
- `v0.12.0.openvex.json`
- `v0.12.0.json`

### Verify Release Assets Locally

Download the release assets into one directory, then check their keyless
signatures against the exact release identity:

```bash
KERNEL_RELEASE_TAG=v0.12.0 make verify-cosign COSIGN_ARTIFACT_DIR=<download-dir>
```

`make verify-cosign` runs `scripts/release/verify_cosign.sh`. It accepts only
`release.yml` on the `refs/tags/v*` ref and fails when it verifies zero bundles
or finds a bundle without its artifact.

`make release-smoke` rebuilds the release surface from source: reproducible
binaries (the kernel and the standalone `receipt_verify` verifier), the SBOM and
the OpenVEX document, plus cosign verification when bundles are present. It
also checks that the build holds all five `receipt_verify-*` assets, each at
least as large as a real build and carrying the executable header of the
operating system and CPU architecture its name states, and that the one for the
running host verifies the frozen fixture chain and rejects a wrong key and a
tampered receipt. A staged `dist/release-assets/` is checked by the staging
script and the release workflow's `binaries` job, not by the smoke. It is the
same smoke the release workflow runs.

### Verify A Receipt Chain Offline

From the first release after `v0.11.3`, releases carry the offline receipt
verifier as `receipt_verify-linux-amd64`, `receipt_verify-linux-arm64`,
`receipt_verify-darwin-amd64`, `receipt_verify-darwin-arm64` and
`receipt_verify-windows-amd64.exe`, each with a `.cosign.bundle`. `v0.11.3` and
earlier releases do not carry them; build from the tagged source with
`make receipt-verify-binaries` instead. After checking the
download with `make verify-cosign`, run it with the signer's public key:

```bash
chmod +x receipt_verify-linux-amd64
./receipt_verify-linux-amd64 --receipt chain.json --key-file signer-public-key.hex
```

It opens no sockets and reads no configuration. Exit code `0` means the chain
verified under the supplied key, `1` means it did not, and `2` means no verdict
was reported: a missing or unknown flag, no key supplied, a receipt file or
`--key-file` that cannot be read, a receipt file that does not parse as a
receipt, receipt array or bundle, or a legacy receipt without
`--allow-legacy-v4`. See [LLM audit receipts](use-cases/llm-audit-receipts.md) for what a verified
result does and does not establish.

These rules decide whether a file is checked at all:

- **Member names are matched exactly.** A file in which a receipt, bundle,
  permit or binding member is spelled in another letter case (`"Verdict"` for
  `verdict`) does not parse (exit `2`). Go's JSON decoder would bind
  `"Verdict"` to the verdict; `jq` and JavaScript would not, so the same file
  would say one thing to the verifier and another to its reader. Keys of
  `metadata`, `public_key_set`, `subject` and other free-form values are
  compared exactly: `a` and `A` there are two keys to every reader. A member
  written twice is refused wherever it is.
- **A bundle holds receipts only inside `receipts`.** In the bundle form (an
  object with a `receipts` array) the verifier checks the receipts in that
  array. A receipt member beside it, such as `verdict`, `status` or
  `tool_name`, is checked by nothing and is what `jq .verdict` returns, so a
  file that carries one does not parse (exit `2`). The bundle's own members
  (`key_id`, `public_key_hex`, `permits`, `gateway_bindings`) and names that
  are not receipt members, such as a `comment`, are accepted.
- **Nesting is limited to 64 levels.** A file nested deeper is refused before
  it is read further (exit `2`).
- **A legacy receipt needs `--allow-legacy-v4`.** A receipt with no
  `signature_version` was signed before `receipt.v5`, over eight fields joined
  with `:` and no escaping. That signature does not cover `verdict`,
  `tool_name` or `timestamp`, and the signature of a `receipt.v5` receipt can
  be replayed as a legacy receipt that says something else. Such a file is not
  checked (exit `2`) unless you pass the flag:

  ```bash
  ./receipt_verify-linux-amd64 --receipt old-chain.json --key-file signer-public-key.hex --allow-legacy-v4
  ```

  The output then counts the legacy receipts (`legacy_receipts` in `--json`)
  and says that their signature does not cover `verdict`, `tool_name` or
  `timestamp`. Pass the flag only for receipts you know were issued before
  `receipt.v5`. The replay itself still fails under the flag (exit `1`): the
  legacy preimage begins with `receipt_id`, and the replayed bytes begin with
  `{`, which no receipt id does. For a chain that mixes the two kinds,
  `preimage_version` is `mixed` and `preimage_versions` lists each preimage
  with its receipt count.

A `receipt.v5` signature covers 13 members, not the whole receipt. The
`integrity` check is always `not_applicable`: it recomputes each receipt's
chain hash and compares it with nothing, and it names the receipt whose other
members (`timestamp`, `tool_name`, `executor_id`, `metadata`, `key_id` among
them) nothing covers. That is a single receipt, or the last receipt of a
chain. The `closure` check compares each earlier receipt with its successor's
signed `prev_hash`. `key_id` in the `--json` verdict is such a member: it is
the first receipt's own claim, not the key a signature verified under, and
`key_id_note` says so.
