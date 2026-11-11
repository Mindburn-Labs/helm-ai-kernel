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

### What The Result Covers

Every check in the report ends in one of four states:

| Status | Meaning |
| --- | --- |
| `VERIFIED` | The check read its input and the property held. |
| `FAILED` | The property did not hold, or evidence the pack is required to carry is missing. |
| `UNVERIFIABLE` | The material is intact, but no trust root you configured vouches for the signer. |
| `NOT_RUN` | The pack carries nothing for this check to read, and nothing requires it. |

A `NOT_RUN` check is never counted as passed. The result states the passed,
failed and not-run counts separately, names each check that did not run with
the reason, and says when a `VERIFIED` result covers only part of the checks:

```text
envelope ep_2eaf090b3964 · seal valid · sig 1/1 · trust dev-local
VERIFIED · sealed <sealed-at> · anchor local-only · storage local-only
checks: 5 passed, 0 failed, 8 not run; this result covers only the checks that ran
  not run: file_hashes: pack has no manifest.json, so there are no manifest hashes to compare
  not run: chain_integrity: 1 receipts carry no prev_hash: this pack asserts no chain of custody, so there is no chain to check
  ...
```

| Check | What a `VERIFIED` result establishes | `NOT_RUN` when |
| --- | --- | --- |
| `structure` | The pack is a directory that holds `00_INDEX.json` or `manifest.json`. | Never; a missing pack fails. |
| `index_integrity` | Every file listed in `00_INDEX.json` is present and matches its SHA-256. | The pack has no `00_INDEX.json`, or it lists no entries. |
| `roots` | The manifest root hash and Merkle root were derived from `00_INDEX.json`. The seal check compares them. | The pack has no `00_INDEX.json`. |
| `evidence_pack_seal` | The seal signature verifies under your trust root (with `--allow-self-attested`, under the key the seal carries), the seal matches the pack inventory with no unindexed file, and the anchor and storage rules of the trust profile hold. | Never; a missing seal fails. |
| `file_hashes` (reported as `hash:<file>`) | Every file named in `manifest.json` `file_hashes` matches its SHA-256. | The pack has no `manifest.json`, or it declares no `file_hashes`. |
| `eu_ai_act_profile` | Each embedded `eu_ai_act_profile` carries the fields its role and risk category require. The referenced records are not resolved. | No JSON file in the pack carries one. |
| `connector_evidence` | Each connector evidence record declares the required `sha256:` hashes and references. The hashes are not recomputed. | The pack has no `connector_evidence.json`. |
| `chain_integrity` | Receipts link from genesis to head through `prev_hash` with no fork, gap or cycle. | No receipt carries a `prev_hash`: the pack asserts no chain. |
| `lamport_monotonicity` | Along each chain the Lamport clock starts at 1 and increases by one. | No receipt carries a `prev_hash`. |
| `policy_decision_hashes` | Every MCP policy receipt carries `output_hash`, `args_hash` and `signature`, or, in a pack without such receipts, at least one receipt carries a `decision_hash`; the detail gives the count. Presence only; the hashes are not recomputed. | Never; a pack in which no receipt carries a binding fails. |
| `replay_determinism` | The replay evidence gate `G2` names is present and consistent with itself: `08_TAPES/tape_manifest.json` parses, `02_PROOFGRAPH/determinism_manifest.json` states equal `live_hash` and `replay_hash`, and `05_DIFFS` holds no files. Nothing is replayed, and the two hashes are the pack's own statements. | `00_INDEX.json` `gates` does not declare `G2`. |
| `host_evidence` (reported per chain file as `<file>:external_host:<check>`) | Host receipt chains parse, hash, link and verify under `--external-host-public-key`. | The pack has no chain file under `host_evidence/` or `11_HOST_EVIDENCE/`. |
| `embedded_signature_trust` | Signatures declared on receipts and attestations verify against configured trust roots, or, under `dev-local`, against keys the sealed pack carries, which the result names as self-attested. Witness signatures are checked only against witness keys the caller configures. | No receipt or attestation declares a signature. |

Whether missing evidence is `FAILED` or `NOT_RUN` follows from what requires it:

- The pack format: an index or manifest, the seal, a proof graph, receipts and
  a policy decision binding on at least one of them. Missing any of these is
  `FAILED`.
- What the pack declares about itself: `G2` in `00_INDEX.json` `gates`
  requires the replay evidence; a receipt with a `prev_hash` claims a chain,
  and then every receipt must link. Evidence that is present must validate.
- The trust profile: `customer` and `high-assurance` require anchor and
  storage receipts, checked inside `evidence_pack_seal`.
- What you require: `--require-check <names>` turns a named check that would
  be `NOT_RUN` into `FAILED`; `--require-eidas` and `--require-tee` add their
  own checks.

Everything else is optional, and a pack without it leaves the check `NOT_RUN`.

```bash
helm-ai-kernel verify evidence-pack.tar --config <trust-config.yaml> \
  --require-check chain_integrity,connector_evidence
```

Exit code `0` means `VERIFIED`: no check failed and every required check ran
and held. It does not mean every check ran; read the counts. Exit code `1`
means `FAILED` or `UNVERIFIABLE`, and `2` means no verdict was reached (a
missing path, an unreadable archive, an unknown flag or check name).

`--json` reports the same result as `outcome`, `check_counts` and a `status`
on every entry of `checks`. `pass` is `true` only for a `VERIFIED` check, so
read `status` to tell a failure from a check that did not run. The schema is
`protocols/json-schemas/cli/helm_cli_schema.json`.

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

EvidencePacks are portable proof bundles for local review and offline
verification.

### Replay A Recorded Tape

```bash
helm-ai-kernel replay --evidence <evidence-pack-dir>
```

`replay` reads `08_TAPES/tape_manifest.json` and the `entry_*.json` files
beside it, and serves the recorded entries back through the tape replayer in
sequence. It reports `COMPLETE` (exit 0) only when every entry was served with
no tape miss, each served value matches the hash recorded on its entry, and
the tape and the manifest name the same entries with the same hashes.
Anything else is `DIVERGED` (exit 1) with the issues listed. A tape with no
entries is `NOT_RUN` (exit 1): nothing was replayed. `--verify` also requires
`data_class` on every entry.

This replays recorded inputs only. The command has the tape, not the code and
policy that consumed it, so it does not re-execute the run or compare
decisions.

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
KERNEL_RELEASE_TAG=v0.8.5 make verify-cosign COSIGN_ARTIFACT_DIR=<download-dir>
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
`--key-file` that cannot be read, or a receipt file that does not parse as a
receipt, receipt array or bundle. See [LLM audit receipts](use-cases/llm-audit-receipts.md) for what a verified
result does and does not establish.
