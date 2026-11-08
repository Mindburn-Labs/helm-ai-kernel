# TON Acton Connector

`ton.acton` is the HELM AI Kernel connector for running the Acton TON smart-contract
toolchain through HELM's deterministic execution boundary.

Acton remains the TON development toolchain. HELM remains the policy and
receipt authority. The connector exposes typed Acton command classes only; it
does not expose raw shell execution or a generic `acton` command field.

helm-gateway links this package through `core/pkg/gateway/adapters/tonacton`
(see `controls.yaml` CTL-061). That adapter performs a subset of the command
classes below: local work, forks, and four testnet operations. It refuses every
mainnet operation and `script.testnet` at admission, and runs the operations
that execute tenant files only through an operator-configured isolation
command. The mainnet and script paths described here remain in the package as
connector policy that the gateway does not reach.

## Supported Command Classes

- Project and diagnostics: `project.new`, `project.init`, `doctor`, `env`, `version`
- Build and validation: `contract.build`, `contract.check`, `contract.format`,
  `contract.format_check`, `contract.test`, coverage, mutation, wrappers,
  compile, disasm, docs, retrace, and `func2tolk`
- Scripts: local, forked testnet/mainnet read-only, typed testnet broadcast,
  and typed mainnet broadcast
- Verification: dry-run, testnet, and mainnet source verification
- Libraries: info, fetch, testnet/mainnet publish, and testnet/mainnet top-up
- Wallet/RPC: wallet list and read-only RPC query

## Safety Model

- Local build/check/fmt/test actions require sandbox grants and deterministic
  receipts.
- Networked scripts require a HELM sidecar script manifest with script hash,
  expected effects, wallet reference, and spend caps.
- Testnet broadcast requires policy allowance, wallet scope, spend cap, network
  grant, and expected effects.
- Mainnet broadcast and mainnet library publish/top-up are T3 irreversible
  actions. The connector's own policy escalates them until approval ceremony
  evidence is present; helm-gateway never reaches that path because it refuses
  every mainnet operation at admission (`ERR_TON_MAINNET_REFUSED`).
- Generic `acton script --net mainnet` is denied.
- Plaintext wallet mnemonics, seed phrases, private keys, and secret values are
  denied and redacted.

## Evidence

Receipts bind the typed command envelope, argv array, sandbox grant hash,
stdout/stderr hashes, Acton/Tolk versions, artifact hashes, drift status, and
transaction metadata when present. This package builds no EvidencePack; the
builder was removed, and `acton_evidence.schema.json` is non-normative.

## Commercial Wrapper Policy

Commercial must consume this OSS connector contract. It must not fork command
classification, policy behavior, proof semantics, receipts, or EvidencePack
behavior.
