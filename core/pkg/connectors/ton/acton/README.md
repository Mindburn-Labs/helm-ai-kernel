# TON Acton Connector

`ton.acton` is the HELM AI Kernel connector for running the Acton TON smart-contract
toolchain through HELM's deterministic execution boundary.

Acton remains the TON development toolchain. HELM remains the policy,
sandbox, receipt, EvidencePack, and replay authority. The connector exposes
typed Acton command classes only; it does not expose raw shell execution or a
generic `acton` command field.

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
  actions. They default to `ESCALATE` until approval ceremony evidence is
  present and policy explicitly allows dispatch.
- Generic `acton script --net mainnet` is denied.
- Plaintext wallet mnemonics, seed phrases, private keys, and secret values are
  denied and redacted.

## Evidence

Receipts bind the typed command envelope, argv array, sandbox grant hash,
stdout/stderr hashes, Acton/Tolk versions, artifact hashes, drift status, and
transaction metadata when present. EvidencePacks are generated through the
native `evidencepack` package and include replay instructions.

## Commercial Wrapper Policy

Commercial must consume this OSS connector contract. It must not fork command
classification, policy behavior, proof semantics, receipts, or EvidencePack
behavior.
