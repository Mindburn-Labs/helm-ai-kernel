# TON Acton Connector

Acton is the TON smart-contract toolchain used for project scaffolding, build,
test, scripting, source verification, and library operations. HELM wraps Acton
so model-proposed TON work crosses PEP/CPI governance before any side effect
can run.

The OSS connector is `ton.acton`. It exposes typed actions such as
`connector.ton.acton.contract.build`, `connector.ton.acton.script.testnet`, and
`connector.ton.acton.source.verify_dry_run`. It does not expose raw shell
commands or a generic `acton` passthrough.

Launch status: preview. TON Acton is not a 0.5.0 launch blocker unless release
CI provides a real `ACTON_BIN` smoke, schema-drift fixtures, connector
EvidencePack verification, approval proof, and release-manifest pin. Without
those artifacts, public copy must say production connector certification is
pending.

## Risk Map

- Local diagnostics: T0/T1
- Build, check, format check, and test: T1
- Coverage, mutation, migration, retrace, forked scripts, and verification
  dry-run: T2
- Testnet broadcast: T2 or T3 depending spend and policy
- Mainnet scripts, mainnet verification transactions, and mainnet library
  publish/top-up: T3 irreversible

## Mainnet Safety

Mainnet broadcast defaults to `ESCALATE`. Dispatch requires a typed action,
valid sandbox grant, wallet reference, spend ceiling, script manifest, expected
effects, compiler pin, policy allowance, approval ceremony, and EvidencePack
requirements.

Generic `acton script --net mainnet` is denied with
`ERR_TON_ACTON_GENERIC_MAINNET_SCRIPT_DENIED`.

## Script Manifest

Networked scripts require a sidecar manifest such as
`contracts/scripts/deploy.helm.json`. The manifest binds script path, script
hash, allowed networks, expected effects, spend caps, wallet ref, and required
preflight checks.

## Wallet Secrets

Wallet references are opaque (`wallet:...`). Plaintext mnemonics, seed phrases,
private keys, API keys, and TON Connect secrets must not appear in workspace
files, args, receipts, EvidencePacks, logs, or UI state.

## EvidencePack Contents

T3 packs include the command envelope, connector contract bundle, P0 ceilings,
policy/CPI/kernel artifacts when supplied, approval ceremony, sandbox grant,
Acton and Tolk versions, source and manifest hashes, build/test/coverage/
mutation/gas/verifier artifacts, receipts, redaction map, and replay
instructions.

## Examples

Allowed local build:

```sh
helm-ai-kernel verify pack <ton-acton-evidencepack>
helm-ai-kernel replay --evidence <ton-acton-evidencepack> --verify
```

Denied mainnet script:

```json
{
  "action_urn": "connector.ton.acton.script.mainnet",
  "generic": true
}
```

Escalated mainnet deployment:

```json
{
  "action_urn": "connector.ton.acton.script.mainnet",
  "approval_ref": "",
  "expected_effects": [{"effect_kind": "TON_DEPLOY"}]
}
```

Commercial surfaces, when implemented, must wrap the OSS connector contract and
must not duplicate connector logic or proof semantics.
