# TON Acton Connector

Acton is the TON smart-contract toolchain used for project scaffolding, build,
test, scripting, source verification, and library operations. HELM wraps Acton
so model-proposed TON work crosses PEP/CPI governance before any side effect
can run.

> Status: linked into `core/cmd/helm-gateway` as the `ton.acton.*` effect types
> (`controls.yaml` CTL-061), for local, fork and testnet operations only. It is
> not linked into `core/cmd/helm-ai-kernel`.
>
> - Every mainnet operation and `script.testnet` are refused at admission
>   (`ERR_TON_MAINNET_REFUSED`, `ERR_TON_TENANT_CODE_WITH_KEY_REFUSED`).
> - Operations that run Acton over tenant files need
>   `HELM_GATEWAY_TON_ACTON_ISOLATION_CMD`. Without it they are not declared.
> - The mainnet, script-manifest and EvidencePack text below describes the
>   connector package's own policy; helm-gateway does not reach it.

The OSS connector is `ton.acton`. It exposes typed actions such as
`connector.ton.acton.contract.build`, `connector.ton.acton.script.testnet`, and
`connector.ton.acton.source.verify_dry_run`. It does not expose raw shell
commands or a generic `acton` passthrough.

Launch status: preview. TON Acton is not a 0.5.1 launch blocker unless release
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

## EvidencePacks

The connector builds no EvidencePack. The builder was removed when the package
was linked into helm-gateway, and `acton_evidence.schema.json` is non-normative.
An Acton effect's evidence is the gateway's signed decision and outcome receipts
and the typed `ton.acton.result.v1` result.

## Examples

Allowed local build: propose `ton.acton.contract.build` with target
`ton-acton:<project>` and `{"schema":"helm.ton.acton.contract.build.v1"}`.

Refused mainnet script: proposing `ton.acton.script.mainnet` fails at Propose
with `ERR_TON_MAINNET_REFUSED`.

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
