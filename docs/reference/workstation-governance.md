<!-- quantum_posture: this page documents workstation flows that use classical Ed25519 receipts and does not claim post-quantum protection. -->

# Workstation Governance

HELM workstation governance starts as a manifest-first proof surface for local coding-agent runs and adds a selected-effect CLI/hook enforcement bridge. It does not claim HELM controls every Codex, Claude Code, IDE, browser, or desktop action. The adapter imports artifact sets, maps them into ProofGraph nodes, emits signed Agent Run Receipts, and can produce signed policy decision receipts that wrapper scripts must obey.

## Current mode

The first profile is `workstation.observe_draft.v1`.

| Class | Meaning | M0-M2 behavior |
| --- | --- | --- |
| Observe | Read-only inspection, git status or diff, tests, builds, and validation commands. | Imported and receipted. |
| Draft | Workspace-scoped file edits and generated artifacts. | Imported and receipted as draft effects. |
| Operate | Network egress, MCP mutation, durable memory writes, recurring loops, deploys, publishes, payments, and secret-sensitive actions. | Fails closed in policy evaluation when no explicit permission exists. The `workstation enforce` CLI refuses selected denied effects before running a wrapped command. |

An empty egress allowlist denies network egress. Empty operate permissions deny operate-class effects. Memory writes are represented as effects with TTL and sensitivity so they can enter review queues later instead of becoming implicit agent memory.

## Artifact set

`helm-ai-kernel workstation import --artifacts <dir>` expects:

- `run.manifest.json`
- `git.diff-summary.json`
- `validation.json`
- optional `tool-events.ndjson`
- optional `policy-profile.json`

The importer hashes each artifact, maps the goal to an `INTENT` node, maps source artifacts to an `ATTESTATION` node, maps file/tool/memory/deny records to `EFFECT` nodes, and emits a `CHECKPOINT` node for the signed receipt reference.

## Receipt viewer

Use the viewer when an operator needs the run summary without reading the original conversation:

```bash
helm-ai-kernel workstation import --artifacts fixtures/workstation/denied-network --out /tmp/workstation-receipt.json
helm-ai-kernel workstation view --receipt /tmp/workstation-receipt.json
```

### Local signer and trusted verification

The first local import, decision, capture, or installed hook provisions one
Ed25519 signer for that HELM data directory. The private seed stays at
`~/.helm-ai-kernel/keys/workstation-ed25519.seed` with `0600` permissions; the
directory has `0700` permissions. Its public key is written next to it as
`workstation-ed25519.pub`. This is a local trust anchor, not a HELM release or
vendor signing key.

If the process has no resolvable home directory, pass an explicit `--data-dir`.
HELM will not create a private key relative to the current working directory.

`workstation view` and `workstation verify-decision` report two separate
results. `integrity` says the receipt was not altered relative to the public
key named inside it. `signer trusted` says that named key matches the expected
local or caller-supplied public key. Both must be `true` for a successful
verification exit code. When verifying a copied receipt on another machine,
supply a separately trusted public-key file:

```bash
helm-ai-kernel workstation verify-decision \
  --receipt /tmp/network-deny.json \
  --trusted-public-key-file ./workstation-ed25519.pub
```

Older receipts made with the retired deterministic signer can still be read
for integrity and migration, but are not trusted. Reissue them with the local
signer rather than treating the legacy key as a trust root.

### Approved signer sources and rotation

Production mode (`HELM_PRODUCTION=1`) never creates a local signer or treats
the adjacent local public-key file as a trust anchor. Signing requires an
explicit `--signing-seed-file`; verification requires either an explicit
`--trusted-signers-file` or the compatibility-only single
`--trusted-public-key-file`. Missing, zero, malformed, unknown, or retired
signer material fails closed.

`--trusted-signers-file` is a caller-owned JSON allowlist. It carries public
keys only, has version `workstation-receipt-trust-store.v1`, and rejects
unknown fields, duplicate keys, key-ID substitution, and symlinks. A retired
source-derived signer can never produce a trusted result:

```json
{
  "version": "workstation-receipt-trust-store.v1",
  "signers": [
    {
      "key_id": "ed25519:<public-key-hex>",
      "public_key": "<public-key-hex>"
    }
  ]
}
```

Deliver this public file through the deployment's approved configuration
channel; the Kernel does not fetch it, generate it, or accept a receipt-bundled
key as trust authority. For rotation, first distribute a store containing the
current and replacement public keys, then switch the explicit signing seed,
verify both receipt generations, and retain the old key for the required
evidence-retention window. Remove a compromised key immediately after the
replacement store is present; receipts from that key then remain readable for
integrity but are no longer trusted.

Local development keeps the single generated signer and adjacent public key as
a migration-safe convenience. It is not available as an implicit production
fallback.

For a classified hook operation, failure to provision the local signer or
persist a denial receipt results in an explicit hook denial. HELM does not
substitute an unsigned or fabricated receipt. If it cannot write the hook
denial protocol at all, it returns the client blocking status instead of a
successful hook exit.

## Enforcement bridge

Selected workstation effects can be evaluated and recorded:

```bash
helm-ai-kernel workstation decide \
  --class network \
  --target https://forbidden.example \
  --out /tmp/network-deny.json

helm-ai-kernel workstation enforce \
  --class network \
  --target https://forbidden.example \
  --out /tmp/network-deny.json
```

`decide` emits a signed policy decision receipt. `enforce` emits the same receipt and exits with code `126` on `DENY`, which makes it usable from shell hooks or wrapper scripts. The bridge covers selected shell, network, MCP, file, memory, and recurring-loop classes; it is not a kernel driver, browser controller, or complete OS sandbox.

The v0.7 shell guard is intentionally narrow. It recognizes only a small set
of literal destructive command forms and does not interpret shell expansion,
aliases, `eval`, wrappers, or every destructive tool. Treat it as a
selected-effect guardrail, not a claim of comprehensive shell enforcement.

## Operator workflow

The local operator read model answers the M4 questions from receipts:

```bash
helm-ai-kernel workstation list --input fixtures/workstation/reference/receipts
helm-ai-kernel workstation denied --input fixtures/workstation/reference/receipts
helm-ai-kernel workstation memory --input fixtures/workstation/reference/receipts
helm-ai-kernel workstation loops --input fixtures/workstation/reference/receipts
```

This renders run list, receipt detail references, denied action timeline, memory review queue, and recurring loop registry from receipts only.

Enterprise Console exposes the same read model as workspace-scoped API routes after a receipt or decision receipt is imported:

- `POST /api/v1/workspaces/{id}/workstation/receipts/import`
- `GET /api/v1/workspaces/{id}/workstation/runs`
- `GET /api/v1/workspaces/{id}/workstation/runs/{run_id}`
- `GET /api/v1/workspaces/{id}/workstation/denied`
- `GET /api/v1/workspaces/{id}/workstation/memory`
- `GET /api/v1/workspaces/{id}/workstation/loops`

The run detail route returns sanitized receipt fields and operator queues, not raw chat transcript bodies.

## Agent Scope Audit

Use `audit scope` when a B2B reviewer needs one report across high-impact agent boundaries instead of separate operator queues:

```bash
helm-ai-kernel audit scope \
  --input fixtures/workstation/reference/receipts \
  --out /tmp/helm-scope-audit \
  --evidence-pack
```

The command accepts `AgentRunReceipt` and `WorkstationPolicyDecisionReceipt` JSON files or directories. It writes `scope-audit.json`, `scope-audit.md`, `evidence-refs.json`, and, when `--evidence-pack` is set, `scope-audit-evidencepack/`. Add `--json` to print the canonical report JSON to stdout.

The report groups events into `mcp`, `filesystem`, `network`, `memory`, `secret`, `deploy`, `payment`, `loop`, and `shell`. It counts allowed, denied, tainted, and unknown actions; lists out-of-scope attempts; records missing controls; summarizes memory TTL/sensitivity/review state; and preserves source receipt hashes and signature presence. Secret, deploy, and payment details are metadata conventions in v1 (`secret_ref`, `lease_ref`, `redaction_ref`, `environment`, `artifact_digest`, `approval_ref`, `rollback_ref`, `verification_ref`, `amount`, `currency`, `counterparty_ref`, `spend_cap_ref`, `idempotency_key`, `ledger_ref`) so existing receipt compatibility is preserved.

`audit scope` is an audit and evidence export over HELM-owned receipts, wrapper decisions, and imported artifacts. It does not imply OS-wide control, full browser control, hosted Console enforcement, or control of proprietary hosted agents unless the relevant action passed through HELM receipts, wrappers, or adapters.

## Conformance and proof

The conformance entrypoint is:

```bash
helm-ai-kernel workstation certify \
  --fixtures fixtures/workstation \
  --mode high-risk-effect-capable
```

Reference receipts live under `fixtures/workstation/reference/receipts/`. A sample EvidencePack lives under `fixtures/workstation/sample-evidencepack/`.

## Boundaries

This feature is not full desktop enforcement. Public copy should say “manifest-first,” “selected-effect enforcement bridge,” and “receipted wrapper/hook path.” For proprietary hosted agents, HELM governs only artifacts and effects that pass through the adapter or wrapper.

Related market context:

- OpenAI describes Codex local, mobile, and remote environment workflows where files, credentials, permissions, and setup stay on the operating machine: <https://openai.com/index/work-with-codex-from-anywhere/>
- OpenAI describes the Codex App Server event model as JSON-RPC over stdio for client-facing agent events and approvals: <https://openai.com/index/unlocking-the-codex-harness/>
- OpenAI describes managed network policy, rules, and OTel audit logs for Codex safety posture: <https://openai.com/index/running-codex-safely/>
