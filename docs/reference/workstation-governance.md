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

### Shell classification modes

The hook accepts `--shell-mode`, which selects the fail direction for `Bash`
tool calls. The default is `denylist` through 0.7.x.

`denylist` is the v0.7 shell guard. It is intentionally narrow: it recognizes
only a small set of literal destructive command forms and does not interpret
shell expansion, aliases, `eval`, wrappers, or every destructive tool. A
command it does not recognize proceeds with no verdict and no receipt. Treat it
as a selected-effect guardrail, not a claim of comprehensive shell enforcement.

`allowlist` inverts that posture to match how the same hook already treats
`mcp__` tools. A command is evaluated in two steps:

1. If it is not statically analyzable — it chains, substitutes, redirects, spans
   a newline, or spawns a nested shell — it is denied with reason code
   `SHELL_COMMAND_NOT_STATICALLY_ANALYZABLE`. This check runs first, which is
   what stops `git status && rm -rf /` on the chaining rather than accepting it
   on its first two tokens.
2. Otherwise the command is matched against a recognition list that maps it to
   an action ID such as `git.status` or `shell.read`. It passes only if that ID
   appears in the active profile's `Observe.AllowedActions`. Anything else is
   routed to the policy engine and denied when no operate permission is granted.

The default profile is already a usable allowlist — five read-only actions in
`Observe`, an empty `Operate.Permissions` — so `allowlist` mode works before any
profile is written. The hook reads `<data-dir>/policy/workstation.json` when
present and falls back to that built-in default.

What `allowlist` mode still does not establish: it classifies the *shape* of a
command, not the behavior of the program that command starts. `go test` and
`make build` are recognized because an operator put `shell.test` / `shell.build`
in the profile, which is a statement that running the repository's own tooling
is acceptable. Ambient configuration outside the command line — a
`diff.external` git setting, for instance — is likewise outside what argv
analysis can see.

Migration: `0.7.x` ships `allowlist` as opt-in with `denylist` as the default,
so no upgrade changes behavior. `0.8.0` flips the binary default to `allowlist`,
which is what carries the change to installs whose baked hook command was never
rewritten; `--shell-mode=denylist` remains the escape hatch.

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
