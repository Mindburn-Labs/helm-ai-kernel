---
title: Quickstart
last_reviewed: 2026-08-21
---

# Quickstart

Run HELM locally and prove the boundary before connecting it to a real agent.
No account or model key is required.

## Install

```bash
brew tap mindburn-labs/tap
brew install helm-ai-kernel
helm-ai-kernel --version
```

From source:

```bash
git clone https://github.com/Mindburn-Labs/helm-ai-kernel.git
cd helm-ai-kernel
make build
./bin/helm-ai-kernel --version
```

## Supported Today

| Surface | Public proof |
| --- | --- |
| Install | `brew install helm-ai-kernel` or `make build` |
| Operator TUI | `helm-ai-kernel` or `helm-ai-kernel tui` (escape: `HELM_NO_TUI=1`, `TERM=dumb`). Catalog ranks Doctor/Watch/Policy/Freeze/Threat first. Ceremony is typed `APPROVE`/`DENY` only. |
| Setup inspect | `helm-ai-kernel setup status --format json` |
| Local proof | `helm-ai-kernel mcp proof --json --out ~/.helm-ai-kernel/proofs` |
| Codex setup | `helm-ai-kernel setup codex --dry-run --json` |
| Claude Code setup | `helm-ai-kernel setup claude-code --dry-run --json` |
| Hermes setup | `helm-ai-kernel setup hermes --scope user --dry-run --json` |
| DeepSeek setup | `helm-ai-kernel setup deepseek --scope user --dry-run --json` |
| Cursor / Windsurf / VS Code config | `helm-ai-kernel setup --client cursor --print-config` |
| OpenClaw / Hermes adapters | [tool runtime adapters](INTEGRATIONS/tool-runtime-adapters.md) |
| Framework adapters | [framework adapters](INTEGRATIONS/framework-adapters.md) |
| Skill Packs | `helm-ai-kernel skills search --json` |
| Agent risk scan | `helm-ai-kernel scan --path . --risk-envelope out/risk-envelope.json --preview out/risk-report.md` |
| MCP quarantine and recovery | `mcp authorize-call`, `mcp quarantine`, `mcp pending`, `mcp receipts`, `mcp revoke`; `mcp approve` rejects opaque local approval metadata |
| OpenAI proxy | `helm-ai-kernel proxy --port 9090` |
| Receipts | `helm-ai-kernel receipts status --format json`, `mcp receipts --json`, `boundary records --json` |
| Conformance | `helm-ai-kernel conform --level L1 --json` and `--level L2` |
| SDKs | source clients under `sdk/` with local test targets |

## Prove The Boundary

```bash
helm-ai-kernel mcp proof --json --out ~/.helm-ai-kernel/proofs
```

Expected shape:

```json
{
  "schema_version": "helm.mcp.proof/v1",
  "offline_verified": true,
  "scenarios": [
    { "verdict": "ESCALATE", "dispatched": false },
    { "verdict": "DENY", "dispatched": false }
  ]
}
```

Verify the generated EvidencePack offline:

```bash
helm-ai-kernel verify --bundle ~/.helm-ai-kernel/proofs/<run-id>/evidencepacks/<run-id> --profile dev-local --allow-self-attested --json
```

The explicit opt-in is required because this local proof creates its own
signing key. It proves internal consistency, not provenance.

When the `v0.8.4` GitHub Release publishes an `evidence-pack.tar`, use that
release asset for release verification instead of a local proof bundle. Until
then, the local proof bundle above is the verifiable path.

For the full public flow, see [HELM Proof Loop](PROOF_LOOP.md).

## See An Escalation

Ask HELM to authorize a local MCP action before dispatch:

```bash
helm-ai-kernel mcp authorize-call \
  --server-id helm-governance \
  --tool-name file_read
```

Every verdict prints the same shape: verdict, decision id, reason, and receipt
path. A local quarantine escalation intentionally does not print a command
that could mint approval authority.

```text
HELM ESCALATE
decision: mcp-boundary-...
reason: unknown MCP server remains quarantined; credential verification is unavailable
approval: credential verification unavailable; the server remains quarantined
receipt: data/receipts/mcp/...
```

Nothing runs on `ESCALATE`. Local `helm-ai-kernel mcp approve` is retained only
for compatibility and rejects opaque approver names, receipt ids, tool lists,
and TTLs; it cannot create an MCP approval or side-effect grant.

To progress a bounded action, the governing approval integration must issue an
exact, credential-verified durable dispatch admission. The local CLI
deliberately has no command that can create that admission. A
verifier-backed runtime re-evaluates the exact request, schema pin, policy,
effect scope, expiry, and revocation before it dispatches.

Inspect the local, no-dispatch state and its evidence:

```bash
helm-ai-kernel mcp quarantine --json
helm-ai-kernel mcp pending --json
helm-ai-kernel mcp receipts --json
```

If an existing registry record must be invalidated, revocation remains
available; it never grants authority:

```bash
helm-ai-kernel mcp revoke \
  --server-id helm-governance \
  --reason "inspection finished"
```

See [Deny Reason Codes](guides/deny-reason-codes.md) for the evidence required
to resolve each reason code.

## Connect A Local Agent

See the supported matrix:

```bash
helm-ai-kernel setup --json
```

For Claude Code:

```bash
helm-ai-kernel setup claude-code --yes
```

For Codex:

```bash
helm-ai-kernel setup codex --yes
```

For Hermes (writes a fail-closed `pre_tool_call` hook in
`~/.hermes/config.yaml`; this does not mean Hermes already sees DENY in
the wild, and it does not write MCP):

```bash
helm-ai-kernel setup hermes --scope user --yes
```

For DeepSeek (writes a fail-closed Kernel `PreToolUse` hook in
`~/.dsh/hooks.json` and points the stock DSH `dsh-hooks-claude-code`
bridge `configPath` at that file; this is an adapter hop, not a
HELM-native agent runtime, and it does not mean
`npx @deepseek-ai/dsh web` sees DENY):

```bash
helm-ai-kernel setup deepseek --scope user --yes
```

Preview writes first:

```bash
helm-ai-kernel setup codex --dry-run --json
helm-ai-kernel setup --client cursor --print-config
```

Setup writes local config and draft policy artifacts. It does not approve
detected tools.

## Inspect

```bash
helm-ai-kernel mcp pending --json
helm-ai-kernel mcp receipts --json
helm-ai-kernel boundary records --verdict ESCALATE --json
```

Keep sensitive prompts, provider keys, endpoints, and unredacted receipts out of
public issues.
