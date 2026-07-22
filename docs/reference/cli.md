---
title: CLI
last_reviewed: 2026-07-16
---

<!-- quantum_posture: this page documents CLI use of classical Ed25519 receipt checks and adds no post-quantum cryptographic control. -->

# CLI

Use `helm-ai-kernel` to run the local proof path, connect agent clients, and
inspect receipts.

## First Proof

```bash
helm-ai-kernel mcp proof --json --out ~/.helm-ai-kernel/proofs
helm-ai-kernel verify --bundle ~/.helm-ai-kernel/proofs/<run-id>/<run-id> --profile dev-local --json
```

## Local Agent Setup

```bash
helm-ai-kernel
helm-ai-kernel setup
helm-ai-kernel setup --json
helm-ai-kernel setup claude-code --yes
helm-ai-kernel setup codex --yes
helm-ai-kernel setup codex --dry-run --json
helm-ai-kernel setup --client cursor --print-config
```

Setup writes local client configuration and draft policy artifacts. It does not
approve tools.

## MCP Approval Commands

Quickstart owns the full approval loop and rerun rule. Use these commands when
you need the reference form:

| Command | Purpose |
| --- | --- |
| `helm-ai-kernel mcp authorize-call --server-id <id> --tool-name <tool>` | Evaluate one MCP tool call before dispatch. |
| `helm-ai-kernel mcp approve --server-id <id> --tools <csv> --ttl 15m --reason <text>` | Approve an exact local server/tool scope. |
| `helm-ai-kernel mcp approve --server-id <id> --tools <csv> --effects side_effect --ttl 15m --reason <text>` | Approve a side-effect tool scope. |
| `helm-ai-kernel mcp revoke --server-id <id> --reason <text>` | Revoke a local approval. |
| `helm-ai-kernel mcp pending --json` | List servers or tools still awaiting approval. |
| `helm-ai-kernel mcp receipts --json` | List local MCP boundary records. |
| `helm-ai-kernel mcp get --server-id <id> --json` | Inspect one MCP server record. |

See [Quickstart](/quickstart#see-an-escalation) for the expected terminal
message and revoke flow.

## Boundary Inspection

```bash
helm-ai-kernel boundary status --json
helm-ai-kernel boundary records --verdict ESCALATE --json
helm-ai-kernel boundary verify --record-id <record-id> --json
```

## Receipts

```bash
helm-ai-kernel receipts tail --agent <agent-id>
helm-ai-kernel workstation verify-decision --receipt <receipt.json>
helm-ai-kernel workstation verify-decision --receipt <receipt.json> --trusted-public-key-file <expected-ed25519-public-key>
helm-ai-kernel workstation verify-decision --receipt <receipt.json> --trusted-signers-file <caller-owned-trust-store.json>
```

`ALLOW`, `DENY`, and `ESCALATE` records include a reason code. `DENY` and
`ESCALATE` do not dispatch in enforce mode.

Workstation verification exits successfully only when receipt integrity and
the signer trust anchor both verify. A signature that validates against the
key embedded in a receipt is not, by itself, proof of an expected signer.
Production verification requires an explicit public-key or signer-store source;
the local development anchor is never an implicit production fallback.

## OpenAI-Compatible Proxy

```bash
helm-ai-kernel proxy \
  --upstream https://api.openai.com/v1 \
  --port 9090 \
  --receipts-dir ./helm-receipts
```

Point an OpenAI-compatible client at `http://127.0.0.1:9090/v1`.

## Help

```bash
helm-ai-kernel help
helm-ai-kernel help --all
helm-ai-kernel mcp --help
helm-ai-kernel verify --help
```
