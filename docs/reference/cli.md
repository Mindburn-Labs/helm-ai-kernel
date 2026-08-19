---
title: CLI
last_reviewed: 2026-08-19
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
helm-ai-kernel setup hermes --scope user --yes
helm-ai-kernel setup deepseek --scope user --yes
helm-ai-kernel setup codex --dry-run --json
helm-ai-kernel setup --client cursor --print-config
```

Setup writes local client configuration and draft policy artifacts. It does not
approve tools. Hermes setup writes a fail-closed `pre_tool_call` shell hook
only; it does not write MCP. DeepSeek setup writes a Kernel hook file and
points the stock DSH `dsh-hooks-claude-code` bridge `configPath` at it; it
does not add a HELM-native agent runtime and does not claim
`npx @deepseek-ai/dsh web` sees DENY.

## MCP Authorization Commands

Use these commands to inspect the fail-closed MCP boundary:

| Command | Purpose |
| --- | --- |
| `helm-ai-kernel mcp authorize-call --server-id <id> --tool-name <tool>` | Evaluate one MCP tool call before dispatch. |
| `helm-ai-kernel mcp approve --server-id <id> --tools <csv> --ttl 15m --reason <text>` | Returns unavailable until credential verification is configured; it does not create approval authority. |
| `helm-ai-kernel mcp revoke --server-id <id> --reason <text>` | Revoke an existing local MCP registry record. |
| `helm-ai-kernel mcp pending --json` | List servers or tools awaiting credential-verified approval. |
| `helm-ai-kernel mcp receipts --json` | List local MCP boundary records. |
| `helm-ai-kernel mcp get --server-id <id> --json` | Inspect one MCP server record. |

No local command can turn an approver string or receipt-shaped value into an
executable MCP approval. Servers remain quarantined until a credential verifier
is wired to the governing approval authority.

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
helm-ai-kernel verify receipt --receipt <receipt.v5.json> --trusted-public-key-file <expected-ed25519.pub>
```

`ALLOW`, `DENY`, and `ESCALATE` records include a reason code. `DENY` and
`ESCALATE` do not dispatch in enforce mode.

Workstation verification exits successfully only when receipt integrity and
the signer trust anchor both verify. A signature that validates against the
key embedded in a receipt is not, by itself, proof of an expected signer.

`verify receipt` is Foundation/offline verify for a Kernel `receipt.v5`
evaluate file. Exit 0 only when integrity and the caller-supplied
`--trusted-public-key-file` both hold. It is not AI OS live, not
helm-ai-kernel#859, not `--allow-self-attested`, and not
`workstation verify-decision`. Hop fixtures are DENY / no permit.

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
