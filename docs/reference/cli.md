---
title: CLI
last_reviewed: 2026-08-22
---

<!-- quantum_posture: this page documents CLI use of classical Ed25519 receipt checks and adds no post-quantum cryptographic control. -->

# CLI

Use `helm-ai-kernel` to run the local proof path, connect agent clients, and
inspect receipts.

## Operator Front Door

On an interactive TTY, bare `helm-ai-kernel` (or `tui` / `ui` / `dashboard`)
opens the full-screen operator TUI. Escape hatches keep the text catalog:

```bash
HELM_NO_TUI=1 helm-ai-kernel
TERM=dumb helm-ai-kernel
helm-ai-kernel help --all
helm-ai-kernel help --json
```

Press `?` inside the TUI for the keyboard map. The catalog ranks Doctor,
Watch, Policy, Freeze, and Threat before setup convenience. Ceremony
decisions require typing `APPROVE` or `DENY`; a click never decides. See
[CLI I/O Convention](../guides/cli-io-convention.md#operator-tui).

## First Proof

```bash
helm-ai-kernel mcp proof --json --out ~/.helm-ai-kernel/proofs
helm-ai-kernel verify --bundle ~/.helm-ai-kernel/proofs/<run-id>/evidencepacks/<run-id> --profile dev-local --allow-self-attested --json
```

The explicit opt-in accepts the locally generated seal as proof of internal
consistency, not provenance.

## Local Agent Setup

```bash
helm-ai-kernel
helm-ai-kernel setup status --format json
helm-ai-kernel setup status cursor --format json
helm-ai-kernel setup claude-code --dry-run --format json
helm-ai-kernel setup repair claude-code --dry-run
helm-ai-kernel setup remove claude-code --dry-run
helm-ai-kernel setup --client cursor --print-config
```

Inspect first. Apply, repair, and remove require `--dry-run` or explicit
`--yes` / typed APPROVE. Cursor/VS Code status names the documented config
path and never claims the editor loaded HELM. Windsurf is print-config-only.

Setup JSON reports `client_state` and a projected `lifecycle`
(`absent` / `planned` / `pending` / `configured` / `active` / `degraded` /
`repairable`). Only `native_loaded` is an active claim; Cursor/Windsurf/VS Code
never report `native_loaded`.

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
helm-ai-kernel receipts status --format json
helm-ai-kernel receipts list --format json
helm-ai-kernel receipts show <receipt-id> --format json
helm-ai-kernel receipts verify --receipt <receipt.v5.json> --trusted-public-key-file <expected-ed25519.pub>
helm-ai-kernel receipts export --evidence DIR --out DIR
helm-ai-kernel receipts tail --agent <agent-id>
helm-ai-kernel workstation verify-decision --receipt <receipt.json>
helm-ai-kernel workstation verify-decision --receipt <receipt.json> --trusted-public-key-file <expected-ed25519-public-key>
helm-ai-kernel verify receipt --receipt <receipt.v5.json> --trusted-public-key-file <expected-ed25519.pub>
```

`status`, `list`, and `show` are bounded inspect. `tail` streams SSE and is
refused as a listener inside the operator TUI. `verify` and `export` are
aliases of the existing routes.

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

## EvidencePack Verification And Tape Replay

```bash
helm-ai-kernel verify <pack> --config <trust-config.yaml>
helm-ai-kernel verify <pack> --config <trust-config.yaml> --require-check chain_integrity
helm-ai-kernel verify <pack> --config <trust-config.yaml> --json
helm-ai-kernel replay --evidence <pack-dir>
```

`verify` reports every check as `VERIFIED`, `FAILED`, `UNVERIFIABLE` or
`NOT_RUN`, and prints the passed, failed and not-run counts separately. A
check the pack gives no input to is `NOT_RUN` and is never counted as passed.
Exit 0 means `VERIFIED`: no check failed and every required check ran and
held; checks that did not run are listed with the reason. Exit 1 means
`FAILED` or `UNVERIFIABLE`; exit 2 means no verdict. `--require-check` names
checks that must have run and fails the pack when one did not. Repeat the flag
or separate names with commas; every named check is required, and a name that
is not a check exits 2. Evidence that is present is validated whether or not
anything requires it. See
[Receipts](../VERIFICATION.md#what-the-result-covers) for each check and what
requires it.

`evidence inspect <pack>` reaches the same verdict through the same code and
exits the same way, in text and `--json` mode. Text output of these commands
shows control characters, line breaks and characters that print as blank
space from the pack as visible escapes, and a backslash as `\\`; `--json`
keeps the raw values. Every check except `roots` and `evidence_pack_seal`,
including `--require-eidas` and `--require-tee`, reads the pack through an
`os.Root` on its directory: a path or symbolic link that leaves the pack, an
absolute symbolic link and a file that is not a regular file fail the check
that wanted them. The seal code those two use reads by path under its own
rules, and the layout check tests whether files exist by path; both are
described in [Receipts](../VERIFICATION.md#what-the-result-covers).

`replay` serves an EvidencePack's recorded tape (`08_TAPES`) back through the
tape replayer and reports `COMPLETE`, `DIVERGED` or `NOT_RUN`. Exit 0 only
for `COMPLETE`: the entry files are in the order of the number in their name
and in sequence order, every entry was served and matches its recorded hash,
every entry has a type the recorder writes, every manifest row carries `seq`,
`type`, `key`, `sha256` and `size_bytes`, and every field the tape manifest
carries for an entry equals that entry. It replays recorded inputs; it does
not re-execute the run, and it does not check the pack seal, so run `verify`
on the pack as well; `verify` replays the tape with the same code. A symbolic
link in place of the tape directory or a tape file, or a tape file that does
not parse, exits 2; with `--json` the result is still printed, with
`replay_status` `NOT_RUN` and the reason in `error`.

## Doctor

```bash
helm-ai-kernel doctor --format json
helm-ai-kernel diag --format json   # alias
```

Doctor reports PASS / WARN / FAIL checks and a `healthy` boolean. Suggestions
point at inspect-first setup commands (`setup status`, `setup repair … --dry-run`);
they do not recommend `--yes`. Exit 0 means no WARN/FAIL; exit 1 means WARN
only; exit 2 means one or more FAIL.

## OpenAI-Compatible Proxy

```bash
helm-ai-kernel proxy \
  --upstream https://api.openai.com/v1 \
  --port 9090 \
  --receipts-dir ./helm-receipts
```

Point an OpenAI-compatible client at `http://127.0.0.1:9090/v1`.

## Format Contract

Operator-data commands accept `--format text|json` (legacy `--json` stays as
an alias). Unknown formats exit 2. Collision verbs (`verify`, `import`,
`skills`) keep domain `--format` meanings. Listeners and `tui` are exempt from
emitting a JSON operator document. Details:
[CLI I/O Convention](../guides/cli-io-convention.md).

## Help

```bash
helm-ai-kernel help
helm-ai-kernel help --all
helm-ai-kernel mcp --help
helm-ai-kernel verify --help
```
