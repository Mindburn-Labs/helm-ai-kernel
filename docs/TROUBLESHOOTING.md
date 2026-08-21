---
title: Troubleshooting
last_reviewed: 2026-08-21
---

# Troubleshooting

Start with the local diagnostic:

```bash
helm-ai-kernel doctor --format json
```

Interactive TTY opens the operator TUI by default. Keep the text front door
with `HELM_NO_TUI=1`, `TERM=dumb`, or a pipe. Inside the TUI, `?` shows the
keyboard map; Esc closes overlays; `q` quits.

## No HELM Server

Check the local boundary:

```bash
curl http://127.0.0.1:7714/healthz
export HELM_URL=http://127.0.0.1:7714
```

`helm-ai-kernel serve --policy` is the quickstart boundary. `helm-ai-kernel
server` is the broader local API server and may use a different port.

## Unexpected DENY

Read the receipt first:

```bash
helm-ai-kernel boundary records --json
helm-ai-kernel mcp receipts --json
helm-ai-kernel receipts status --format json
```

Common causes:

- revoked admission
- expired admission
- unapproved tool
- effect mismatch
- schema drift
- policy-forbidden action

A definitive `DENY` should not be retried as if it were a network error.

## Unexpected ESCALATE

Inspect pending escalations:

```bash
helm-ai-kernel mcp pending --json
```

`ESCALATE` means HELM blocked the action and wrote a receipt. Nothing
dispatches. Local `helm-ai-kernel mcp approve` rejects opaque approver
metadata and does not create authority. A credential-verified durable
dispatch admission from the governing approval integration must cover the
exact server, tool, effect, TTL, and reason before you rerun the original
action.

See the escalation path in [Quickstart](QUICKSTART.md#see-an-escalation).

## Approval Did Not Work

Check scope:

```bash
helm-ai-kernel mcp receipts --json
```

Admissions do not resume a blocked action. They only affect the next
evaluation. If the original action uses a different server, tool, schema, or
effect, HELM must keep blocking it. Ceremony typing in the operator TUI
(`APPROVE` / `DENY`) never invents a grant that the Kernel did not already
have pending.

## Proxy Has No Receipts

Confirm the app is using HELM as the base URL:

```bash
export OPENAI_BASE_URL=http://127.0.0.1:9090/v1
```

Then inspect receipts:

```bash
helm-ai-kernel receipts list --format json
helm-ai-kernel receipts tail \
  --agent <agent-id> \
  --server http://127.0.0.1:7714
```

`tail` streams SSE and is refused as a listener inside the operator TUI;
prefer `status` / `list` / `show` for bounded inspect.

A successful upstream response is not proof that the request crossed HELM.

## Conformance Failure

Run the public levels:

```bash
helm-ai-kernel conform --level L1 --json
helm-ai-kernel conform --level L2 --json
helm-ai-kernel conform negative --json
```

If `L2` fails, inspect MCP quarantine state, schema pins, admission scope,
revocation, expiry, and receipt emission.
