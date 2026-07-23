---
title: Troubleshooting
last_reviewed: 2026-07-01
---

# Troubleshooting

Start with the local diagnostic:

```bash
helm-ai-kernel doctor --json
```

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
```

Common causes:

- revoked approval
- expired approval
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

`ESCALATE` means HELM blocked the action and wrote a receipt. The bundled MCP
CLI and API cannot resolve it with local approval metadata; keep the action
blocked. Rerun only after a credential-verifying integration has recorded a
scope-bound approval, and only as a new evaluation.

## Approval Did Not Work

Check scope:

```bash
helm-ai-kernel mcp receipts --json
```

Approvals do not resume a blocked action. They only affect the next evaluation.
If the original action uses a different server, tool, schema, or effect, HELM
must keep blocking it.

## Proxy Has No Receipts

Confirm the app is using HELM as the base URL:

```bash
export OPENAI_BASE_URL=http://127.0.0.1:9090/v1
```

Then inspect receipts:

```bash
helm-ai-kernel receipts tail \
  --agent <agent-id> \
  --server http://127.0.0.1:7714
```

A successful upstream response is not proof that the request crossed HELM.

## Conformance Failure

Run the public levels:

```bash
helm-ai-kernel conform --level L1 --json
helm-ai-kernel conform --level L2 --json
helm-ai-kernel conform negative --json
```

If `L2` fails, inspect MCP quarantine state, schema pins, approval scope,
revocation, expiry, and receipt emission.
