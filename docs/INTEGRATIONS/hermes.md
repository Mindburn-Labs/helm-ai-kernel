---
title: Hermes
last_reviewed: 2026-07-01
---

# Hermes

Use HELM as a pre-dispatch boundary for Hermes tool proposals.

```text
Hermes tool proposal
-> fromHermesToolCall(...)
-> HELM evaluate
-> ALLOW: dispatch
-> DENY or ESCALATE: block and write a receipt
```

## Adapter

The supported adapter lives in `helm-agent-integrations`:

```python
from helm_tool_wrapper import from_hermes_tool_call, preflight_action

intent = from_hermes_tool_call({
    "tool_name": "terminal",
    "arguments": {"command": "rm -rf ./secrets"},
    "task_id": "local-task",
})

decision = preflight_action(
    helm_url="http://127.0.0.1:7714",
    action_urn=intent.action_urn,
    input=intent.input,
    metadata=intent.metadata,
)
```

Dispatch the Hermes tool only when HELM returns `ALLOW`. For `DENY` or
`ESCALATE`, keep the tool blocked and show the decision and receipt path.

## Receipt Sample

The integration repository includes a local sample for a destructive shell
proposal that is denied before dispatch:

```bash
python3 scripts/generate_samples.py --check
python3 scripts/verify_samples.py
cat receipts/samples/hermes-dangerous-shell-deny.json
```

## Scope

This page covers the Hermes tool-call boundary only. It does not claim upstream
endorsement or a hosted Hermes runtime.
