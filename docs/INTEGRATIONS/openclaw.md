---
title: OpenClaw
last_reviewed: 2026-07-01
---

# OpenClaw

Use HELM as a pre-dispatch boundary for OpenClaw-style skill calls.

```text
OpenClaw skill call
-> fromOpenClawSkillCall(...)
-> HELM evaluate
-> ALLOW: dispatch
-> DENY or ESCALATE: block and write a receipt
```

## Adapter

The supported adapter lives in `helm-agent-integrations`:

```ts
import { fromOpenClawSkillCall, preflightAction } from "@mindburn/helm-tool-wrapper";

const intent = fromOpenClawSkillCall({
  skill: "gmail-send",
  input: {
    to: "ops@example.invalid",
    subject: "Draft follow-up",
  },
  conversation_id: "local-session",
});

const decision = await preflightAction({
  helmUrl: "http://127.0.0.1:7714",
  actionUrn: intent.actionUrn,
  input: intent.input,
  metadata: intent.metadata,
});
```

Dispatch the OpenClaw skill only when HELM returns `ALLOW`. For `DENY` or
`ESCALATE`, show the decision and receipt path to the developer.

## Receipt Sample

The integration repository includes a local sample for an external send that
escalates before dispatch:

```bash
python3 scripts/generate_samples.py --check
python3 scripts/verify_samples.py
cat receipts/samples/openclaw-email-escalate.json
```

## Scope

This page covers the OpenClaw skill-call boundary only. It does not claim
upstream endorsement or a hosted OpenClaw runtime.
