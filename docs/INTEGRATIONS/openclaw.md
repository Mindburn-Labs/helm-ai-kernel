---
title: OpenClaw
last_reviewed: 2026-07-15
---

# OpenClaw

The integration source includes a mapping for OpenClaw-style skill calls. It is
a source adapter, not a published registry install surface and not evidence of
upstream endorsement.

```text
OpenClaw-style skill call
-> source adapter maps the action
-> documented local HELM HTTP or SDK contract
-> ALLOW: the owning wrapper may dispatch
-> DENY or ESCALATE: the owning wrapper stays blocked
-> source read-back and receipt verification
```

## Use Today

Use one of the verified clients on [SDKs](/sdks), or generate a client from the
[public OpenAPI](/openapi.yaml). Keep the call in your own wrapper until HELM
returns its verdict. Do not install an unpublished adapter package.

## Evidence Required Before Dispatch

- exact skill and action mapping;
- bounded credential and resource scope;
- local HELM base URL and route authentication;
- blocked `DENY` and `ESCALATE` cases;
- explicit `ALLOW` executor owned by the wrapper;
- source-system result read-back;
- receipt or EvidencePack verification; and
- rollback, revocation, and support ownership.

## Scope

This page covers the source mapping and required boundary contract only. It does
not claim a hosted OpenClaw runtime, automatic interception, or a released
adapter package.
