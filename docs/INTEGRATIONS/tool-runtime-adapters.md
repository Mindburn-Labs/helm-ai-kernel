---
title: Tool Runtime Adapters
last_reviewed: 2026-07-15
---

# Tool Runtime Adapters

Use a runtime adapter only when the owning runtime exposes a concrete call you
can stop before dispatch. The adapter must map that call into the documented
HELM HTTP or SDK contract, wait for the verdict, and keep `DENY` and `ESCALATE`
blocked.

## Source Adapter Inventory

The separately versioned integration source contains mappings for OpenClaw,
Hermes, Mastra, Browser Use, TinyFish, E2B, and Composio call shapes. Source
availability is not a registry-package or client-load claim.

This page intentionally publishes no adapter package install command. Use one of
the verified SDK coordinates on [SDKs](/sdks), or generate a client from the
[public OpenAPI](/openapi.yaml), until a separately released adapter package and
clean registry check exist.

## Required Dispatch Pattern

1. Capture the exact runtime call before its side effect.
2. Map action, resource, context, tenant, and principal into the selected HELM
   contract.
3. Call the local boundary with the documented authentication for that route.
4. Dispatch only on `ALLOW`.
5. Keep `DENY` and `ESCALATE` blocked.
6. Read the source result back when the external system changes state.
7. Retain the decision record and verify the exported evidence offline.

## Release Gate

Do not call an adapter supported from source alone. A public adapter install path
requires a versioned package, registry availability, source-to-package
provenance, a clean install, a routed allow case, blocked deny and escalate
cases, receipt verification, and an explicit support owner.
