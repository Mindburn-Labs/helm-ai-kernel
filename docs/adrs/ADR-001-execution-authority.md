# ADR-001: HELM Is Execution Authority, Not Assistant Shell

**Status:** Accepted
**Date:** 2026-04-04

## Context

Multiple agent orchestration frameworks (OpenClaw, Claude Code, Codex, custom MCP clients) provide reasoning and planning capabilities. The market temptation is to build HELM as another assistant shell competing on UX.

## Decision

HELM is the **execution authority layer**, not an assistant shell.

- HELM does not compete with agent shells. It sits beneath them.
- Any agent runtime can reason. Only HELM can execute.
- All external effects MUST cross HELM regardless of the originating runtime.
- HELM-native agents, MCP clients, OpenClaw assistants, and custom orchestrators all use the same execution boundary.

## Consequences

- HELM never owns the "chat" or "reasoning" surface as a primary product.
- The Compatibility and Interception Layer (`runtimeadapters/`) becomes a first-class module.
- Product value is measured by governance authority and receipt integrity, not conversational UX.
- External runtimes are replaceable surfaces; HELM is the non-replaceable substrate.
