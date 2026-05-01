---
title: Compatibility
---

# Compatibility

This page describes the retained OSS compatibility surface, not every historical adapter or experimental integration that has existed in the repository.

## Supported Public Surfaces

| Surface | Status |
| --- | --- |
| Go kernel and CLI | Supported |
| OpenAI-compatible proxy | Supported |
| MCP server, OAuth resource/scope enforcement, and bundle generation | Supported |
| Evidence export and offline verification | Supported |
| Go SDK | Supported |
| Python SDK | Supported |
| TypeScript SDK | Supported |
| Rust SDK | Supported |
| Java SDK | Supported |

## Framework Adapter Helpers

The TypeScript SDK ships compatibility helpers for normalizing tool-call events from common agent frameworks into HELM governance requests:

| Framework | Status | Test Surface |
| --- | --- | --- |
| LangGraph | Compatible | `sdk/ts/src/adapters/agent-frameworks.test.ts` |
| CrewAI | Compatible | `sdk/ts/src/adapters/agent-frameworks.test.ts` |
| OpenAI Agents SDK | Compatible | `sdk/ts/src/adapters/agent-frameworks.test.ts` |
| PydanticAI | Compatible | `sdk/ts/src/adapters/agent-frameworks.test.ts` |
| LlamaIndex | Compatible | `sdk/ts/src/adapters/agent-frameworks.test.ts` |

## Source Build Expectations

The retained CI verifies:

- Go build and test for the kernel
- Python SDK tests
- TypeScript SDK tests
- Rust SDK build and test
- Java SDK build
- fixture root verification through the Go verifier

## Deployment Surface

The repository keeps a Helm chart under `deploy/helm-chart/` for Kubernetes-based deployment. Interactive clients, static viewers, Node CLI wrappers, and generated browser-rendered reports are outside the retained OSS compatibility surface.

## MCP 2026 Radar Notes

The original Linear radar item pointed at `https://modelcontextprotocol.io/roadmap`; as of April 30, 2026 that URL returns a 404 and the current source is [MCP Roadmap](https://modelcontextprotocol.io/development/roadmap). The current roadmap frames enterprise-managed auth, gateway/proxy authorization propagation, and finer-grained least-privilege scopes as active enterprise/security directions, while RFC 8707 remains the normative OAuth source for resource indicators. HELM OSS implements this as an additive auth and metadata layer; protocol versions and existing tool schemas remain backward compatible.
