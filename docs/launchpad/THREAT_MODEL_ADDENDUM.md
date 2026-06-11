---
title: Launchpad Threat Model Addendum
last_reviewed: 2026-05-20
---

# Launchpad Threat Model Addendum

Status: GA claim guard for Launchpad local-container support.

## Scope

This addendum records the residual risks that must stay visible in Launchpad
claims, docs, receipts, and conformance evidence.

## Isolation Tiers

`local-container` uses Docker hardening as the baseline developer substrate:
capability drop, no-new-privileges, read-only root filesystem, resource limits,
deny-by-default networking, and scoped workspace mounts. That baseline is not a
hostile-agent isolation claim.

Hostile-agent claims require a hardened isolation tier with receipt evidence:
Docker rootless/user namespace remapping, Docker Enhanced Container Isolation,
gVisor, Kata/Firecracker, or a dedicated VM substrate. Unsupported or
unconfigured modes must fail closed before launch.

## Egress And Prompt Data

The launch-owned egress proxy validates CONNECT destinations against the
embedded BYO model-provider catalog and emits allow/deny receipts. CONNECT
payload contents remain encrypted and opaque to the proxy. Without token-broker
or L7 model-gateway enforcement, Launchpad can claim only destination
enforcement: catalog-backed provider egress with receipt-backed proxy control.

Any claim that sensitive prompt contents could not leave the runtime requires
separate model-gateway inspection, scoped token issuance, or broker receipts.

## MCP Mediation

MCP claims require proof that every advertised path reaches the governed
executor before dispatch: stdio, HTTP JSON-RPC, `/mcp/v1/execute`, generated
client configs, MCPB/plugin packaging, and subprocess wrapper profiles. The
proof harness must include negative cases for unknown tools, schema drift,
side-effect tools without approval receipts, and unapproved servers.

WebSocket MCP is not a supported Launchpad transport. Any future WebSocket path
must be added to the mediation proof harness before it appears in public claims.

## Supported App Claim Boundary

OpenClaw and Hermes are the current live local-container set after workflow
`26198407296` passed signed artifact build, contract preflight, SBOM,
vulnerability scan, live model-provider launch, teardown, and offline
EvidencePack verification. OpenCode and Kilo Code are `verify_only`; `--version`
smoke checks do not count as live-agent F2 coverage.

Any app outside that four-app set remains non-marketable as supported until the
same evidence refs are present in the registry and the docs-truth gate passes.

## External Risk Frame

The claim ledger maps Launchpad residual risk to OWASP LLM06 Excessive Agency
and OWASP LLM03 Supply Chain:

- Excessive agency: container launch, MCP execution, filesystem writes, egress,
  and teardown must be permissioned, receipt-backed, and fail-closed.
- Supply chain: app artifacts, MCP manifests, policies, SBOMs, vulnerability
  scans, and promotion refs must be pinned and verified before support claims.

References:

- https://genai.owasp.org/llmrisk/llm062025-excessive-agency/
- https://genai.owasp.org/llmrisk/llm032025-supply-chain/
