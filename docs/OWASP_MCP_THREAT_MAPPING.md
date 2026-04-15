---
title: OWASP_MCP_THREAT_MAPPING
---

# OWASP MCP Threat Mapping

> **Canonical** · v1.0 · Normative Appendix
>
> This appendix maps recognized agentic AI threat categories
> to HELM's three-layer execution security model. It provides
> enterprise teams with an architectural checklist, not a slogan.
>
> **Reference**: [EXECUTION_SECURITY_MODEL.md](EXECUTION_SECURITY_MODEL.md)
> for the layer definitions.

---

## Threat-to-Defense Matrix

Each threat is mapped to one or more HELM layers and the specific
defense mechanisms that mitigate it.

| # | Threat | Layer(s) | HELM Defense | Reason Code |
| :- | :----- | :------- | :----------- | :---------- |
| 1 | **Tool Poisoning** — malicious tool descriptions that trick the agent into calling dangerous tools | A + B | Bounded surface (capability manifest allowlist) prevents undeclared tools from being reachable. Schema PEP validates tool args against pinned schemas, blocking injected payloads. | `DENY_TOOL_NOT_FOUND` |
| 2 | **Excessive Permission Scope** — agent has access to more tools/capabilities than needed | A | Capability manifests constrain the bounded surface per agent/profile. P0 ceilings enforce hard limits. Side-effect class profiles (read-only, write-limited) restrict capability classes. | N/A (design-time) |
| 3 | **Resource Overborrowing** — agent consumes excessive compute, API calls, or budget | B | ACID-locked budget gates with fail-closed enforcement. P0 ceilings are non-overridable. Per-call gas metering in WASI sandbox. | `BUDGET_EXCEEDED` |
| 4 | **Schema Drift** — tool argument/response schemas change without governance, causing silent corruption | B | Contract pinning: connector response schemas are pinned at deployment. Any drift produces a hard error. JCS canonicalization eliminates encoding ambiguity. | `ERR_CONNECTOR_CONTRACT_DRIFT` |
| 5 | **Tool Misuse** — agent calls a legitimate tool with malicious or out-of-context arguments | B | PEP verdict evaluates execution admissibility per-call. Sandbox preconditions enforce environmental requirements. PRG checks cryptographic prerequisites. | `DENY` + specific reason |
| 6 | **Untrusted Connector Drift** — third-party connector behavior changes without notice | A + B | Shape checks on connector output against pinned schemas. Deny/defer on unrecognized response shapes. Connector allowlists restrict which connectors are reachable. | `ERR_CONNECTOR_CONTRACT_DRIFT` |
| 7 | **Parameter Injection** — crafted tool arguments that embed hidden commands or exploit downstream parsers | B | JCS canonicalization (RFC 8785) normalizes all arguments before evaluation. SHA-256 hash of canonical args bound into signed receipt. Schema validation rejects extra/unknown fields. | `DENY` |
| 8 | **Capability Escalation** — agent attempts to gain higher privileges than granted | A + B | Delegation sessions enforce subset-of-delegator invariant. Profile enforcement prevents write actions through read-only profiles. P0 ceilings cannot be overridden by policy. | `DELEGATION_SCOPE_VIOLATION`, `IDENTITY_ISOLATION_VIOLATION` |
| 9 | **Unverifiable Actions** — agent takes actions with no audit trail or proof of authorization | C | Every call (ALLOW and DENY) produces an Ed25519-signed receipt. ProofGraph DAG provides causal ordering. EvidencePack enables offline verification. | N/A (always produced) |
| 10 | **Audit Gap** — compliance or legal teams cannot reconstruct what happened | C | ProofGraph + EvidencePack provide complete, deterministic, offline-verifiable execution history. Deny receipts include reason codes. Replay engine reconstructs full session from genesis. | N/A (always available) |
| 11 | **Session Replay** — attacker replays a valid execution to re-trigger effects | B + C | Lamport clock monotonicity per session. Causal PrevHash chain (each receipt signs over previous). Idempotency cache in executor rejects duplicates. Delegation session nonces prevent session replay. | `DENY` (replay detected) |
| 12 | **Trust Key Compromise** — attacker gains control of a signing key | C | Event-sourced Trust Registry with immutable key lifecycle events. Ceremony-based key rotation. Every key event is signed and Lamport-ordered. Unknown keys produce hard denial. | `TRUST_KEY_UNKNOWN` |

---

## Coverage Analysis

### Layer A — Surface Containment

Mitigates threats that exploit **too-large attack surfaces**:
- Tool Poisoning (#1) — undeclared tools never reach the executor
- Excessive Permission Scope (#2) — bounded surface minimizes reachable capabilities
- Untrusted Connector Drift (#6) — connector allowlists limit exposure

**Design-time property**: these protections are configured before execution,
not computed per-call.

### Layer B — Dispatch Enforcement

Mitigates threats that exploit **individual tool calls**:
- Resource Overborrowing (#3) — per-call budget enforcement
- Schema Drift (#4) — per-call contract validation
- Tool Misuse (#5) — per-call admissibility check
- Parameter Injection (#7) — per-call canonicalization and validation
- Capability Escalation (#8) — per-call delegation scope enforcement
- Session Replay (#11) — per-call idempotency and ordering

**Dispatch-time property**: these protections execute for every individual call.

### Layer C — Verifiable Receipts

Mitigates threats that exploit **lack of evidence**:
- Unverifiable Actions (#9) — all calls produce signed receipts
- Audit Gap (#10) — complete ProofGraph + EvidencePack
- Session Replay (#11) — causal hash chain detects manipulation
- Trust Key Compromise (#12) — event-sourced key registry

**Post-execution property**: these protections provide independent proof.

---

## Conformance Test Coverage

Each threat has a corresponding conformance use case or gate test:

| Threat | Use Case / Gate |
| :----- | :-------------- |
| Tool Poisoning | UC-013 |
| Excessive Permission Scope | UC-019, UC-020 |
| Resource Overborrowing | UC-017 |
| Schema Drift | UC-015 |
| Tool Misuse | UC-001, UC-002 |
| Untrusted Connector Drift | UC-009 |
| Parameter Injection | UC-014 |
| Capability Escalation | UC-018 |
| Unverifiable Actions | UC-022 |
| Audit Gap | UC-007, UC-008 |
| Session Replay | UC-021, UC-006 |
| Trust Key Compromise | UC-010 |

→ See [use-cases/](use-cases/) for the full test suite.

---

## MCP Supply Chain Defenses (April 2026)

The following defenses extend HELM's Layer A (Surface Containment) with active MCP supply chain protection, based on research from arXiv 2603.00195, 2604.03081, 2604.08407, and 2508.14925.

| # | Threat | Defense | Package |
| :- | :----- | :------ | :------ |
| 13 | **DDIPE Documentation Poisoning** — MCP tool descriptions contain hidden instructions that manipulate agent behavior | DDIPE scanner analyzes all tool documentation before agent exposure. Detects embedded instructions, prompt injection patterns, and social engineering. | `mcp/docscan.go` |
| 14 | **Rug-Pull (Behavioral Drift)** — MCP tool changes behavior after initial installation/approval | Tool fingerprinting captures schema + behavior snapshot at install time. Runtime checks detect drift and trigger re-verification or blocking. | `mcp/rugpull.go` |
| 15 | **Typosquatting** — Malicious MCP tools use names similar to legitimate ones | Levenshtein distance comparison against known-good tool registries. Near-match tool names produce warnings. Blocks tools within edit distance threshold of popular packages. | `mcp/typosquat.go` |
| 16 | **Capability Overclaim** — Skill packs declare minimal capabilities but invoke privileged tools at runtime | SkillFortify performs static capability verification. Declared capabilities are checked against actual tool invocations. Mismatches produce `CAPABILITY_MISMATCH_VIOLATION`. | `pack/verify_capabilities.go` |
| 17 | **Unsigned Dependencies** — Skill packs from unverified publishers | Publisher signature chain verification back to trusted root. Unsigned packs are blocked. Signature must cover content hash (not just metadata). | `pack/provenance.go` |
| 18 | **MCP Server Reputation** — Unknown MCP servers with no trust history | Federated trust scoring aggregates cross-organization reputation. Low-trust servers have tools flagged for manual review. Trust scores decay without positive signals. | `mcp/trust.go` |

### MCPTox Benchmark

The MCPTox adversarial harness (`mcp/mcptox_test.go`) continuously validates 0% attack success rate (ASR) against known tool poisoning payloads. This runs as part of `make crucible-full` and produces a machine-readable report.

---

## OWASP References

This mapping aligns with the following OWASP resources:

- [OWASP Top 10 for LLM Applications](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- OWASP MCP Security Guidelines (emerging)
- [OWASP API Security Top 10](https://owasp.org/API-Security/)

HELM's three-layer model maps to OWASP categories but provides
stronger guarantees through cryptographic enforcement and deterministic
verification, rather than advisory guardrails.

---

_Canonical revision: 2026-03-21 · HELM UCS v1.2_
