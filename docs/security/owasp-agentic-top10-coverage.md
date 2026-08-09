---
title: OWASP Agentic Top 10 Mapping
last_reviewed: 2026-08-09
---

# OWASP Agentic Top 10 Mapping

## Audience

Security reviewers checking which OWASP Agentic AI Top 10 risks are covered by current HELM AI Kernel evidence.

## Outcome

After this page you should know which ASI category maps to which kernel control, which package test and conformance scenario exercise it, what residual risk each category leaves outside the OSS boundary, and which command re-checks the mapping.

## Source Truth

- Machine-readable mapping: `core/pkg/conformance/agentsafety/registry.go` — 60 case entries, each naming a baseline policy rule, config guard, package test, conformance scenario, residual risk, and expected policy action.
- Case matrix: `docs/security/agent-safety-conformance-cases.md` — the per-case narrative. `core/pkg/conformance/agentsafety/registry_test.go` parses its case IDs and fails if the registry and the matrix disagree, or if the count is not 60.
- Baseline policy rules: `core/pkg/policybundles` — `TestRegistryRulesExistInBaselineBundle` fails if a registry entry names a rule that is not in `AgentSafetyBaselineBundle()`, or if the rule's action or canonical reason code differs from the entry's.
- Shared conformance scenario: `core/pkg/conformance/scenarios/agent_safety_baseline_test.go` (`TestAgentSafetyBaselineRegistryScenarios`).
- Validation: `cd core && go test ./pkg/conformance/agentsafety/... ./pkg/conformance/scenarios/... ./pkg/policybundles/...`, then `make docs-coverage` and `make docs-truth`.

This page is not published. It is absent from `docs/public-docs.manifest.json`, which lists 30 documents and carries only `docs/security/quantum-posture.md` under `docs/security/`. There is no `security/owasp-agentic-top10-mapping` public route; do not cite one. The adjacent MCP-specific mapping is `docs/OWASP_MCP_THREAT_MAPPING.md`.

Do not expand this page with unsupported product, SDK, deployment, compliance, or integration claims unless the registry points to code, schemas, tests, examples, or an owner doc that proves the claim.

## Category Map

Category labels below are the ones the code enforces — the `Group` strings in `core/pkg/conformance/agentsafety/registry.go`. They are the OWASP Top 10 for Agentic Applications (December 2025) categories, not the LLM Top 10, and not the older "prompt injection / tool poisoning / excessive permission…" list this page used to carry.

| Category | Cases | Baseline rules | Control packages | Verdicts | Residual risk |
| --- | --- | --- | --- | --- | --- |
| ASI01 Agent Goal Hijack | `AGH-01`–`AGH-05` | `TaintedHighRisk`, `MemoryInfluenceOnly`, `EgressBoundary`, `ProtectedConfig` | `pkg/policybundles`, `pkg/memory`, `pkg/firewall`, `pkg/manifest` | `deny` | Source tainting adapters are deployment-specific; longitudinal drift detection depends on runtime observation windows. |
| ASI02 Tool Misuse and Exploitation | `TME-01`–`TME-06` | `TaintedHighRisk`, `EgressBoundary`, `HighImpactApproval`, `ToolContract`, `ApprovedArgs` | `pkg/policycel`, `pkg/firewall`, `pkg/contracts`, `pkg/manifest` | `deny`, `require_approval` | Tool adapters must preserve output taint and supply approved-argument hash bindings; covert-channel and DNS-signature detection is out of OSS scope. |
| ASI03 Identity and Privilege Abuse | `IPA-01`–`IPA-06` | `DelegationIdentity`, `A2AVerification`, `ToolContract` | `pkg/a2a`, `pkg/identity`, `pkg/contracts` | `deny` | Privilege attenuation depends on tenant RBAC data; registry authenticity depends on configured trust roots; clock trust is inherited from runtime attestation. |
| ASI04 Agentic Supply Chain Vulnerabilities | `ASC-01`–`ASC-06` | `SupplyChain`, `SafeDepOverride`, `ToolContract`, `TaintedHighRisk`, `EgressBoundary` | `pkg/safedep`, `pkg/manifest`, `pkg/evidencepack`, `pkg/policycel`, `pkg/conformance/sandbox` | `deny` | External transparency logs are optional deployment hardening. |
| ASI05 Unexpected Code Execution | `RCE-01`–`RCE-06` | `TaintedHighRisk`, `ApprovedArgs`, `ProtectedConfig`, `SafeDepOverride`, `EgressBoundary` | `pkg/conformance/sandbox`, `pkg/conformance/scenarios`, `pkg/manifest`, `pkg/memory` | `deny` | Shell-free executors stay responsible for avoiding string expansion. |
| ASI06 Memory and Context Poisoning | `MEM-01`–`MEM-06` | `MemoryInfluenceOnly` | `pkg/memory`, `pkg/a2a` | `deny` | Memory scoring quality depends on upstream provenance capture. |
| ASI07 Insecure Inter-Agent Communication | `A2A-01`–`A2A-05` | `A2AVerification`, `ToolContract` | `pkg/a2a`, `pkg/manifest` | `deny` | Nonce persistence depends on a transport-specific replay cache. |
| ASI08 Cascading Failures | `CAS-01`–`CAS-06` | `BudgetCircuitBreaker`, `HighImpactApproval`, `SupplyChain`, `SafeDepOverride` | `pkg/effectgraph`, `pkg/contracts`, `pkg/conformance`, `pkg/conformance/scenarios`, `pkg/safedep` | `deny`, `require_approval` | Planner quality is advisory until effect policies approve. |
| ASI09 Human-Agent Trust Exploitation | `HITL-01`–`HITL-04` | `HighImpactApproval`, `PreviewSideEffect`, `SafeDepOverride` | `pkg/contracts`, `pkg/manifest`, `pkg/safedep` | `deny`, `require_approval` | UI presentation requirements live outside core package tests. |
| ASI10 Rogue Agents | `ROG-01`–`ROG-06` | `A2AVerification`, `EgressBoundary`, `HighImpactApproval`, `ProtectedConfig`, `SafeDepOverride` | `pkg/a2a`, `pkg/firewall`, `pkg/effectgraph`, `pkg/contracts`, `pkg/safedep` | `deny`, `require_approval` | Observer store hardening depends on the production evidence backend. |

An eleventh group, `Benchmark Imports` (`BENCH-01`–`BENCH-04`), is registered alongside the ten categories. Its expected action is `log`, not `deny` — it records imported benchmark evidence and blocks nothing. Do not count it as coverage.

`registry.go` is the authority for the per-case detail this table summarises: each entry also carries the specific `ConfigGuard`, `PackageTest`, `ExpectedReasonCode`, and whether a receipt is required. Read the entry, not this table, before making a claim about one case.

## Coverage Discipline

OWASP Agentic Top 10 coverage must stay evidence-backed. The registry is the enforcement point for that discipline: `registry_test.go` rejects any entry missing a case ID, group, policy rule, config guard, package test, conformance scenario, residual risk, or expected action, so a category cannot be claimed without all seven.

Two boundaries this mapping does not cross:

- Policy evaluation does not replace app authorization, secrets management, sandboxing, or network egress controls. The residual-risk column names what each category still leaves to the deployment.
- A `deny` in the table is a policy verdict, not proof that a given deployment's adapters feed the kernel the facts the rule needs. Several residual risks say exactly that — tainting, provenance, and approved-argument bindings come from adapters.

When changing a claim here, change the registry entry and the case matrix in the same commit; the tests fail otherwise.
