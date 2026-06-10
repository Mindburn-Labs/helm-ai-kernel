---
title: PCAS Authorization Propagation Gap Analysis
last_reviewed: 2026-06-10
---

# PCAS Authorization Propagation Gap Analysis

## Audience

Security reviewers and kernel maintainers assessing HELM against PCAS
(arXiv 2605.05440, Tallam, Kamiwaza AI, 2026-05-06), which formalizes
authorization propagation across multi-agent workflows with Datalog
policies enforced by a reference monitor over a dependency graph of tool
calls, results, and messages.

## Source Truth

- Paper: <https://arxiv.org/abs/2605.05440>
- Proof tests: `core/pkg/mcp/pcas_propagation_proof_test.go`
  (`cd core && go test ./pkg/mcp/ -run TestPCAS`)
- Enforcement points: `core/pkg/mcp/aip.go` (delegation chains),
  `core/pkg/mcp/firewall.go` (dispatch reference monitor),
  `core/pkg/guardian` (Gate 5 delegation), `core/pkg/proofgraph`
  (causal dependency DAG), `core/pkg/policy/wasm` + CEL (policy runtime)

## Why PCAS matters to HELM

PCAS reports that a deterministic reference monitor lifts agent policy
compliance from 48% to 93% with zero policy violations, independent of
model reasoning. That is a quantitative external validation of HELM's
core thesis: policy enforcement must live in a fail-closed kernel beneath
the agent, not in model reasoning. This analysis maps PCAS's formal
properties to existing HELM surfaces — per MIN-494 scope, no new engine
is introduced.

## Property mapping

| PCAS property | PCAS mechanism | HELM surface | Status |
| --- | --- | --- | --- |
| Transitive delegation | Datalog rules over delegation edges | `AIPVerifier` delegation chains: authority flows only via explicit claims; every hop bounded by the delegator's effective scope; widening rejected at registration. Guardian Gate 5 links delegation sessions into decisions. | **Covered** — proof `TestPCASTransitiveDelegationBoundedPropagation` |
| Temporal validity | Validity intervals on authorization facts | `DelegationClaim.ExpiresAt` checked at every verification with fail-closed expiry; effect permits and quarantine approvals are similarly time-bound. | **Covered** — proof `TestPCASTemporalValidityExpiryRevokesAuthority` |
| Reference monitor at dispatch | Datalog monitor intercepts every tool call | `ExecutionFirewall.AuthorizeToolCall` intercepts every call (quarantine → catalog → scope → schema pin), emits a sealed `ExecutionBoundaryRecord` for allow *and* deny. Policy languages are CEL + WASM bytecode (deterministic, sandboxed) rather than Datalog — equivalent monitor, different policy calculus. | **Covered (different calculus)** — proof `TestPCASPropagatedScopeEnforcedAtDispatchWithEvidence` |
| Dependency-graph state model | Agent state as DAG of calls/results/messages | `proofgraph` records the causal DAG (INTENT, ATTESTATION, EFFECT nodes, Lamport ordering) — but as *evidence*, not as a *policy input*. Policies today evaluate per-call context, not graph queries. | **Partial gap** — causality is recorded, not policy-queryable |
| Aggregation inference | Deny when combined results cross a boundary | Not enforced. Each tool call is authorized independently; two individually-permitted reads are never re-evaluated as an aggregate. | **Gap** — pinned by `TestPCASAggregationInferenceGapIsDocumentedBehavior` |
| Compliance benchmark (48%→93%) | Frontier-model agent benchmark | Not reproduced in-repo. HELM governed calls are 100% policy-conformant by construction (fail-closed interception); an apples-to-apples benchmark run is marketing/diligence work, not kernel work. | **Out of scope here** — candidate follow-up |

## Gap detail and direction

1. **Aggregation inference (real gap).** PCAS can express "agent may read
   any single record but not enumerate the directory". HELM's per-call
   scope checks cannot. The natural fit — when prioritized — is a P2
   overlay that evaluates CEL over a session-scoped call-history window
   (counts, distinct-argument cardinality) fed from the audit store, or a
   WASM policy with access to proofgraph queries. No new engine is
   required: both policy runtimes already exist; the missing piece is
   exposing dependency-graph context as policy input.
2. **Dependency-graph as policy input (partial gap).** `proofgraph`
   already captures exactly the DAG PCAS reasons over. Bridging it into
   guardian evaluation context would close most of the distance to PCAS
   expressiveness without adopting Datalog.
3. **No action needed** on transitive delegation, temporal validity, or
   the reference-monitor architecture itself — the proof tests bind these
   claims to code.

## Positioning note

PCAS validates the deterministic-enforcement thesis but is a research
prototype scoped to policy evaluation; HELM additionally signs and
hash-chains every decision (EvidencePack, AAT export) and fails closed on
unknown servers/tools. When citing PCAS numbers in public material, use
the claims registry flow — do not quote the 48%→93% delta as a HELM
measurement.
