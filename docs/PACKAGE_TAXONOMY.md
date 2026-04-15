---
title: PACKAGE_TAXONOMY
---

# HELM Package Taxonomy

Classification of all 84 directories in `core/pkg/`.

## Legend

| Category | Count | Description |
|----------|-------|-------------|
| **TCB** | 8 | Trusted Computing Base — the irreducible security boundary |
| **Supporting** | 32 | Infrastructure required by the TCB or CLI commands |
| **Extension** | 25 | Protocol extensions, adapters, and integrations |
| **Enterprise-origin** | 12 | Features that originated in commercial development |
| **Internal** | 7 | Utilities and internal abstractions |

---

## TCB — Trusted Computing Base (8)

These packages form the fail-closed execution boundary. Nothing else is required for HELM's core security guarantee.

| Package | Purpose |
|---------|---------|
| `guardian/` | Policy Enforcement Point — PRG evaluation, decision signing, fail-closed deny |
| `crypto/` | Ed25519 signing, verification, key management, canonicalization; `hybrid_signer.go` (Ed25519 + ML-DSA-65 dual signatures), `zkp/` (ZK compliance proof interfaces) |
| `contracts/` | Canonical types: Receipt, DecisionRecord, Effect, Intent, Verdict |
| `prg/` | Proof Requirement Graph — rule evaluation, policy engine |
| `executor/` | SafeExecutor — governed tool execution with receipt emission |
| `conform/` | Conformance engine — gate evaluation, profile matching |
| `canonicalize/` | JCS canonicalization, deterministic hashing |
| `store/` | Receipt persistence (SQLite + Postgres) |

---

## Supporting Infrastructure (32)

Required by the TCB or CLI commands. Not security-critical but operationally necessary.

| Package | Purpose |
|---------|---------|
| `artifacts/` | Artifact registry, envelope management, CAS storage |
| `audit/` | Audit log implementation, append-only event recording |
| `auth/` | Authentication middleware, token validation |
| `authority/` | Authority clock, trust root management |
| `authz/` | Authorization policies, RBAC primitives |
| `boundary/` | Boundary check helpers, scope validation |
| `budget/` | Budget tracking, cost accounting, ceiling enforcement; `estimate.go` adds pre-execution cost prediction |
| `buildguard/` | Build-time guard constraints |
| `bundles/` | Bundle management, artifact packaging |
| `capabilities/` | Capability registry, tool declaration |
| `certification/` | Conformance certification artifacts |
| `config/` | Configuration loading, `helm.yaml` parsing |
| `context/` | Execution context, environment snapshot |
| `credentials/` | Credential management, key storage |
| `database/` | Database helpers, migration runner |
| `effects/` | Effect type registry, dispatch; `circuitbreaker.go` (per-connector circuit breakers), `reversibility.go` (effect reversibility classification), `otel.go` (OpenTelemetry spans), `types.go` (CostBreakdown attribution) |
| `envelope/` | Effect envelope validation |
| `evidence/` | Evidence collection, chain building |
| `evidencepack/` | EvidencePack archive creation and extraction; `summary.go` provides constant-size O(1) completeness proofs |
| `firewall/` | Egress control, network policy enforcement |
| `identity/` | Principal identity, delegation sessions, isolation; `did/` (W3C DID identifiers), `continuous_delegation.go` (AITH time-bound revocable delegation) |
| `intent/` | Execution intent management |
| `kernel/` | Kernel primitives: CSNF, CEL-DP, Merkle, FreezeController; `memory_integrity.go` (SHA-256 hash-protected memory), `memory_trust.go` (temporal decay trust scoring) |
| `kernelruntime/` | Runtime lifecycle, intent submission |
| `manifest/` | Schema manifest loading and validation |
| `merkle/` | Merkle tree utilities (separate from kernel) |
| `pdp/` | Policy Decision Point interface for external policy backends |
| `proofgraph/` | ProofGraph DAG construction and traversal; `cloudevents/` (SIEM export via CloudEvents), `attribution/` (per-agent cost attribution) |
| `receipts/` | Receipt helpers, chain validation |
| `sandbox/` | Sandbox execution, isolation primitives |
| `trust/` | Trust root management, key ceremony |
| `verifier/` | EvidencePack verification, signature checking |

---

## Protocol Extensions (24)

Adapters, integrations, and protocol implementations. These extend HELM but are not required for core governance.

| Package | Purpose |
|---------|---------|
| `a2a/` | Agent-to-Agent protocol adapter |
| `api/` | REST API types and handlers |
| `bridge/` | Bridge adapter for external policy backends |
| `conformance/` | Extended conformance testing framework |
| `connector/` | Generic connector interface |
| `connectors/` | Concrete connector implementations |
| `escalation/` | Escalation workflow management |
| `evaluation/` | Policy evaluation utilities |
| `forensics/` | Forensic analysis tools |
| `gateway/` | API gateway middleware |
| `governance/` | High-level governance orchestration |
| `integrations/` | Third-party integration adapters |
| `intervention/` | Temporal intervention, throttle, quarantine |
| `kms/` | Key Management Service abstraction |
| `ledger/` | Event ledger, append-only log |
| `mcp/` | MCP (Model Context Protocol) server/client; `aip.go` (Agent Identity Protocol delegation), `docscan.go` (DDIPE documentation scanning), `rugpull.go` (rug-pull detection), `trust.go` (federated trust scoring), `typosquat.go` (typosquatting detection), `mcptox_test.go` (MCPTox adversarial benchmark) |
| `observability/` | Metrics, health checks |
| `otel/` | OpenTelemetry integration |
| `pack/` | Skill pack management; `verify_capabilities.go` (SkillFortify static capability verification), `provenance.go` (cryptographic publisher provenance) |
| `policy/` | Policy loading and compilation; `suggest/` (auto-generate rules from execution history), `verify/` (static analysis: circular deps, shadowed rules), `lint/` (policy linting) |
| `policyloader/` | External policy source loading |
| `provenance/` | Provenance tracking, chain of custody |
| `runtime/` | Runtime lifecycle management |
| `slo/` | SLO engine: latency/error-rate objectives with error budgets (`engine.go`) |
| `threatscan/` | Threat signal detection (prompt injection, unicode, credential); `ensemble.go` (multi-scanner voting with ANY/MAJORITY/UNANIMOUS strategies) |

---

## Enterprise-Origin (12)

Features that originated during commercial development. Present in the OSS repo for code completeness. Not part of the canonical TCB.

| Package | Purpose | Notes |
|---------|---------|-------|
| `compliance/` | Compliance export, regulatory reporting | Enterprise workflow |
| `disclosure/` | Disclosure controls, selective evidence release | Enterprise governance |
| `edgegovernance/` | Edge deployment governance patterns | Enterprise topology |
| `memory/` | Governed memory (LKS/CKS), promotion lifecycle | Commercial subsystem |
| `orgdna/` | Organization genome, research/org-structure modeling | Not OSS wedge scope |
| `privacy/` | Privacy controls, data classification | Enterprise compliance |
| `registry/` | Extended registry patterns | Commercial extension |
| `releasegovernance/` | Release governance, staged rollout | Enterprise ops |
| `rir/` | Registry information records | Enterprise metadata |
| `security/` | Extended security controls | Enterprise hardening |
| `simulation/` | Policy simulation runner | Enterprise testing |
| `tape/` | Execution tape recording, replay storage | Commercial feature |

---

## Internal Utilities (7)

Shared utilities and internal abstractions.

| Package | Purpose |
|---------|---------|
| `interfaces/` | Shared Go interfaces |
| `surface/` | Surface area helpers |
| `tooling/` | Internal dev tooling |
| `truth/` | Truth verification utilities |
| `util/` | General utilities |
| `versioning/` | Version comparison, compatibility checking |
| `replay/` | Execution tape replay verification; `compare.go` (trace diff across governance sessions) |
