---
title: OSS_SCOPE
---

# HELM OSS Scope

> **Canonical architecture**: see [ARCHITECTURE.md](ARCHITECTURE.md) for the
> normative trust boundary model and TCB definition. For the canonical
> 8-package TCB inventory, see [ARCHITECTURE.md](ARCHITECTURE.md).

HELM OSS is the **open execution kernel and self-hostable Console** of the HELM stack.

It exists to keep the deterministic boundary small, portable, and independently trustworthy. The commercial HELM layers must extend this kernel, not replace it.

## Kernel TCB (Trusted Computing Base)

The canonical TCB is bounded to **8 packages** — the minimal trusted core.
See [ARCHITECTURE.md](ARCHITECTURE.md) for the authoritative package list,
expansion criteria, and CI enforcement details.

## Active OSS Packages

The following packages are part of the OSS kernel, including both TCB and
non-TCB supporting infrastructure:

### TCB Packages

| Package            | Purpose                                                       | Status    |
| ------------------ | ------------------------------------------------------------- | --------- |
| `contracts/`       | Canonical data structures (Decision, Effect, Receipt, Intent) | ✅ Active |
| `crypto/`          | Ed25519 signing, JCS canonicalization                         | ✅ Active |
| `guardian/`        | Policy Enforcement Point (PEP), PRG enforcement               | ✅ Active |
| `executor/`        | SafeExecutor with receipt generation                          | ✅ Active |
| `proofgraph/`      | Cryptographic ProofGraph DAG                                  | ✅ Active |
| `trust/registry/`  | Event-sourced trust registry                                  | ✅ Active |
| `runtime/sandbox/` | WASI sandbox (wazero, deny-by-default)                        | ✅ Active |
| `receipts/`        | Receipt policy enforcement (fail-closed)                      | ✅ Active |

### Supporting Infrastructure (Non-TCB)

| Package                | Purpose                                    | Status    |
| ---------------------- | ------------------------------------------ | --------- |
| `canonicalize/`        | RFC 8785 JCS implementation                | ✅ Active |
| `manifest/`            | Tool args/output validation (PEP boundary) | ✅ Active |
| `agent/adapter.go`     | KernelBridge choke point                   | ✅ Active |
| `runtime/budget/`      | Compute budget enforcement                 | ✅ Active |
| `escalation/ceremony/` | RFC-005 Approval Ceremony                  | ✅ Active |
| `genesis/ceremony/`    | VGL six-phase Genesis ceremony state machine | ✅ Active |
| `evidence/`            | Evidence pack export/verify                | ✅ Active |
| `replay/`              | Replay engine for verification             | ✅ Active |
| `mcp/`                 | Tool catalog + MCP gateway                 | ✅ Active |
| `kernel/`              | Rate limiting, backpressure                | ✅ Active |
| `a2a/`                 | Agent-to-Agent trust protocol              | ✅ Active |
| `otel/`                | OpenTelemetry governance telemetry         | ✅ Active |
| `identity/did/`        | W3C DID-based agent identity               | ✅ Active |
| `crypto/hybrid/`       | Hybrid Ed25519 + ML-DSA-65 dual signing    | ✅ Active |
| `crypto/zkproof/`      | Zero-knowledge compliance proofs           | ✅ Active |
| `memory/`              | Memory integrity, trust, poisoning defense | ✅ Active |
| `threatscan/ensemble/` | Quorum-based multi-engine threat scanning  | ✅ Active |
| `evidencepack/summary/`| Constant-size cryptographic evidence summaries | ✅ Active |
| `skillfortify/`        | Runtime tool/skill integrity verification  | ✅ Active |
| `provenance/`          | Supply chain provenance with signed attestations | ✅ Active |
| `budget/cost/`         | Cost attribution and pre-execution estimation | ✅ Active |
| `delegation/aip/`      | Agent Interaction Protocol, continuous delegation | ✅ Active |
| `replay/comparison/`   | Side-by-side replay comparison for drift detection | ✅ Active |
| `a2a/federation/`      | Federated trust across organizations       | ✅ Active |
| `mcptox/`              | MCP tool toxicity scanner (rug-pull, typosquatting) | ✅ Active |
| `effects/reversibility/` | Reversibility engine for effect compensation | ✅ Active |
| `observability/slo_engine/` | SLO-driven governance actions          | ✅ Active |
| `otel/cloudevents/`    | CloudEvents SIEM export                    | ✅ Active |
| `connectors/ddipe/`    | DDIPE document scanning for governance extraction | ✅ Active |

### Deployment Infrastructure

| Package                         | Purpose                                  | Status    |
| ------------------------------- | ---------------------------------------- | --------- |
| `deploy/helm-operator/`         | K8s CRDs (PolicyBundle, GuardianSidecar) | ✅ Active |
| `protocols/spec/`               | RFC-style protocol specification         | ✅ Active |
| `protocols/conformance/v1/owasp/` | Machine-readable OWASP threat vectors  | ✅ Active |

### Product Surfaces

The OSS boundary ships exactly one browser UI: `apps/console`, the HELM OSS Console. It is a self-hostable operator surface over the local kernel and uses `@helm/design-system-core` for all product UI primitives and styling. The repository does not ship a second browser UI, a static report viewer, a Node CLI wrapper, a Next starter, or generated HTML report surface.

`@helm/design-system-core` remains a reusable React/token package. The Console consumes it through public package entrypoints so package integrity, app fidelity, and OSS boundary truth are tested together.

## Removed from TCB (Enterprise)

The following packages were removed to minimize the attack surface:

| Package                    | Reason                        |
| -------------------------- | ----------------------------- |
| `access/`                  | Enterprise access control     |
| `ingestion/`               | Brain subsystem data pipeline |
| `verification/refinement/` | Enterprise verification       |
| `cockpit/`                 | Product console               |
| `ops/`                     | Operations tooling            |
| `multiregion/`             | Multi-region orchestration    |
| `hierarchy/`               | Enterprise hierarchy          |
| `heuristic/`               | Heuristic analysis            |
| `perimeter/`               | Network perimeter             |

## First-Class Execution Surfaces

### MCP Interceptor

The MCP gateway (`core/pkg/mcp/`) is a **first-class governed surface**,
not an adapter. It provides:

- Tool discovery with governance metadata (`/mcp/v1/capabilities`)
- Governed tool execution with signed receipts (`/mcp/v1/execute`)
- Schema validation against pinned tool contracts
- Full ProofGraph integration — MCP calls produce the same receipt chain
  as OpenAI proxy calls

### OpenAI-Compatible Proxy

The governed proxy (`/v1/chat/completions`) intercepts OpenAI-compatible
tool calls and routes them through the PEP boundary.

### Bounded-Surface Primitives

The OSS kernel includes configurable surface containment primitives
(see [EXECUTION_SECURITY_MODEL.md](EXECUTION_SECURITY_MODEL.md)):

- Domain-scoped tool bundles
- Explicit capability manifests
- Read-only / write-limited / side-effect-class profiles
- Connector allowlists
- Destination scoping
- Filesystem/network deny-by-default (WASI)
- Sandbox profile requirement per tool class

## Boundary Truth

OSS includes:

- **Surface containment** — capability manifests, tool bundles, sandbox profiles
- **Dispatch enforcement** — fail-closed PEP, policy evaluation, budget gates
- **Verifiable receipts** — signed receipts, ProofGraph, replay
- **MCP interceptor** — first-class governed MCP surface
- **OpenAI proxy** — governed proxy for OpenAI-compatible SDKs
- **HELM OSS Console** — one self-hostable browser UI for command, receipts, policy, MCP, evidence, replay, ProofGraph, conformance, trust, incidents, audit, developer, and settings workflows
- Adapters and integration surfaces

OSS does not include (commercial overlays only):

- Managed hosted control plane operations
- Enterprise identity and admin (SCIM, SSO/SAML/OIDC, directory sync)
- Legal hold, long-term hosted retention, regulator-facing workflows
- Org-scale rollout / staging / shadow enforcement on live production traffic
- Managed federation and hosted trust registries
- Premium pack channels (teams, enterprise) and entitlement engine
- Certified connector program as a hosted service (OSS ships the connector SDK + community verification harness)
- Billing, seat management, usage metering

The invariant is simple: OSS must stay fully useful on its own as a developer-first execution kernel and self-hostable Console: Go CLI, HTTP/API contracts, SDKs, evidence export, offline verification, replay, conformance, Console assets, and release artifacts. Mindburn-specific managed-service operations live outside this repository and integrate through those public contracts.
