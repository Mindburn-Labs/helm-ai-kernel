---
title: OSS_SCOPE
---

# HELM OSS Scope

> **Canonical architecture**: see [ARCHITECTURE.md](ARCHITECTURE.md) for the
> normative trust boundary model and TCB definition. For the canonical
> 8-package TCB inventory, see [TCB_POLICY.md](TCB_POLICY.md).

HELM OSS is the **open execution kernel** of the HELM stack.

It exists to keep the deterministic boundary small, portable, and independently trustworthy. The commercial HELM layers must extend this kernel, not replace it.

## Kernel TCB (Trusted Computing Base)

The canonical TCB is bounded to **8 packages** — the minimal trusted core.
See [TCB_POLICY.md](TCB_POLICY.md) for the authoritative package list,
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

### Product Surfaces (local-first — boundary re-split in progress)

The OSS boundary is expanding beyond the execution kernel to include the full
local-first product surface: Studio shell, design tokens, Genesis Local
ceremony engine, community pack install, and the evidence/dispute viewers.
Migration is tracked by `/.claude/plans/dynamic-orbiting-crayon.md`; see
`apps/helm-studio/MIGRATION_STATUS.md` for the concrete adaptations that
divide the OSS and commercial Studio builds (main.tsx + vite.config.ts).

| Surface                      | Purpose                                               | Status                 |
| ---------------------------- | ----------------------------------------------------- | ---------------------- |
| `apps/helm-studio/`          | Generic Studio shell + extension-contract foundation  | 🛠 Staged Phase 2a    |
| `packages/design-tokens/`    | Mindburn DS v1.0 palette mirrored from `mindburn/`    | ✅ Active Phase 2b    |
| `tools/dispute-viewer/`      | Offline HTML viewer for verify/conform reports        | ✅ Active Phase 3c    |
| `core/pkg/genesis/ceremony/` | VGL state machine + in-memory store                   | ✅ Active Phase 3a    |
| `core/pkg/packs/install/`    | Core + community pack Runner (Plan/Install/Rollback)  | ✅ Active Phase 4a    |

## Removed from TCB (Enterprise)

The following packages were removed to minimize the attack surface:

| Package                    | Reason                        |
| -------------------------- | ----------------------------- |
| `access/`                  | Enterprise access control     |
| `ingestion/`               | Brain subsystem data pipeline |
| `verification/refinement/` | Enterprise verification       |
| `cockpit/`                 | UI dashboard                  |
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
(see [CAPABILITY_MANIFESTS.md](CAPABILITY_MANIFESTS.md)):

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
- Adapters and integration surfaces

OSS does not include:

- Hosted multi-tenant control plane (shared Genesis sessions, team workspaces)
- Enterprise identity (SSO, SCIM, SAML, directory federation)
- Legal hold, long-horizon retention, regulator-facing audit views
- Org-scale rollout, staged/shadow policy deployment across fleets
- Managed federation and vendor-mesh across organizations
- Premium / certified pack ecosystem channels (teams, enterprise)
- Billing, seat management, usage-based metering

The invariant is simple: OSS ships a beautiful local-first product — kernel
plus Studio shell plus Genesis Local plus community packs plus evidence /
replay / dispute viewers. The commercial layer monetizes shared
organizational control around that product, not artificial runtime crippleware.
