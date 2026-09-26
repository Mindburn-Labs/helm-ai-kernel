---
title: KERNEL_SCOPE
last_reviewed: 2026-05-12
---

<!-- quantum_posture: this page lists the classical Ed25519 signing in core/pkg/crypto and adds no post-quantum cryptographic control. -->

# HELM AI Kernel Scope

## Audience

Maintainers, adopters, and downstream packagers deciding what is in HELM AI Kernel and what is outside this repository.

## Outcome

After this page you should know what this surface is for, which source files own the behavior, which public route or adjacent page to use next, and which validation command to run before changing the claim.

## Source Truth

- Public route: `kernel-scope`
- Source document: `helm-ai-kernel/docs/KERNEL_SCOPE.md`
- Public manifest: `helm-ai-kernel/docs/public-docs.manifest.json`
- Source inventory: `helm-ai-kernel/docs/source-inventory.manifest.json`
- Validation: `make docs-coverage`, `make docs-truth`, and `npm run coverage:inventory` from `docs-platform`

Do not expand this page with unsupported product, SDK, deployment, compliance, or integration claims unless the inventory manifest points to code, schemas, tests, examples, or an owner doc that proves the claim.

## RLM Input Evidence Boundary

RLM outputs can help maintainers inspect large repos, logs, PDFs, receipts, and
EvidencePacks. They are input evidence only until represented through existing
Kernel contracts: verdicts, signed receipts, ProofGraph refs, EvidencePacks,
conformance fixtures, verifier code, or release evidence. Do not add a new RLM
proof universe or describe RLM output itself as Kernel verification.

> **Canonical architecture**: see [ARCHITECTURE.md](ARCHITECTURE.md) for the
> normative trust boundary model and TCB definition. For the canonical
> 8-package TCB inventory, see [ARCHITECTURE.md](ARCHITECTURE.md).

HELM AI Kernel is the **open, headless execution kernel and API contract** of the HELM stack.

It exists to keep the deterministic boundary small, portable, and independently trustworthy. Downstream HELM layers must extend this kernel through public contracts, not replace it.

### Organization lifecycle integrations

An organization runtime may use the same Kernel contracts while creating,
connecting, operating, or transforming an organization. The runtime owns
goals, obligations, planning, shared-resource allocation, outcome evaluation,
and organization version changes. Kernel owns the authority and evidence for
the effects that cross its boundary.

Reuse existing obligation, capability, effect, permit, receipt, ProofGraph,
and EvidencePack semantics. A newly generated adapter or tool remains a
candidate until qualified and admitted through the owning activation path;
generation cannot grant it authority. Resource references must resolve to
the enforcement required by the bound effect, rather than implying that a
reference alone reserves organization-wide capacity.

Downstream product acceptance must prove durable operation, recovery, and
verified outcomes separately. Neither a valid organization schema nor a
Kernel conformance fixture establishes general availability of that product.
Kernel remains reusable without a commercial runtime, a named organization,
or a particular model provider.

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
| `runtime/sandbox/` | WASI sandbox (wazero, deny-by-default); the shipped server runs no pack (CTL-044) | Library only |
| `receipts/`        | Receipt policy enforcement (fail-closed); not linked into `core/cmd/helm-ai-kernel` | Library only |

### Supporting Infrastructure (Non-TCB)

| Package                | Purpose                                    | Status    |
| ---------------------- | ------------------------------------------ | --------- |
| `canonicalize/`        | RFC 8785 JCS implementation                | ✅ Active |
| `manifest/`            | Tool args/output validation (PEP boundary) | ✅ Active |
| `bridge/`              | KernelBridge choke point                   | ✅ Active |
| `runtime/budget/`      | Compute budget enforcement; not linked into `core/cmd/helm-ai-kernel` | Library only |
| `escalation/ceremony/` | RFC-005 Approval Ceremony; not linked into `core/cmd/helm-ai-kernel` | Library only |
| `evidence/`            | Evidence pack export/verify                | ✅ Active |
| `replay/`              | Replay engine for verification; not linked into `core/cmd/helm-ai-kernel` | Library only |
| `mcp/`                 | Tool catalog + MCP gateway                 | ✅ Active |
| `kernel/`              | Freeze, scoped-stop fences, context guard; request rate limiting lives in `api/` (CTL-013) | ✅ Active |
| `a2a/`                 | Agent-to-Agent trust protocol              | ✅ Active |
| `otel/`                | OpenTelemetry governance telemetry         | ✅ Active |
| `identity/did/`        | W3C DID-based agent identity               | ✅ Active |
| `policy/reconcile/`    | Runtime policy source reconciliation and snapshot swap | ✅ Active |

### Frontier / Spec-Only Surfaces

The following names appear in strategy, standard, or roadmap material but are not active source paths in this OSS repository as of the v1.3 convergence pass. They MUST NOT be documented as shipped packages until source, tests, and conformance vectors exist under the matching path:

- `crypto/hybrid/`
- `crypto/zkproof/` (cryptographic proof attestation)
- `memory/`
- `threatscan/ensemble/`
- `evidencepack/summary/`
- `skillfortify/`
- `provenance/`
- `budget/cost/`
- `delegation/aip/`
- `replay/comparison/`
- `a2a/federation/`
- `mcptox/`
- `effects/reversibility/`
- `observability/slo_engine/`
- `otel/cloudevents/`
- `connectors/ddipe/`

### Deployment Infrastructure

| Package                         | Purpose                                  | Status    |
| ------------------------------- | ---------------------------------------- | --------- |
| `deploy/helm-chart/`            | Kubernetes Helm chart, optional HelmPolicyBundle CRD template | ✅ Active |
| `protocols/spec/`               | RFC-style protocol specification         | ✅ Active |
| `protocols/conformance/v1/owasp/` | Machine-readable OWASP threat vectors  | ✅ Active |

### Product Surfaces

The OSS boundary is headless. It ships the kernel CLI, HTTP APIs, OpenAPI
schema, Protobuf contracts, SDKs, receipts, conformance fixtures, and deployment
packaging that an external Console can consume. Browser UI source, design-system
packages, static viewers, Next/Vite starters, and generated HTML report
surfaces are outside this repository's trusted computing base.

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
- **Dispatch enforcement** — fail-closed PEP and policy evaluation; the Guardian budget gate has no tracker in a shipped binary (CTL-011)
- **Verifiable receipts** — signed receipts, ProofGraph, replay
- **MCP interceptor** — first-class governed MCP surface
- **OpenAI proxy** — governed proxy for OpenAI-compatible SDKs
- **Headless API contract** — HTTP routes, schemas, receipts, SDKs, and conformance fixtures for external clients
- Adapters and integration surfaces

OSS does not include:

- Hosted Mindburn operations
- Enterprise identity and admin beyond the OSS runtime contract
- Legal hold, long-term hosted retention, or regulator-facing workflows
- Organization-scale rollout, staging, or shadow enforcement on live production traffic
- Managed federation or hosted trust registries
- Private entitlement, seat management, usage metering, or account-management systems
- Non-OSS connector certification programs

The invariant is simple: OSS must stay fully useful on its own as a developer-first execution kernel: Go CLI, HTTP/API contracts, SDKs, evidence export, offline verification, replay, conformance, and release artifacts. Hosted, organization-specific, and browser UI operations live outside this repository and integrate through those public contracts.

## Troubleshooting

| Symptom | First check |
| --- | --- |
| Published output is stale or incomplete | Run `npm run helm-public:accuracy` in `docs-platform`, then check the source path and public manifest row for this page. |
| A claim needs implementation backing | Check the Source Truth files above and update the implementation, manifest, source inventory, or page in the same change. |

## Diagram

```mermaid
flowchart TD
    subgraph Ingestion["1. Ingestion & Context Plane"]
        kernel["Kernel scope"]
        retain["Retained public surfaces"]
        cli["CLI and proxy"]
        sdk["SDKs and examples"]
        protocol["Protocols and schemas"]
        exclude["Excluded hosted surfaces"]
        commercial["HELM AI Enterprise docs"]
    end

    subgraph Ledger["4. Tamper-Evident Ledger Plane"]
        verify["Receipts and verification"]
    end

    %% Operational Flow Edges
    kernel --> retain
    retain --> cli
    retain --> sdk
    retain --> protocol
    retain --> verify
    kernel --> exclude
    exclude --> commercial

    %% Premium Styling Rules
    style verify fill:#2f855a,stroke:#276749,stroke-width:2px,color:#fff
```
