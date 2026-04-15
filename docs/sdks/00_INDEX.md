---
title: 00_INDEX
---

# HELM SDK Documentation

## Available SDKs

| Language | Package | Install | Docs |
|----------|---------|---------|------|
| TypeScript | `@mindburn/helm` | `npm install @mindburn/helm` | [sdk/ts/README.md](../../sdk/ts/README.md) |
| Python | `helm-sdk` | `pip install helm-sdk` | [sdk/python/README.md](../../sdk/python/README.md) |
| Go | `helm-oss/sdk/go` | `go get github.com/Mindburn-Labs/helm-oss/sdk/go` | [sdk/go/README.md](../../sdk/go/README.md) |
| Rust | `helm-sdk` | `cargo add helm-sdk` | [sdk/rust/README.md](../../sdk/rust/README.md) |
| Java | `ai.mindburn.helm:helm` | Maven/Gradle | [sdk/java/README.md](../../sdk/java/README.md) |

## Common API Surface

Every SDK exposes the same core primitives:

| Method | Description |
|--------|-------------|
| `chatCompletions` | Governed chat completion via HELM proxy |
| `approveIntent` | Submit approval for high-risk operations |
| `listSessions` | List ProofGraph sessions |
| `getReceipts` | Get receipts for a session |
| `exportEvidence` | Export EvidencePack |
| `verifyEvidence` | Verify EvidencePack offline |
| `conformanceRun` | Run conformance check |
| `health` | Health check |

Every error includes a typed `reason_code` (e.g., `DENY_TOOL_NOT_FOUND`, `BUDGET_EXCEEDED`).

## Zero-SDK Path

You don't need an SDK to use HELM. Point any OpenAI-compatible client at the HELM proxy:

```bash
export OPENAI_BASE_URL=http://localhost:8080/v1
```

SDKs add typed errors, receipt parsing, and framework-specific adapters.

## Key Packages for SDK Consumers

Beyond the core API surface, SDK consumers should be aware of the following packages and types:

### Identity (W3C DID)

Agents are identified via W3C Decentralized Identifiers. SDKs expose DID creation and resolution:

| Method | Description |
|--------|-------------|
| `createAgentDID` | Generate a new W3C DID for an agent |
| `resolveDID` | Resolve a DID to its public key and metadata |
| `verifyDIDSignature` | Verify a signature against a DID document |

DID format: `did:helm:<key-fingerprint>`. All receipts reference the signer's DID.

### Hybrid Signing

Receipts and evidence packs can be signed with hybrid Ed25519 + ML-DSA-65:

| Method | Description |
|--------|-------------|
| `verifyHybridSignature` | Verify both classical and post-quantum signatures |
| `getSignatureAlgorithm` | Returns `ed25519`, `ml-dsa-65`, or `hybrid` |

Hybrid signatures are backwards-compatible — verifiers that only support Ed25519 can verify the classical component.

### Cost Types

SDKs expose cost attribution and estimation types:

| Type | Description |
|------|-------------|
| `CostEstimate` | Pre-execution cost estimate (amount, confidence, model) |
| `CostAttribution` | Post-execution cost record (agent, session, tool, amount) |
| `BudgetStatus` | Remaining budget, burn rate, projected exhaustion time |

### Evidence Summaries

For large evidence packs, SDKs support constant-size summaries:

| Method | Description |
|--------|-------------|
| `exportEvidenceSummary` | Export a 256-byte cryptographic summary of an evidence pack |
| `verifyEvidenceSummary` | Verify a summary against a full evidence pack |

### MCPTox Reports

When using MCP tools, SDKs surface MCPTox scan results:

| Type | Description |
|------|-------------|
| `MCPToxReport` | Scan results for a tool (rug_pull, typosquatting, supply_chain flags) |
| `ToolProvenanceAttestation` | Signed attestation of tool origin and integrity |

## Contract Versioning

SDKs are generated from [api/openapi/helm.openapi.yaml](../../api/openapi/helm.openapi.yaml) and [protocols/proto/helm/](../../protocols/proto/helm/). CI prevents drift between the spec and generated types. Run `make codegen-check` to verify.
