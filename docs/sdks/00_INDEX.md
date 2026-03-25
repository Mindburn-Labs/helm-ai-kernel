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

## Contract Versioning

SDKs are generated from [api/openapi/helm.openapi.yaml](../../api/openapi/helm.openapi.yaml). CI prevents drift between the spec and generated types. Run `make codegen-check` to verify.
