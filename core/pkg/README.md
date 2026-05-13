# HELM AI Kernel Core Packages Source Owner

## Audience

Use this file when you need to find the package that owns runtime, policy, receipt, verifier, evidence, MCP, sandbox, compliance, connector, or governance behavior.

## Responsibility

`core/pkg` is the shared runtime library layer behind the OSS CLI and server. Public docs should not duplicate every package; they should link to the right source family and explain the externally supported behavior.

## Package Families

- Boundary and policy: `boundary`, `policybundles`, `policyloader`, `celcheck`, `contracts`, `runtime`.
- Receipts and evidence: `receipts`, `evidence`, `proofgraph`, `merkle`, `ledger`, `verifier`.
- MCP and execution safety: `mcp`, `sandbox`, `runtime/sandbox`, `firewall`, `guardian`, `executor`.
- Identity and crypto: `identity`, `crypto`, `kms`, `rbac`, `auth`, `vcredentials`.
- Observability and operations: `metrics`, `otel`, `observability`, `tracing`, `audit`.
- Connectors and integrations: `connectors`, `integrations`, `registry`, `packs`.
- Compliance and governance: `compliance`, `governance`, `constitution`, `delegation`.

## Public Docs Owners

- Runtime and first-call flows: `helm-ai-kernel/developer-journey`.
- Architecture and trust boundary: `helm-ai-kernel/architecture`.
- Verification and receipts: `helm-ai-kernel/verification`.
- MCP behavior: `helm-ai-kernel/integrations/mcp`.
- Protocol and schema contracts: `helm-ai-kernel/reference/protocols-and-schemas`.

## Validation

Run:

```bash
make test
make docs-coverage
make docs-truth
```

Any public behavior claim must point to a package, test, schema, example, or generated API contract from this layer.
