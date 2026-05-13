# HELM AI Kernel Execution Boundary Response

HELM AI Kernel is implemented as the proof-bearing execution boundary for agent actions. Outer scanners, gateways, frameworks, and observability systems can coexist with HELM, but they do not replace HELM's signed allow/deny receipts, native EvidencePack roots, or fail-closed PEP/PDP semantics.

## Implemented OSS Surfaces

- Boundary kernel: `helm-ai-kernel boundary status|capabilities|records|get|verify|checkpoint` and `/api/v1/boundary/status`, `/api/v1/boundary/capabilities`, `/api/v1/boundary/records`, `/api/v1/boundary/checkpoints`.
- Negative conformance vectors: `helm-ai-kernel conform negative --json`, `helm-ai-kernel conform vectors --json`, `GET /api/v1/conformance/negative`, and `GET /api/v1/conformance/vectors`.
- MCP quarantine and approval records: `helm-ai-kernel mcp scan|wrap|list|get|approve|revoke`, `GET|POST /api/v1/mcp/registry`, `POST /api/v1/mcp/registry/{server_id}/approve`, and `POST /api/v1/mcp/registry/{server_id}/revoke`.
- MCP execution firewall primitives: `helm-ai-kernel mcp auth-profile list|put|verify`, `helm-ai-kernel mcp authorize-call`, `GET|PUT /api/v1/mcp/auth-profiles`, `POST /api/v1/mcp/authorize-call`, and the MCP protected-resource metadata route.
- Identity and ReBAC snapshot evidence: `helm-ai-kernel identity agents`, `helm-ai-kernel authz health|check|snapshots|get`, `/api/v1/identity/agents`, `/api/v1/authz/health`, `/api/v1/authz/check`, and `/api/v1/authz/snapshots`.
- Approval, timelock-ready, and budget surfaces: `helm-ai-kernel approvals list|create|approve|deny|revoke`, `helm-ai-kernel budget list|set|verify`, `/api/v1/approvals`, and `/api/v1/budgets`.
- Sandbox grant evidence: `helm-ai-kernel sandbox profiles|grant|list|get|verify|preflight|inspect`, `/api/v1/sandbox/profiles`, `/api/v1/sandbox/grants`, and `/api/v1/sandbox/preflight`.
- Evidence export wrappers: `helm-ai-kernel evidence export --envelope`, `helm-ai-kernel evidence envelope list|create|get|verify`, `/api/v1/evidence/envelopes`, `/api/v1/evidence/export`, `/api/v1/evidence/verify`, and `/api/v1/replay/verify`.
- Non-authoritative telemetry and coexistence: `helm-ai-kernel telemetry otel-config`, `helm-ai-kernel coexistence manifest`, `helm-ai-kernel integrate scaffold --framework <name>`, `/api/v1/telemetry/otel/config`, `/api/v1/telemetry/export`, and `/api/v1/coexistence/capabilities`.
- Public SDK coverage: Go, Python, TypeScript, Rust, and Java expose the new route families as typed or structured clients.
- Console coverage: the HELM AI Kernel Console shows route-backed boundary, MCP, sandbox, authz, approvals, budgets, evidence, conformance, telemetry, and coexistence workspaces without private-only state.

## Durable State

`helm-ai-kernel serve` stores boundary surface state in the runtime database through the `boundary_surface_snapshots` table. Lite Mode uses the existing SQLite database; Postgres deployments use the same table contract. Standalone CLI commands use `HELM_BOUNDARY_REGISTRY_PATH` or `HELM_DATA_DIR/boundary/surfaces.json` so local records, approvals, checkpoints, envelopes, and budget changes survive separate CLI invocations.

## Boundary Rule

Every execution path that reaches a tool, connector, MCP server, OpenAI-compatible proxy, or sandbox must have a HELM boundary record before dispatch. Deny paths must still emit receipts. Missing policy, stale policy, PDP outage, stale relationship snapshots, missing credentials, malformed arguments, schema drift, direct upstream bypass, sandbox overgrant, and blocked egress are fail-closed cases.

## Native Evidence Remains Authority

External envelope formats are export wrappers over HELM-native EvidencePack roots. They are useful for interoperability, procurement, and audit handoff, but offline verification starts with HELM receipts, grant/snapshot hashes, and the EvidencePack manifest.

## Public Contract Files

- `schemas/receipts/sandbox_grant.v1.json`
- `schemas/receipts/authz_snapshot.v1.json`
- `schemas/receipts/mcp_authorization_profile.v1.json`
- `schemas/receipts/execution_boundary_record.v1.json`
- `schemas/receipts/evidence_envelope_manifest.v1.json`

## Verification

Targeted verification for this boundary slice:

```sh
go test ./core/pkg/contracts ./core/pkg/boundary ./core/cmd/helm-ai-kernel
cd tests/conformance && go test ./...
cd sdk/go && GOWORK=off CGO_ENABLED=0 go test ./client
cd sdk/python && python -m pytest -q
cd sdk/ts && npm test
cd sdk/rust && cargo test
cd sdk/java && mvn test -q
```

Console verification:

```sh
make test-console
```
