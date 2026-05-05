# HELM OSS Execution Boundary Response

HELM OSS is implemented as the proof-bearing execution boundary for agent actions. Outer scanners, gateways, frameworks, and observability systems can coexist with HELM, but they do not replace HELM's signed allow/deny receipts, native EvidencePack roots, or fail-closed PEP/PDP semantics.

## Implemented OSS Surfaces

- Negative conformance vectors: `helm conform negative --json` and `GET /api/v1/conformance/negative`.
- MCP quarantine and approval records: `helm mcp approve` plus `GET|POST /api/v1/mcp/registry` and `POST /api/v1/mcp/registry/approve`.
- MCP execution firewall primitives: list-time scope filtering, call-time authorization, schema pinning, quarantine checks, and sealed `ExecutionBoundaryRecord` allow/deny outputs.
- Sandbox grant evidence: `SandboxGrant` contracts, JSON schemas, `helm sandbox inspect`, and `GET /api/v1/sandbox/grants/inspect`.
- ReBAC snapshot evidence: deterministic relationship tuple hashing and sealed `AuthzSnapshot` records.
- Evidence export wrappers: `helm evidence export --envelope`, `POST /api/v1/evidence/envelopes`, and `EvidenceEnvelopeManifest` records for DSSE/JWS first, with SCITT/COSE behind explicit experimental enablement.

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
cd core && go test ./pkg/contracts ./pkg/mcp ./pkg/authz ./pkg/evidence ./pkg/conformance ./pkg/runtime/sandbox ./cmd/helm
```

Console verification:

```sh
make test-console
```
