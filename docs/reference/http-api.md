---
title: HTTP API
last_reviewed: 2026-07-13
---

# HTTP API

The public HTTP surface is for local proof, boundary evaluation, receipts,
evidence export, conformance checks, MCP authorization, and the
OpenAI-compatible proxy.

Use the CLI first. Use HTTP when you need a local client or generated types.

## Base URLs

| Surface | Base URL |
| --- | --- |
| Local boundary | `http://127.0.0.1:7714` |
| Local API server | `http://127.0.0.1:8080` |
| OpenAI-compatible proxy | `http://127.0.0.1:9090/v1` |

## Public Route Families

| Family | Routes |
| --- | --- |
| Health | `GET /api/health` |
| Demo proof | `POST /api/demo/run`, `POST /api/demo/verify`, `POST /api/demo/tamper` |
| Evaluate | `POST /api/v1/evaluate` |
| Receipts | `GET /api/v1/receipts`, `GET /api/v1/receipts/tail`, `GET /api/v1/receipts/{receipt_id}` |
| Evidence | `POST /api/v1/evidence/export`, `POST /api/v1/evidence/verify` |
| Boundary | `GET /api/v1/boundary/status` |
| Conformance | `GET /api/v1/conformance/negative` |
| MCP approvals | `GET /api/v1/mcp/registry`, `POST /api/v1/mcp/scan`, `POST /api/v1/mcp/authorize-call` |
| OpenAI proxy | `POST /v1/chat/completions` |

Protected runtime, identity, trust-key mutation, billing, console diagnostics,
direct MCP execution, onboarding, and unpublished operations are not part of the
public docs surface.

## Auth Classes

| Class | Behavior |
| --- | --- |
| `public` | No runtime admin credential required |
| `tenant_scoped` | Requires `Authorization: Bearer $HELM_ADMIN_API_KEY` and matching tenant/principal context |
| `admin` / `authenticated` | Requires `Authorization: Bearer $HELM_ADMIN_API_KEY` |
| `service_internal` | Requires `Authorization: Bearer $HELM_SERVICE_API_KEY` |

When `HELM_EMERGENCY_STOP_FENCE_ENABLED=1`, `POST /api/v1/evaluate`
additionally requires an authenticated tenant matching the server-owned
`HELM_RUNTIME_TENANT_ID` and `X-Helm-Workspace-ID` matching the server-owned
`HELM_RUNTIME_WORKSPACE_ID`. A request body cannot choose either scope
binding. This is a dispatch fence only; it does not cancel already running
work.

The unauthenticated OpenAI-compatible proxy (`POST /v1/chat/completions`) is
unavailable while this fence is enabled because request JSON is not an
authoritative tenant/workspace binding.

## Scoped decision evaluation

`POST /api/v1/evaluate` is the sole public evaluator contract. It requires:

- `Authorization: Bearer $HELM_ADMIN_API_KEY`
- `X-Helm-Tenant-ID`, `X-Helm-Principal-ID`, and `X-Helm-Session-ID`
- Optional `X-Helm-Workspace-ID` when the caller is within a workspace scope
- Optional `Idempotency-Key`, scoped to the authenticated tenant, principal,
  workspace, session, method, and path

Its JSON body is strictly limited to the following shape; `principal`, tenant,
workspace, and session values in JSON are rejected rather than trusted:

```json
{
  "action": "read-ticket",
  "resource": "ticket:123",
  "context": {"source": "example"},
  "session_history": []
}
```

The response is a signed `DecisionRecord`. `X-Helm-Receipt-ID` identifies the
durable receipt. When an idempotency record is replayed,
`X-Helm-Idempotency-Replayed: true` is returned. A reused key with a different
request fingerprint in the same authenticated scope is rejected with `409`.

## Decision signature schemas

`DecisionRecord.signature_schema` identifies the canonical payload used for
its signature. The current request-bound schema is
`helm.decision.signature.v2`. It binds the authenticated subject, governed
action and resource, effect/policy hashes, decision outcome, signer-selected
signature type, and other security-relevant record metadata. A signature fails
verification if any of those v2-bound values change.

Older stored decisions may omit `signature_schema`; that explicitly denotes the
legacy v1 payload and is accepted only for backward verification. Clients must
not treat an absent schema as proof that subject, action, or resource were
cryptographically bound. Unknown schema values fail verification.

At an effect boundary, v1 is audit-only even when its historical signature
verifies: the Guardian rejects it before issuing an execution intent, and the
SafeExecutor rejects it before SafeDep evaluation or tool dispatch. New
executable decisions must use the request-bound v2 schema.

## Receipt Headers

Some routes return HELM decision metadata:

| Header | Meaning |
| --- | --- |
| `X-Helm-Decision-ID` | Boundary decision id |
| `X-Helm-Receipt-ID` | Receipt id |
| `X-Helm-Reason-Code` | Reason code |
| `X-Helm-Status` | Boundary status |
| `X-Helm-Output-Hash` | Hash binding governed output |

If a client hides headers, inspect receipts through the CLI or receipt routes.

## OpenAPI

Generate clients from:

```text
api/openapi/helm.openapi.yaml
```

Validate route drift locally:

```bash
cd core
go test ./cmd/helm-ai-kernel -run 'Test.*Route|Test.*OpenAPI|Test.*Receipt|Test.*Boundary' -count=1
```
