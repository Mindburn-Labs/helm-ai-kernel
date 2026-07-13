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

## Canonical Evaluate Contract

`POST /api/v1/evaluate` accepts one strict JSON body:

```json
{
  "action": "EXECUTE_TOOL",
  "resource": "local.echo",
  "context": {
    "request_id": "request-123"
  }
}
```

`Authorization: Bearer $HELM_ADMIN_API_KEY`, `X-Helm-Tenant-ID`, and
`X-Helm-Principal-ID` are required. `X-Helm-Workspace-ID` is optional unless
the scoped emergency-stop fence is enabled, when it must match the
server-owned workspace binding.

The body cannot select identity, tenant, workspace, or trusted security
metadata. Top-level `principal`, `session_history`, legacy evaluator fields,
and unknown fields are rejected with `400`. `context` must not contain
`principal_id`, tenant or workspace aliases, or Guardian-owned keys such as
`security_context_trusted`, `credential_hash`, `session_id`,
`source_channel`, `trust_level`, or `destination`.

Each invocation is evaluated independently. This route does not advertise
`Idempotency-Key` replay or conflict semantics. Its response is the typed,
signed `DecisionRecord`; the authenticated principal, action, and resource are
bound before it is signed.

### Migration

The former generic/legacy evaluator payload is retired. Do not send
`tool`, `args`, `agent_id`, `effect_level`, `session_id`, or body `principal`
to `/api/v1/evaluate`; do not retain a dual-payload fallback. Use the typed
`DecisionRequest` and SDK identity configuration instead. Framework adapter
helpers submit governed chat completions and are not direct evaluator
conformance evidence.

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
