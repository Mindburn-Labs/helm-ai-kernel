---
title: HTTP API
last_reviewed: 2026-07-12
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

When hosted metering is explicitly activated with
`HELM_METERING_ACTIVATE=1`, the same OpenAI route becomes tenant-scoped:
it requires the verified `HELM_RUNTIME_TENANT_ID`,
`HELM_RUNTIME_WORKSPACE_ID`, and `HELM_RUNTIME_PRINCIPAL_ID` binding before
the proxy contacts an upstream. The client authorization credential is not
forwarded to the model provider; configure a server-owned
`HELM_UPSTREAM_AUTHORIZATION` when the upstream requires a bearer credential.
Streaming proxy responses are unavailable in hosted metering mode until they
can settle against a durable receipt.

The internal hosted-meter API is not a public HTTP endpoint. It uses a
server-owned Bearer token plus verified scope headers and sends only receipt
identifiers; credit class, pricing, value, and OEM allocation are derived by
the control plane. See [Hosted Metering Contract](../architecture/hosted-metering-contract.md).

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
