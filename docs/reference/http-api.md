---
title: HTTP API
last_reviewed: 2026-07-11
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

## Tenant and Workspace Binding

The Kernel does not issue tenant tokens. On the routes the Control Plane calls,
the tenant, principal and workspace come from one of two places:

- **A Control Plane identity token (ADR-0005, dual-accept).** It is accepted
  when `HELM_CP_IDENTITY_JWKS_URL`, `HELM_CP_IDENTITY_ISSUER`,
  `HELM_CP_IDENTITY_AUDIENCE` and `HELM_CP_IDENTITY_ACTOR` are set, on
  `POST /api/v1/evaluate`, `POST /internal/v1/organization-runtime/evaluate`,
  `GET /api/v1/receipts*` and `POST /v1/chat/completions`. The bearer is an
  RS256 token from that issuer, verified against its key set:
  - `sub` is the principal;
  - `tenant_id` and `workspace_id` are the scope;
  - `act.sub` must be the configured actor;
  - `aud` must be exactly `HELM_CP_IDENTITY_AUDIENCE`, as its only value;
  - `scope` must be exactly the route family's scope, and only that one
    (`helm.evaluate`, `helm.organization_runtime.evaluate`,
    `helm.receipts.read`, `helm.proxy.chat`);
  - the lifetime is at most 300 s.

  The token may be sent as `Authorization: Bearer` or in `X-HELM-API-Key`.
  On `POST /v1/chat/completions` send it in `X-HELM-API-Key`: that route
  forwards `Authorization` upstream as the provider credential, so a token
  sent there is dropped before the request is forwarded. The key set is
  fetched at most once per 30 s, whatever `kid` a request names. If the
  endpoint is unreachable, cached keys keep verifying for up to one hour
  after the last successful fetch; with no usable keys the route answers
  `503`.

  Identity headers are then optional and must equal the claims. When
  `principal_bindings` holds rows for `sub`, the token's tenant must be one of
  them; a principal with no row passes on the token and is counted in
  `helm_token_unbound_principal_total{route}`. With the fence on, the token's
  scope must still be the configured one.
- **Otherwise, the legacy path:** the Control Plane's assertion in headers
  under a shared Kernel credential, as in the table below. Each such request
  is counted in `helm_legacy_header_identity_total{route}`. How much of the
  assertion is checked depends on `HELM_EMERGENCY_STOP_FENCE_ENABLED`; see the
  workspace rules below the table.

| Route | Credential | Tenant and principal | Workspace |
| --- | --- | --- | --- |
| `POST /api/v1/evaluate`, `GET /api/v1/receipts*` | `HELM_ADMIN_API_KEY` | `X-Helm-Tenant-ID` / `X-Helm-Principal-ID`, accepted only as the `HELM_RUNTIME_TENANT_ID`/`HELM_RUNTIME_PRINCIPAL_ID` pair or a pair registered through `POST /api/v1/admin/principal-bindings` | see below |
| `POST /internal/v1/organization-runtime/evaluate` | `HELM_ORGANIZATION_RUNTIME_API_KEY` | the same headers, all three required, checked against the same pair or registry | see below, plus the company activation record for that tenant and workspace |
| `POST /v1/chat/completions` | `HELM_ADMIN_API_KEY` | the configured pair only | see below; the configured workspace applies when the header is absent |
| `POST /api/v1/extauthz/authorize` | `HELM_SERVICE_API_KEY` | `tenant_id` in the body must equal `HELM_RUNTIME_TENANT_ID` | `workspace_id` in the body must equal `HELM_RUNTIME_WORKSPACE_ID`; both must be configured |
| `/internal/v1/generated-spec-approvals/*`, approval and effect workload routes | workload bearer token | token claims | token claims |
| `POST /internal/emergency-stop/fence` | `HELM_SERVICE_API_KEY` | the fence command's scope; see [Emergency-stop fence](../EMERGENCY_STOP_FENCE.md) | the same |

Workspace binding, for the first three rows:

- **Fence on.** The Kernel serves one configured scope. The authenticated
  tenant must equal `HELM_RUNTIME_TENANT_ID`, so a registered binding for
  another tenant is refused. `X-Helm-Workspace-ID` must name
  `HELM_RUNTIME_WORKSPACE_ID`; evaluate and receipt reads require the header.
  An unconfigured workspace refuses every request, because the fence covers
  only the configured scope.
- **Fence off (the default, and the deployed QA and staging shape).** Nothing
  binds the tenant or workspace to the configured scope. The tenant is whatever
  the route gate accepted: the env pair or any registered binding.
  `X-Helm-Workspace-ID` is the caller's unverified assertion. This is a known
  gap. A multi-tenant Control Plane cannot be served by one configured tenant,
  so the fix is identity taken from a verified token, planned for a later
  HELM-755 slice.

Ext-authz is the exception: it is bound to the configured scope in both modes.

**Binding a principal.** `POST /api/v1/admin/principal-bindings` (admin key,
body `{"tenant_id", "principal_id"}`) answers `201` for a new binding and `200`
when the pair is already bound. A principal holds bindings in one tenant only:
binding one that is already bound in another tenant answers `409` with reason
code `TENANT_ISOLATION`, writes nothing, and counts
`helm_principal_rebind_refused_total`. The check and the insert run in one
transaction, serialized per principal, so concurrent binds into different
tenants cannot both succeed (ADR-0005 §11). `HELM_CROSS_TENANT_PRINCIPALS`
(chart: `helm.auth.crossTenantPrincipals`), a comma-separated list that is
empty by default, names the principals that may hold bindings in several
tenants, such as the Control Plane's `helm-workflow-runner`; each such bind is
logged. Listing a principal widens the token cross-check above for exactly
that principal: its token passes in every tenant it is bound to, and is still
refused in any tenant it is not.

**Stores without a tenant dimension.** The boundary surface registry and the
Launchpad run store are each one store per process. Their `tenant_scoped`
routes serve only the configured tenant (`HELM_RUNTIME_TENANT_ID`, `default`
when unset), and every other bound tenant gets `403`, with the fence on or off.
These routes are `/api/v1/boundary/{status,capabilities,records}`,
`/api/v1/evidence/verification-scopes`, `/api/v1/telemetry/harness-traces`,
`/api/v1/plans/transactions`, `/api/v1/harness/change-contracts` and
`/api/v1/launchpad/*`, together with their item routes. The Launchpad routes
are also off unless `HELM_LAUNCHPAD_ROUTES_ENABLED=1`.

Request bodies and `context` never select a scope; see below.

**What this does not provide.** With a token, identity no longer comes from
headers, but a compromised Control Plane issuer can still mint a token for any
tenant, and a token can be replayed within its lifetime by anyone who can read
the plain-HTTP pod traffic; `HELM_CP_IDENTITY_REQUIRE_CNF` binds tokens to an
mTLS client certificate where one exists. On the legacy path the admin credential is shared. Whoever holds
it can assert any registered tenant, and with the fence off any workspace.
These checks catch a missing or wrong binding from a
correct caller; they do not isolate tenants from a compromised caller. That
needs per-tenant credentials or identity taken from a verified token, which is
not implemented yet.

The emergency-stop fence is a dispatch fence only; it does not cancel already
running work.

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

## v0.8 client migration (source target)

First-party SDKs now send a canonical `EvaluateRequest`: non-blank top-level
`tool`, `effect_level`, and `session_id`. The runtime records the authenticated
principal; request-body `principal` and `agent_id` do not establish identity.

Direct-daemon callers may temporarily retain the legacy `action`/`resource`
shape only when `context.session_id` is non-blank. That compatibility path is
not an SDK contract. Migrate SDK clients to the canonical request and typed
`EvaluateResponse` before relying on the v0.8 release target.

Do not mix the two forms with different values. If canonical and legacy aliases
are both present, `tool`/`action`, `effect_level`/`resource`, and top-level
`session_id`/`context.session_id` must match after trimming. The runtime rejects
conflicts before policy evaluation or receipt issuance.

Request `context` is not an identity or scope authority. The daemon removes
caller-supplied principal, tenant, and workspace authority spellings before
Guardian evaluation, then adds only the canonical values bound by the
authenticated request. Other context fields are preserved.

Receipt reads are tenant-scoped. Prefer `session_id`; legacy `agent` is an
alias for that signed session ID and is never an executor filter. A session
listing accepts `since=lamport:<n>`. A tenant-wide listing must continue with
the opaque `v1.<base64url>` `next_cursor` (or SSE event ID), because scalar
Lamport clocks can collide across signed sessions.
