---
title: HTTP API
last_reviewed: 2026-09-26
---

<!-- quantum_posture: this page documents classical TLS on the API listener and publishes the existing classical, hybrid or ML-DSA-65 receipt public keys; it claims no post-quantum transport. -->

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

The API server speaks `https://` instead when native TLS is configured; see
[Native TLS](#native-tls).

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

## Native TLS

`serve` terminates TLS on its API listener when both of these are set:

| Variable | Meaning |
| --- | --- |
| `HELM_TLS_CERT_FILE` | PEM certificate chain for the API listener |
| `HELM_TLS_KEY_FILE` | PEM private key for that certificate |
| `HELM_TLS_CLIENT_AUTH` | Optional: `require` or `verify-if-given` client certificates. Unset means off |
| `HELM_TLS_CLIENT_CA_FILE` | PEM CA bundle for client certificates; required with, and only with, `HELM_TLS_CLIENT_AUTH` |

- Set both the certificate and the key, or neither. Any partial or unreadable
  configuration stops `serve` at startup; it never falls back to plain HTTP.
- The minimum protocol version is TLS 1.2.
- The pair is re-read on the next handshake after either file's modification
  time or size changes, so a Secret that cert-manager rotates in place is
  picked up without a restart. A pair that fails to load is skipped and the
  previous one keeps serving. The client CA is read once at startup.
- With `HELM_TLS_CLIENT_AUTH=require`, a client without a certificate from
  that CA is refused during the handshake. The verified certificate is the one
  `HELM_CP_IDENTITY_REQUIRE_CNF` binds Control Plane tokens to.
- With none of the variables set, the listener is plain HTTP as before.
- The health (`HELM_HEALTH_PORT`) and metrics (`HELM_METRICS_PORT`) listeners
  stay plain HTTP, so Kubernetes probes are unchanged.
- TLS is not supported together with the Desktop loopback transport.

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

  On `POST /v1/chat/completions` the same rule protects the Kernel
  credential: an `Authorization` header whose value is the admin, service or
  organization-runtime key is dropped before the request is forwarded, so the
  provider receives no `Authorization` at all. To send a provider key, put the
  Kernel key in `X-HELM-API-Key` and the provider key in `Authorization`.

| Route | Credential | Tenant and principal | Workspace |
| --- | --- | --- | --- |
| `POST /api/v1/evaluate`, `GET /api/v1/receipts*` | `HELM_ADMIN_API_KEY` | `X-Helm-Tenant-ID` / `X-Helm-Principal-ID`, accepted only as the `HELM_RUNTIME_TENANT_ID`/`HELM_RUNTIME_PRINCIPAL_ID` pair or a pair registered through `POST /api/v1/admin/principal-bindings` | see below |
| `POST /internal/v1/organization-runtime/evaluate` | `HELM_ORGANIZATION_RUNTIME_API_KEY` | the same headers, all three required, checked against the same pair or registry | see below, plus the company activation record for that tenant and workspace |
| `POST /v1/chat/completions` | `HELM_ADMIN_API_KEY` | the configured pair only | see below; the configured workspace applies when the header is absent |
| `/mcp`, `/mcp/v1/capabilities`, `/mcp/v1/execute` | `HELM_ADMIN_API_KEY` | the configured pair only; optional headers must match it | not bound |
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
the pod traffic when the API listener runs without [native TLS](#native-tls);
`HELM_CP_IDENTITY_REQUIRE_CNF` binds tokens to the mTLS client certificate
that `HELM_TLS_CLIENT_AUTH=require` verifies. On the legacy path the admin credential is shared. Whoever holds
it can assert any registered tenant, and with the fence off any workspace.
These checks catch a missing or wrong binding from a
correct caller; they do not isolate tenants from a compromised caller. That
needs per-tenant credentials or identity taken from a verified token, which is
not implemented yet.

The emergency-stop fence is a dispatch fence only; it does not cancel already
running work.

**The MCP gateway is single-tenant.** It serves the configured tenant
(`HELM_RUNTIME_TENANT_ID`, `default` when unset) and refuses a caller that
asserts another one; registered principal bindings do not extend it. Each
decision receipt is written in that tenant, so `GET /api/v1/receipts` lists it
for that tenant.

## Egress

Production egress is deny-all. Every production Guardian (`serve`, `proxy`,
`mcp serve`) builds its egress checker with no allowlist, and no flag or
variable supplies one. A decision whose trusted context names or requires a
destination is denied with `DATA_EGRESS_BLOCKED`. `POST /v1/chat/completions`
requires its upstream host as that destination, so on `serve` it denies every
call before reaching the upstream. The standalone `helm-ai-kernel proxy` names
no destination and is not affected.

## Receipt Keyring

`GET /api/v1/receipt-keyring` is public and read-only. It returns the public
half of the receipt signer the Kernel is running, in the exact shape the
Control Plane reads from `HELM_KERNEL_RECEIPT_KEYRING`:

```json
{"keyring_version":"kernel-evaluate-receipt-keyring.v1","keys":[{"key_id":"root","profile":"classical","ed25519_public_key_hex":"<64 lowercase hex>"}]}
```

- `key_id`, `profile` and the public keys are the values the signer stamps on
  every receipt (`key_id`, `signature_profile`, `public_key_set`).
- `profile` is `classical` (Ed25519, the default), `hybrid` (Ed25519 and
  ML-DSA-65, with `HELM_RECEIPT_PROFILE=hybrid`, adding
  `ml_dsa_65_public_key_hex`) or `pqc` (ML-DSA-65 only).
- The body is one JSON object with no other fields, so it can be stored as
  the Control Plane's pin as-is:

  ```bash
  curl -fsS --cacert ca.crt https://<kernel>:8080/api/v1/receipt-keyring
  ```

- Without a receipt signer the route answers `503`, never an empty `keys`
  array, which the Control Plane would read as "not configured".
- It carries no private key material. Fetch it over TLS or check it out of
  band: over plain HTTP a network attacker could substitute the keys.

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
