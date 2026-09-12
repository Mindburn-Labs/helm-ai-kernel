---
title: MCP 2026-07-28 RC Authorization Mapping
last_reviewed: 2026-09-12
---

<!-- quantum_posture: this page maps OAuth/JWT bearer validation performed by
core/pkg/mcp/jwks.go (classical JWS via the configured JWKS) and references the
ID-JAG exchange of the Enterprise-Managed Authorization extension, which happens
outside HELM; it adds no cryptographic control of its own. -->

# MCP 2026-07-28 Authorization Mapping

## Audience

Security reviewers and integrators mapping the HELM policy engine to the six
authorization SEPs of the MCP 2026-07-28 revision. The revision was published
as a release candidate on 2026-06-09 and finalized on 2026-07-28; the SEP
mapping below is unchanged between the two.

## Source Truth

- Spec source: <https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization>
  (release candidate announcement:
  <https://blog.modelcontextprotocol.io/posts/2026-07-28-release-candidate/>;
  final release: <https://blog.modelcontextprotocol.io/posts/2026-07-28/>)
- Conformance vectors: `core/pkg/mcp/testdata/mcp_2026_07_28_authz_vectors.json`
- Vector driver: `core/pkg/mcp/mcp_2026_07_28_authz_vectors_test.go`
- Enforcement points: `core/pkg/mcp/jwks.go`, `core/pkg/mcp/firewall.go`,
  `core/pkg/mcp/oauth_context.go`, `core/pkg/mcp/gateway.go`
- Validation: `cd core && go test ./pkg/mcp/ -run TestMCP20260728AuthorizationSEPVectors`

## Mapping

The 2026-07-28 revision hardens MCP authorization toward deployed OAuth 2.0 /
OpenID Connect practice through six SEPs. HELM's position is the protected resource and
policy enforcement point (PEP): it validates inbound authorization, enforces
scopes per tool call, and emits sealed structured decision records.

| SEP | Requirement | HELM enforcement point | Status |
| --- | --- | --- | --- |
| SEP-2468 | Validate `iss` on authorization responses (RFC 9207) to stop mix-up attacks. | `JWKSValidator` rejects tokens whose `iss` differs from the configured issuer (`HELM_OAUTH_ISSUER`) with `invalid_issuer`. | Enforced (vectors `sep-2468-*`) |
| SEP-837 | Clients declare OIDC `application_type` during Dynamic Client Registration. | Client-side obligation. HELM is the resource/PEP, not the registering client; no kernel surface. SDK clients performing DCR must declare it. | Client obligation (documented) |
| SEP-2352 | Credentials bind to the issuing AS `issuer`; re-register when resources migrate. | `JWKSValidator` binds acceptance to issuer + RFC 8707 resource indicator (`HELM_OAUTH_RESOURCE`); tokens minted for another resource fail `invalid_resource`. | Enforced (vectors `sep-2352-*`) |
| SEP-2207 | How to request refresh tokens from OIDC-style authorization servers. | Client-side acquisition flow. HELM validates each presented access token (issuer, audience, resource, scopes, expiry) regardless of how it was refreshed. | Client obligation (documented) |
| SEP-2350 | Scope accumulation during step-up authorization. | `ExecutionFirewall.AuthorizeToolCall` + `hasAllOAuthScopes`: calls lacking the elevated scope are denied fail-closed (`INSUFFICIENT_PRIVILEGE`); accumulated grants are honored monotonically; list-time visibility (`FilterVisibleTools`) follows the same scope rules. | Enforced (vectors `sep-2350-*`) |
| SEP-2351 | `.well-known` discovery suffix clarification. | Gateway serves RFC 9728 protected-resource metadata on both `/.well-known/oauth-protected-resource` and `/.well-known/oauth-protected-resource/mcp`, advertising `authorization_servers` and `scopes_supported`. | Enforced (vectors `sep-2351-*`) |

## Structured audit (SIEM-ready)

Every tool-call authorization decision — allow or deny — produces a sealed
`contracts.ExecutionBoundaryRecord` carrying `record_id`, `policy_epoch`,
`tool_name`, `args_hash`, `mcp_server_id`, `oauth_resource`, sorted
`oauth_scopes`, `verdict`, `reason_code`, `created_at`, and a JCS/SHA-256
`record_hash`. Records are JSON, hash-bound, and stream into the append-only
audit store, which exports to SIEM pipelines via the audit evidence pack and
the AAT JSONL mode (`helm-ai-kernel export aat`). The vector driver asserts
these fields on every tool-call vector. For trace correlation across
gateways, OTel context propagates per SEP-414 (W3C Trace Context in `_meta`).

## Final-revision items outside the six SEPs

Verified against the final 2026-07-28 text on 2026-09-12. None of these
change the enforcement points above; they bound what this page claims.

- Dynamic Client Registration (RFC 7591) is deprecated in favour of Client ID
  Metadata Documents (`draft-ietf-oauth-client-id-metadata-document`), which
  clients SHOULD support. HELM is the protected resource and does not register
  clients; the SEP-837 row above stays a client obligation. HELM does not host
  an authorization server and therefore does not resolve CIMD URLs.
- `Enterprise-Managed Authorization` (`io.modelcontextprotocol/enterprise-managed-authorization`,
  stable extension) lets a client exchange an Identity Assertion JWT
  Authorization Grant from an enterprise IdP at the MCP authorization server.
  The token that reaches HELM is still validated by `JWKSValidator` on issuer,
  audience, resource, scopes and expiry; HELM performs no ID-JAG exchange.
- Protocol-version negotiation: `core/pkg/mcp/protocol.go` declares
  `2025-11-25` as the latest supported revision. The final 2026-07-28 wire
  contract (no `initialize`, `_meta`-carried version and capabilities,
  `server/discover`, `resultType` on every result, `Mcp-Method`/`Mcp-Name`
  headers) is not implemented by the gateway. This page maps only the
  authorization model, which the gateway enforces regardless of revision.

## Out-of-scope notes

- The revision also removes protocol-level sessions (SEP-2567) and the
  `initialize` handshake (SEP-2575); HELM's session-scoped authorization is
  carried in validated token claims and per-call scope grants, so
  authorization does not depend on the removed `Mcp-Session-Id` header.
- Gateway/proxy authorization propagation beyond trace context is not part
  of the six authorization SEPs; transitive delegation enforcement is
  tracked separately (PCAS gap analysis, MIN-494).
