# Approval grant consumption runtime

Status: internal, source-owned, pre-production.

This runtime lets one authenticated workload consume one live, signed
`ApprovalGrant` for the exact pack lifecycle action already approved by the
Kernel ceremony. It also exposes a read-only recovery operation for response
loss. It does not create approval authority, mint a generic `EffectPermit`,
dispatch a connector, or prove a production deployment.

## Startup contract

The routes are absent unless `HELM_APPROVAL_CONSUMPTION_ENABLED=1`. Once that
flag is set, any missing or invalid dependency is startup-fatal, including in a
non-production process. SQLite is rejected; the ceremony ledger must use the
PostgreSQL runtime and its forced tenant/workspace RLS policy.

| Variable | Requirement |
| --- | --- |
| `DATABASE_URL` | PostgreSQL DSN. The configured runtime role must be non-superuser and must not have `BYPASSRLS`. |
| `HELM_APPROVAL_CONSUMPTION_ENABLED` | Set to `1` to mount the two internal routes. |
| `HELM_APPROVAL_CONSUMER_JWKS_URL` | Absolute HTTPS JWKS URL for workload access-token verification. |
| `HELM_APPROVAL_CONSUMER_ISSUER` | Exact expected JWT `iss`. |
| `HELM_APPROVAL_CONSUMER_AUDIENCE` | Exact expected JWT `aud`; it is also bound into the persisted consumption record. |
| `HELM_APPROVAL_CONSUMER_RESOURCE` | Required RFC 8707 resource indicator for this Kernel consumption surface. |
| `HELM_APPROVAL_CONSUMER_SCOPE` | Required scope; defaults to `helm.approval.consume`. |
| `HELM_APPROVAL_CONSUMER_MAX_TOKEN_TTL` | Maximum `iat` to `exp` interval; defaults to `5m` and cannot exceed `15m`. |
| `HELM_APPROVAL_SIGNING_KEY_REF` | Exact key reference already bound into signed grants. |
| `HELM_APPROVAL_KERNEL_TRUST_ROOT_ID` | Exact Kernel trust-root identifier already bound into signed grants. |

The token must have a valid RSA signature from the configured JWKS and include
`sub`, `tenant_id`, `workspace_id`, `iss`, `aud`, `resource`, `scope`, `iat`,
and `exp`. Caller headers and JSON fields never supply workload scope.

## Internal routes

Both routes accept the same strict JSON object and reject unknown fields,
trailing JSON, non-JSON content types, uppercase or malformed hashes, oversized
bodies, and invalid nonces before querying the ledger.

```json
{
  "approval_id": "approval-...",
  "grant_id": "grant-...",
  "grant_hash": "sha256:<64 lowercase hex characters>",
  "nonce": "<64 lowercase hex characters>"
}
```

- `POST /internal/v1/approval-grants/consume` performs the single atomic
  `GRANT_ISSUED -> CONSUMED` transition and returns the signed
  `approval-grant-consumption.v1` record.
- `POST /internal/v1/approval-grants/recover` returns that exact record only to
  the same subject, tenant, workspace, and audience while the original grant
  remains live. It does not increment the record version or consume again.

Responses set `Cache-Control: no-store` and
`X-Helm-Contract-Status: internal_non_production`. A client must persist the
returned consumption record and signature before attempting the separately
authorized pack lifecycle dispatch.

## Failure handling

| Status | Meaning | Operator action |
| --- | --- | --- |
| `400` | Malformed or non-canonical tuple. | Do not retry unchanged input. |
| `401` | Missing, invalid, expired, or overlong workload token. | Obtain a fresh resource-bound token. |
| `403` | Missing scope or workload identity does not match the signed grant. | Treat as a security denial; do not substitute body/header scope. |
| `404` | No record exists in the authenticated tenant/workspace scope. | Reconcile the source approval reference. |
| `409` | Grant state, tuple, replay, or expiry rejects the operation. | Use recovery only after a response-loss ambiguity; otherwise request new approval. |
| `415` | Request is not `application/json`. | Correct the client contract; do not retry unchanged input. |
| `503` | Durable authority, signature verification, or runtime wiring is unavailable. | Stop dispatch and repair the Kernel dependency. |

Never retry `consume` by dispatching optimistically. After an ambiguous HTTP
response, call `recover` with the same tuple and the same workload identity. If
recovery does not return the signed record, no connector operation is
authorized.

## Source-owned checks

Run:

```bash
make verify-approval-ceremony-vectors
make test-approval-ceremony-postgres
make docs-coverage
make docs-truth
```

The PostgreSQL target proves forced RLS and single-winner concurrency with a
non-bypass runtime role. These checks do not prove Data Plane integration,
connector execution, outcome/compensation closure, EvidencePack emission,
deployment, or GA release authority.
