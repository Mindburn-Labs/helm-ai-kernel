# Approval grant consumption runtime

<!-- quantum_posture: documents classical Ed25519 grant/consumption signatures and RSA-JWKS (RS256) OAuth token verification; no post-quantum control is added or claimed. -->

Status: internal, source-owned, pre-production.

This runtime lets one authenticated workload consume one live, signed
`ApprovalGrant` for the exact pack lifecycle action already approved by the
Kernel ceremony. It also exposes a read-only recovery operation for response
loss and a separately scoped, signed near-effect dispatch admission. It does
not create approval authority, mint a generic `EffectPermit`, dispatch a
connector, cancel admitted work, or prove a production deployment.

## Startup contract

The routes are absent unless `HELM_APPROVAL_CONSUMPTION_ENABLED=1`. Once that
flag is set, any missing or invalid dependency is startup-fatal, including in a
non-production process. SQLite is rejected; the ceremony ledger must use the
PostgreSQL runtime and its forced tenant/workspace RLS policy. Scoped
emergency-stop fencing must also be enabled against the same PostgreSQL
runtime; consumption, dispatch admission, and FENCE use one
transaction-scoped advisory lock for the verified tenant/workspace.

| Variable | Requirement |
| --- | --- |
| `DATABASE_URL` | PostgreSQL DSN. The configured role must be non-superuser, must not have `BYPASSRLS`, and currently must own the target schema/tables because startup runs idempotent source-owned DDL. A separate migration/runtime credential split is not implemented in this slice. |
| `HELM_APPROVAL_CONSUMPTION_ENABLED` | Set to `1` to mount the four internal consumption/admission routes. |
| `HELM_EMERGENCY_STOP_FENCE_ENABLED` | Must be `1`; approval consumption will not start without the durable scoped-stop coordinator. |
| `HELM_APPROVAL_CONSUMER_JWKS_URL` | Absolute HTTPS JWKS URL for workload access-token verification. |
| `HELM_APPROVAL_CONSUMER_ISSUER` | Exact expected JWT `iss`. |
| `HELM_APPROVAL_CONSUMER_AUDIENCE` | Exact expected JWT `aud`; it is also bound into the persisted consumption record. |
| `HELM_APPROVAL_CONSUMER_RESOURCE` | Required RFC 8707 resource indicator for this Kernel consumption surface. |
| `HELM_APPROVAL_CONSUMER_SCOPE` | Required scope; defaults to `helm.approval.consume`. |
| `HELM_APPROVAL_DISPATCH_SCOPE` | Separate dispatch-admission scope; defaults to `helm.approval.dispatch` and must differ from the consumption scope. |
| `HELM_APPROVAL_DISPATCH_ADMISSION_TTL` | Immutable admission lifetime; defaults to `30s`, cannot exceed `1m`, and is capped by the signed grant expiry. |
| `HELM_APPROVAL_CONSUMER_MAX_TOKEN_TTL` | Maximum `iat` to `exp` interval; defaults to `5m` and cannot exceed `15m`. |
| `HELM_APPROVAL_SIGNING_KEY_REF` | Exact key reference already bound into signed grants. |
| `HELM_APPROVAL_KERNEL_TRUST_ROOT_ID` | Exact Kernel trust-root identifier already bound into signed grants. |

The token must have a valid RSA signature from the configured JWKS and include
`sub`, `tenant_id`, `workspace_id`, `iss`, `aud`, `resource`, `scope`, `iat`,
and `exp`. Caller headers and JSON fields never supply workload scope.
After initialization, the data path uses `SELECT` on
`emergency_stop_fences`, `SELECT, INSERT, UPDATE` on `approval_ceremonies`,
and `SELECT, INSERT` on `approval_dispatch_admissions`. The current process
still runs idempotent `CREATE`/`ALTER` statements at startup, so the configured
connection role must also own those schema objects; DML-only runtime authority
is a remaining hardening item. It remains non-superuser and must not receive
`BYPASSRLS`.

### Contract rollout rule

This contract epoch is intentionally fail-closed and not rolling-upgrade
compatible with approval artifacts written under an earlier contract version,
including dispatch-admission `2026-07-17`. The challenge, grant, consumption,
and dispatch-admission contracts now require the signed `connector_authority`
object, and their strict readers reject older persisted JSON rather than
inventing connector authority during recovery.

Before enabling this binary, operators must produce source-owned evidence that
the non-production approval epoch is empty or fully drained: no live
`HOLD_PENDING` ceremony, challenge, grant, consumption, or dispatch-admission
row may survive the cutover. If any
such artifact must remain recoverable, deployment is blocked until a separately
reviewed dual-read/data-migration path exists with conformance vectors for both
epochs. Mixed-version Kernel replicas, in-place rolling deployment, and
rewriting old signed artifacts are prohibited. This rule does not authorize a
production rollout; the remaining blockers below still apply.

## Internal routes

The consume and consumption-recovery routes accept the same strict JSON object
and reject unknown fields, trailing JSON, non-JSON content types, uppercase or
malformed hashes, oversized bodies, and invalid nonces before querying the
ledger.

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
  `approval-grant-consumption.v1` record. An active same-scope FENCE wins the
  shared PostgreSQL scope lock and leaves the grant in `GRANT_ISSUED`.
- `POST /internal/v1/approval-grants/recover` returns that exact record only to
  the same subject, tenant, workspace, and audience while the original grant
  remains live. It does not increment the record version, consume again, or
  create new authority. Recovery remains available after FENCE so a
  response-loss ambiguity can close with the persisted signed evidence.

The dispatch-admission routes require the separately configured dispatch
scope (default `helm.approval.dispatch`) and accept:

```json
{
  "approval_id": "approval-...",
  "attempt_id": "attempt-...",
  "consumption_hash": "sha256:<64 lowercase hex characters>",
  "idempotency_key_hash": "sha256:<64 lowercase hex characters>",
  "effect_hash": "sha256:<64 lowercase hex characters>",
  "action": "install"
}
```

`action` is one of `install`, `upgrade`, `uninstall`, or `rollback` and must
match the signed consumption. The caller cannot select a connector. The
Kernel copies the self-hashed `connector_authority` committed by the
policy-owned approval binding through challenge, verified quorum, grant, and
consumption into the signed admission. That object binds tenant/workspace,
pack, exact effect/lifecycle action, exact connector action, policy hash,
connector release scope/authority/revision, binary/signature,
sandbox/drift policy, and certification evidence.

This slice defines and preserves that immutable binding but does not yet wire a
production `BindingProvider` backed by the durable source-owned connector
registry, nor does it cryptographically validate the referenced connector
signature or certification at binding time. `state=certified`, a certification
reference, and their self-hashed snapshot are not proof that a release is
currently certified. The internal effect reservation boundary now rechecks
current revocation state, but until the production provider verifies
source-owned provenance and the boundary is deployed in the Data Plane, the
contract remains internal and non-production.

- `POST /internal/v1/approval-grants/admit-dispatch` acquires the same
  tenant/workspace advisory lock as FENCE, verifies the exact signed
  consumption and workload identity, and persists a Kernel-signed
  `approval-dispatch-admission.v1` record before returning it. FENCE-first
  rejects a new admission. Admission-first creates an admitted `NOT_STARTED`
  record that future FENCE reconciliation must treat as pre-existing work;
  that state does not claim the connector has started. This slice does not yet
  implement admission close transitions or an active-work disposition API.
- For records written under this exact contract epoch, an exact retry of an
  already committed admission returns the same immutable record and expiry,
  including after a later FENCE. Reusing an attempt with changed bindings, or
  reusing one consumption for a second attempt, conflicts. Earlier contract
  epochs are governed by the fail-closed cutover rule above and are not
  recoverable by this binary without a reviewed compatibility path.
- `POST /internal/v1/approval-grants/recover-dispatch-admission` performs the
  exact read-only response-loss recovery for the same workload identity and
  request bindings. It creates no authority and does not extend the admission
  expiry.
- Once an admission expires, exact claim/recovery still returns the same
  expired evidence, while a new attempt for that consumption conflicts. There
  is no renewal path in this slice; the Data Plane must fail closed and await
  the later close/reconciliation contract. Signature verification alone is
  not a liveness check: the effect boundary must also call the contract's
  half-open `ValidateAt(now)` gate before `expires_at`.

Successful responses set `Cache-Control: no-store` and
`X-Helm-Contract-Status: internal_non_production`. A client must persist the
returned consumption and dispatch-admission records and signatures. Production
promotion remains blocked until the Data Plane verifies the admission and
persists it atomically with `CONSUMED -> DISPATCHING` before every connector
effect, including cached and recovered consumptions. That gate is necessary
but not sufficient. The internal effect reservation boundary now compares the
immutable approved snapshot with the transactionally locked current release,
persists append-only `ADMITTED / STARTED / NOT_STARTED / UNCERTAIN` truth, lists
active work, and enforces the GitHub pre-network seam when explicitly wired.
Deployed Data Plane wiring, active-work disposition, source connector ACK,
signed close evidence, and controlled runtime proof remain required before
production or Emergency Stop claims. See
`docs/operations/effect-reservation.md`.

## Failure handling

| Status | Meaning | Operator action |
| --- | --- | --- |
| `400` | Malformed or non-canonical tuple. | Do not retry unchanged input. |
| `401` | Missing, invalid, expired, or overlong workload token. | Obtain a fresh resource-bound token. |
| `403` | Missing scope or workload identity does not match the signed grant. | Treat as a security denial; do not substitute body/header scope. |
| `404` | No record exists in the authenticated tenant/workspace scope. | Reconcile the source approval reference. |
| `409` | Grant/admission state, tuple, immutable replay binding, expiry, or the single-consumption rule rejects the operation; an active FENCE rejects new consumption/admission mutations but not exact committed admission replay/recovery. `X-Helm-Reason-Code: EMERGENCY_STOP_FENCED` identifies the bounded fence denial. | Do not dispatch. Use the matching recovery route only to reconcile an operation that may already have committed. |
| `415` | Request is not `application/json`. | Correct the client contract; do not retry unchanged input. |
| `503` | Durable authority, signature verification, runtime wiring, or scoped-stop status is unavailable. On `consume` only, `X-Helm-Reason-Code: EMERGENCY_STOP_UNVERIFIED` identifies a failed early fence check; dispatch-admission storage failures return the bounded generic authority error. | Stop dispatch and repair the Kernel dependency. |

Never retry `consume` or `admit-dispatch` by dispatching optimistically. After
an ambiguous HTTP response, call the corresponding recovery route with the
same tuple, bindings, and workload identity. A consumption record without a
live, verified dispatch admission authorizes no connector operation.

## Source-owned checks

Run:

```bash
make verify-approval-ceremony-vectors
make test-approval-ceremony-postgres
make docs-coverage
make docs-truth
```

The PostgreSQL target proves forced RLS on the ceremony, dispatch-admission,
and emergency-stop tables; single-winner consumption; exact-scope isolation;
concurrent admission/FENCE serialization; immutable exact admission replay;
post-lock expiry enforcement; denied-grant immutability; and post-FENCE
recovery with a non-bypass runtime role. These checks do not prove Data Plane
enforcement, connector execution, outcome/compensation closure, EvidencePack
emission, deployment, or GA release authority.
