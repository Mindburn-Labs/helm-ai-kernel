# Gateway provisioning API (contract 5a)

<!-- quantum_posture: this note describes a wire contract that carries SHA-256
digests and bearer tokens as opaque values and no signatures or keys. It adds no
cryptographic control and makes no post-quantum claim; token verification is
ADR-0005's. -->

Status: wire contract, 2026-09-30. `helm-gateway` serves it from the change that
follows this one; until then every RPC answers `unimplemented`.

- IDL: [`protocols/proto/helm/gateway/v1/authority_admin.proto`](../../protocols/proto/helm/gateway/v1/authority_admin.proto),
  package `helm.gateway.v1`, service `AuthorityAdminService`.
- Go bindings: `sdk/go/gen/helm/gateway/v1` (`authority_admin.pb.go`,
  `authority_admin.connect.go`), generated like the effect API's.
- Contract tests: `sdk/go/gen/helm/gateway/v1/authority_admin_contract_test.go`.
- Related: [Gateway effect API](gateway-effect-api.md) (Propose and the rest),
  [Authority rows](authority-rows.md) (the tables these RPCs write).

## What it is for

Admission (`EffectGatewayService.Propose`) reads a tenant's authority rows:
principals, effect types, mandates and limits. Until now nothing shipped wrote
them, so a tenant on a real gateway could not exist. This service is the one
place they are written: the Control Plane calls it when a company is enrolled,
when its organization is activated and when a mandate is delegated, narrowed or
revoked. It exposes `authorityrows.Store` (HELM-750) and adds no rule of its
own: delegation only narrows, widening needs a distinct human, a stop cannot be
bypassed by delegating.

## Operations

All eight are unary. Each takes the token scope `helm.gateway.provision` and an
`idempotency_key`.

| RPC | Effect | Direction | Approval |
|---|---|---|---|
| `UpsertTenant` | creates the token's tenant control row | adds a tenant with no authority | none |
| `UpsertPrincipal` | registers a principal of a kind, with an external subject | registering grants nothing | none |
| `DeactivatePrincipal` | disables a principal; bumps its row version | narrows | none |
| `RegisterEffectTypes` | registers effect types with their risk class; may raise a class | narrows or adds nothing a mandate grants | none |
| `ActivateRootMandate` | activates a root mandate and its limits in one transaction | **widens** | a distinct human's single-use decide token, bound to the terms |
| `DelegateMandate` | a child mandate and its limits, within every mandate above it | narrows | none |
| `RevokeMandate` | revokes a mandate; bumps its version | narrows | none |
| `SetLimit` | adds a limit, or lowers the one of the same shape | narrows | none |

Nothing here raises a limit, lowers a risk class or re-enables a principal. Each
of those widens, and needs an approved authority change (`helm.authority.*`,
contract 5), which this contract does not define. The service refuses them.

Every write runs in one PostgreSQL transaction bound to the token's tenant under
forced row security, and bumps the version of the control row of what it
narrows in that same transaction (ADR-0001 §5.1), so a permit issued under the
old row fails its dispatch claim with `AUTHORITY_CHANGED`.

## Identity and the token

The tenant comes only from the token (R9, ADR-0005). No request message carries
a tenant or a workspace, and the contract test enforces that. The principal and
mandate ids that requests do carry name the objects being provisioned, or
selectors the gateway checks against its own rows.

| Token rule | Value |
|---|---|
| Scope | `helm.gateway.provision`, the only scope any of these RPCs takes. One scope per token, as everywhere. |
| Minted for | the Control Plane's service principal, by its workload-identity issuer. |
| Audience, issuer, `act.sub`, `cnf` | as for the effect API: `helm-gateway:<env>`, `HELM_CP_IDENTITY_*`. `act.sub`, when present, must be the configured workload actor. |
| `sub` | the caller. It needs no principal row of its own, so that `UpsertTenant` can be the first call. If the tenant has a row for it, that row must not be a human's: a human is `permission_denied` (`INSUFFICIENT_PRIVILEGE`) whatever its token says. |
| `tenant_id` | the tenant provisioned. A tenant with no control row is `permission_denied` (`TENANT_ISOLATION`) on every RPC but `UpsertTenant`. |
| `workspace_id` | required of every gateway token; provisioning is tenant-wide and does not use it. |

Only the scope separates this API from the rest, so the issuer must mint it for
nobody but the Control Plane's service principal. A token of another scope is
`permission_denied`, and so is a token of this scope on any other RPC.

## Idempotency

Every RPC carries a tenant-scoped `idempotency_key` (1 to 255 bytes). The gateway
stores it in `authority_provisioning` with a SHA-256 digest of the request, in
the transaction that makes the write (R6):

- **New key.** The write happens.
- **Same key, same digest.** Nothing is written. The response is the current
  state of what the key named, with `existing = true`: a mandate that has been
  revoked since comes back revoked. `ActivateRootMandate` needs no valid
  approval token then, so a retry after the approval token expired still
  answers.
- **Same key, different digest.** `already_exists`,
  `IDEMPOTENCY_CONFLICT`. The key belongs to one operation of one tenant.

The digest covers the operation, the calling principal and every field except
the key and the approval token, after the gateway normalizes it: sets
(effect types, targets, approval-required entries) are sorted and
de-duplicated, timestamps are truncated to microseconds, and limits are sorted.
Two requests that would write the same rows therefore have one digest. A
concurrent duplicate waits for the first to commit, then replays it.

A refused call rolls back with everything else: it stores no key, and a
refused activation uses no approval token up.

## Principals: one registry, and the mapping to the kernel's

`helm-gateway` reads `authority_principals` and nothing else. The kernel's
`principal_bindings` table (ADR-0005 §3, written by
`POST /api/v1/admin/principal-bindings`) is the legacy runtime's registry of
which principals belong to which tenant; the gateway never reads it and this API
never writes it. They meet on one identifier only:

| Where | Field | Value |
|---|---|---|
| Token | `sub` | the Control Plane principal id |
| Gateway | `authority_principals.principal_id` | the same string, per tenant |
| Kernel | `principal_bindings.principal_id` | the same string, per tenant |
| Gateway | `authority_principals.kind` | `human`, `agent` or `service`: the gateway's own fact, never taken from a token claim |
| Gateway | `authority_principals.external_system`, `external_subject` | who vouches for the principal, e.g. `helm-control-plane` and the Control Plane's user id |

Consequences for the Control Plane:

- Enrolment calls `UpsertPrincipal` for the gateway, and keeps binding the same
  id in the kernel while a legacy route still needs it. Neither call implies the
  other; when the legacy routes are retired (ADR-0005 phase 4) only the gateway
  call remains.
- `UpsertPrincipal` is idempotent on the principal: the same id with the same
  kind returns the row. A **kind never changes** and a **disabled principal is
  not re-enabled**; a new person or seat gets a new id.
- **A human carries an external subject, and one subject names one principal
  per tenant.** Approver != requester (ADR-0001 I6) is checked on principal ids,
  so a person registered twice would count as two people. The unique index on
  `(tenant_id, external_system, external_subject)` refuses the second
  registration, and a principal presented with another subject than the one it
  has: `already_exists`, `IDENTITY_ISOLATION_VIOLATION`. A subject may be attached
  once to a principal that has none; it is never changed.
- The gateway does not enforce the kernel's one-tenant rule for a principal
  (ADR-0005 §11); the same id in two tenants is two rows. That rule stays where
  the shared kernel registry is.

## Activating a root mandate

A root mandate widens authority. `ActivateRootMandate` therefore takes the proof
of a distinct human's approval, and the gateway checks it inside the activating
transaction.

1. The Control Plane shows the approver the terms and limits. The approver is an
   active **human** principal of the tenant, neither `requested_by` nor
   `holder_id`.
2. The Control Plane computes the **activation digest** over what it will send
   (below), and mints a `helm.gateway.decide` token for the approver: `sub` the
   approver, `tenant_id` the tenant, `act.sub` the configured workload actor when
   it carries the decision, and exactly one `authorization_details` entry
   ```json
   {"type": "helm_mandate_activation", "activation_digest": "<lower-case hex>"}
   ```
   It mints one per decision and never caches it.
3. It calls `ActivateRootMandate` with that token in `approval_token`.

The gateway then requires all of these, and a failure changes nothing:

- the token verifies as any gateway token does, has the scope
  `helm.gateway.decide` and no other, and is of the same tenant as the provision
  token;
- it names the digest of exactly this holder, requester, terms and limits, so an
  approval of one mandate cannot activate another;
- its `jti` is new: the gateway records `(tenant, issuer, jti)` in
  `authority_token_replay` in this transaction, like a decide token on
  `Approve`. A token used by any operation is spent for all of them;
- the approver is, in the gateway's own rows, an active human principal, not
  under an active principal stop, and distinct from the requester and the holder
  (`APPROVER_NOT_DISTINCT` otherwise; the store's checks and the
  `authority_mandates` constraints hold the same rule twice);
- the holder and requester are active principals of the tenant, and every effect
  type is registered.

The mandate and its limits are created together, so admission never sees the
mandate without them.

### Activation digest v1

SHA-256 over the concatenation of the fields below, in order. `u64(n)` is an
8-byte big-endian unsigned integer and `field(b)` is `u64(len(b)) || b`. A *set*
is `u64(count)` then each member as a `field`, members sorted by their bytes and
each once. `optional(x)` is the byte `0x00` when `x` is unset, and `0x01`
followed by `u64(x)` when it is set.

1. `field("helm.gateway.v1.mandate-activation-digest.v1")`: the domain tag;
2. `field(holder_id)`;
3. `field(requested_by)`;
4. the set of `terms.effect_types`;
5. `optional(terms.per_call_limit)`;
6. `optional(terms.approval_threshold)`;
7. `field(valid_from)`, then `field(valid_until)`: RFC 3339 text in UTC with
   exactly six fractional digits and a `Z` suffix, truncated to microseconds,
   never rounded, for example `2026-10-30T12:30:45.123456Z`;
8. the set of `terms.targets` (empty: any target);
9. `field(terms.condition)`;
10. the set of `terms.approval_required`;
11. `u64(count)` of `terms.risk_classes`, then for each entry sorted by effect
    type bytes: `field(effect_type)` and `field(class)`, the class in lower case
    (`low`, `medium`, `high`, `irreversible`);
12. `u64(count)` of `limits`, then each limit, sorted by unit bytes, measure,
    window, span and value: `field(unit)`, `field(measure)` (`sum`, `count`,
    `distinct`), `field(window)` (`none`, `hour`, `day`, `month`), `u64(span)`
    and `u64(value)`.

The token carries the digest as 64 lower-case hexadecimal characters. Amounts are
non-negative integers before hashing.

Test vector (`TestActivationDigestVector`):

| Field | Value |
|---|---|
| `holder_id` | `agent-a` |
| `requested_by` | `human-a` |
| `effect_types` | `github.repository.get`, `github.branch.create_from_changes`, `github.repository.get` |
| `per_call_limit` | unset |
| `approval_threshold` | `0` |
| `valid_from` | `2026-09-30T00:00:00Z`, encoded `2026-09-30T00:00:00.000000Z` |
| `valid_until` | `2026-10-30T12:30:45.123456789Z`, encoded `2026-10-30T12:30:45.123456Z` |
| `targets` | `github.com/Mindburn-Labs/example`, `github.com/Mindburn-Labs/other` |
| `condition` | `input.args.head.startsWith("helm/")` |
| `approval_required` | `github.branch.create_from_changes` |
| `risk_classes` | `github.repository.get`: `low`, `github.branch.create_from_changes`: `medium` |
| `limits` | `usd_cents` sum month span 1 value 50000; `count` count day span 1 value 20 |
| **activation digest** | `fe6393c4a564545f1e6b835f0e06eddc7d555120272158e578f8ca6a1908c527` |

The test checks the Go reference and an independent Python implementation,
`sdk/go/gen/helm/gateway/v1/testdata/activation_digest.py`, which it runs. It
also checks that reordering effect types, targets and limits, and the
nanoseconds below a microsecond, leave the digest unchanged, and that the
holder, the requester and a limit value change it.

## Delegation, revocation and limits

- **Delegation only narrows.** The child's terms and limits are within every
  mandate above it: a subset of effect types and targets, a per-call limit and
  approval threshold no higher, a window inside the parent's, every
  approval requirement and risk class kept, and a limit of a given shape no
  higher than any ancestor's. A widening is `failed_precondition`,
  `DELEGATION_SCOPE_VIOLATION`, naming the term. Only the parent's holder
  delegates it (`delegator_id`; anyone else is `permission_denied`), every
  mandate in the chain must be active, and no active stop may cover the tenant,
  the delegator or the chain (`EMERGENCY_STOP_FENCED`).
- **Revocation** is final and cascades at admission, which checks every link.
  Revoking a revoked mandate answers with it, unchanged.
- **Limits** are keyed by mandate (or the tenant, when `mandate_id` is empty),
  unit, measure, window and span. `SetLimit` adds one, or lowers the one of that
  shape; the same value changes nothing. A higher value, or one above an
  ancestor's, is `DELEGATION_SCOPE_VIOLATION`. Amounts are integers: money is
  minor units.

## Errors

Each error carries one `helm.errors.v1.ErrorDetail`, as in the effect API.

| Connect code | Reason code | When |
|---|---|---|
| `unauthenticated` | none | no token, or one that does not verify |
| `permission_denied` | `INSUFFICIENT_PRIVILEGE` | another scope; the provisioner is a human; an approval token that is missing, invalid, spent, of another tenant, or bound to other terms; a delegator that is not the parent's holder |
| `permission_denied` | `TENANT_ISOLATION` | the tenant has no control row yet |
| `permission_denied` | `APPROVER_NOT_DISTINCT` | the approver is the requester or the holder |
| `permission_denied` | `APPROVAL_REQUIRED` | a new activation without an approval token |
| `invalid_argument` | `SCHEMA_VIOLATION` | a malformed request; a condition that does not compile |
| `not_found` | none | a principal, mandate or limit the tenant does not have, or another tenant's |
| `already_exists` | `IDEMPOTENCY_CONFLICT` | the key was used with another request |
| `already_exists` | `IDENTITY_ISOLATION_VIOLATION` | a kind change, or a second principal for one external subject |
| `failed_precondition` | `DELEGATION_SCOPE_VIOLATION` | a widening: a limit raised, a risk class lowered, a child wider than its parent |
| `failed_precondition` | `PRINCIPAL_INACTIVE`, `MANDATE_INACTIVE` | a disabled principal, a revoked mandate |
| `failed_precondition` | `EMERGENCY_STOP_FENCED` | delegation under an active stop |
| `unavailable`, `aborted` | none, `retryable` | transient; retry with the same request |

## Bootstrapping a tenant

The order the Control Plane follows for a new company:

1. `UpsertTenant`.
2. `UpsertPrincipal` for the owner and every other human (kind `human`, with the
   Control Plane's user id as the external subject), for each agent seat (kind
   `agent`), and for the Control Plane's workload principals (kind `service`).
3. `RegisterEffectTypes` with the tenant's effect types and their risk classes,
   including `helm.authority.lift` where operators may lift stops.
4. `ActivateRootMandate` for each holder, with the approval of a human who is
   neither the requester nor the holder, and the mandate's limits.
5. `DelegateMandate` down the organization, `SetLimit` and `RevokeMandate` as it
   changes, and `DeactivatePrincipal` when a seat is retired.

## Not in this contract

- **Reads.** Every response carries what the write produced. There is no
  `ListMandates` or `GetPrincipal`; a replay of a key answers with the current
  state of what it named.
- **In-place narrowing of a mandate's terms** (`authorityrows.Store.Narrow`).
  Revoke and delegate narrower instead.
- **The `helm.authority.*` effects** of contract 5, which will carry widenings
  such as raising a limit or re-enabling a principal through the approval
  path of the effect API.
- **Step-up** for the approval of a root mandate. It is a decide token of a
  human principal; the passkey slice of the effect API adds the assertion.
