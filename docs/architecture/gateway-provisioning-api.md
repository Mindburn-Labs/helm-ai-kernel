# Gateway authority provisioning (contract 5)

<!-- quantum_posture: this note describes a wire contract that carries SHA-256
digests as opaque values and no signatures or keys. It adds no cryptographic
control and makes no post-quantum claim; token verification is ADR-0005's. -->

Status: served, 2026-09-30. `helm-gateway serve` dispatches
`helm.authority.provision.v1` and `helm.authority.narrow.v1` through the
authority adapter and mounts the three RPCs of `AuthorityAdminService` on its
API listener, beside `EffectGatewayService`. Approving a provision plan needs
a step-up proof, which the approval path takes in its own change: until then
`Approve` of a provision plan fails closed with `STEP_UP_REQUIRED`, and only a
narrowing plan, which needs no approval, applies end to end.

- Effect argument schemas:
  [`protocols/json-schemas/effects/authority/provision.v1.json`](../../protocols/json-schemas/effects/authority/provision.v1.json)
  and [`narrow.v1.json`](../../protocols/json-schemas/effects/authority/narrow.v1.json),
  with valid and invalid examples beside them.
- IDL: [`protocols/proto/helm/gateway/v1/authority_admin.proto`](../../protocols/proto/helm/gateway/v1/authority_admin.proto),
  package `helm.gateway.v1`, service `AuthorityAdminService`; Go bindings in
  `sdk/go/gen/helm/gateway/v1`.
- Contract tests: `sdk/go/gen/helm/gateway/v1/authority_admin_contract_test.go`.
- Related: [Gateway effect API](gateway-effect-api.md) (Propose, Approve,
  Dispatch and Observe, which carry these effects) and
  [Authority rows](authority-rows.md) (the tables a plan writes).

## What it is for

Admission (`EffectGatewayService.Propose`) reads a tenant's authority rows:
principals, effect types, mandates and limits. Until now nothing shipped wrote
them, so a tenant on a real gateway could not exist. Authority is written the
way every other consequential change is: as an effect that passes admission, a
distinct human's approval, a single-use dispatch claim and a read-back. There is
no second, administrative path that widens authority.

- **`helm.authority.provision.v1`** applies one organization's whole authority
  plan: its effect types, its principals, its mandates (a tree, delegated from
  the organization's root mandate) and their limits. It widens authority, so it
  is `ESCALATED` and needs a distinct human's approval with step-up.
- **`helm.authority.narrow.v1`** applies a plan that only narrows the one
  applied: it revokes nodes, narrows terms, adds or lowers limits and disables
  the organization's own agents and services. It needs no approval and is
  `ADMITTED` at once, but only from the organization's provisioner, the service
  principal that requested the plan applied now.
- **`AuthorityAdminService`** does what an effect cannot do for itself:
  `EnsurePrincipals` registers the first principals, so that an effect has a
  requester and an approver; `GetProvisioning` reads what a plan applied;
  `ListEffectTypes` is the catalog of effect types with their argument schemas.

## The path of a plan

| Step | Who | What the gateway does |
|---|---|---|
| 0 | the Control Plane (`helm.gateway.provision`) | `EnsurePrincipals`: the tenant, the organization's service principal and the owner (a human) exist. Once per tenant. |
| 1 | the organization's service principal, carried by the Control Plane (`helm.gateway.propose`) | `Propose` with `effect_type` `helm.authority.provision.v1`, `target` the `org_ref`, `arguments` the plan. It is `ESCALATED` and shows the plan to the approver through `GetAttemptContent`. |
| 2 | a distinct human (`helm.gateway.decide`) | `Approve` with the approval digest and a step-up proof. The approver is an active human principal of the tenant, not the requester. Approval re-admits the attempt: `ADMITTED`, with a permit. |
| 3 | the requester's workload (`helm.gateway.execute`) | `Dispatch` claims the permit once and calls the authority adapter, which applies the plan in one transaction. |
| 4 | the same workload | `Observe` reads the applied plan back: `OBSERVED(SUCCEEDED)` when the organization's applied digest is this plan's. |

`helm.authority.narrow.v1` skips step 2, and its step 1 is the provisioner's
alone (below). Nothing else differs.

Admission treats these two effect types differently from every other, in three
ways, because they are how authority begins:

1. **No proposer mandate.** A mandate is what a plan creates; the first plan
   cannot need one. Authority for a provision attempt is the approver's
   approval of the exact plan bytes, which the approval digest binds (attempt
   id, target, argument digest, expiry).
2. **The requester is a registered service principal.** A human, an agent or an
   unregistered principal proposing either effect is `DENIED`
   (`INSUFFICIENT_PRIVILEGE`). A stop on the requester or the tenant still
   denies (`EMERGENCY_STOP_FENCED`), except that a tenant-wide stop does not
   block `narrow` (rule 4).
3. **No effect-type row and no limit.** They spend nothing and are the
   gateway's own (`grantable` is false in the catalog). A mandate never grants
   them: a plan whose terms name a `helm.authority.*` effect type, or whose
   `effect_types` list one, is refused.
4. **The organization's provisioner.** The service principal that requested the
   plan applied now is the organization's *provisioner*, and
   `GetProvisioning` says who it is. A `narrow` plan is accepted only from it:
   any other requester is `permission_denied` (`INSUFFICIENT_PRIVILEGE`) at
   Propose and no attempt is made, because an unapproved change must not be
   open to every service principal of the tenant. A `provision` plan may come
   from another service principal (a distinct human approves it), and that
   principal is the provisioner from then on. `narrow` reduces authority, which
   is what an operator needs in an incident, so a tenant-wide stop does not
   block it; a stop on the requester or on the workload that dispatches it
   does. (A plan effect has no effect-type row, so none is stopped by effect
   type.)

Every other rule of the effect API holds: idempotency key and request digest
(R6), approver != requester, the single-use decide token, the approval digest,
the escalation window, the dispatch claim's authority-version check, stops, the
UNKNOWN reconciliation. A permit's authority versions include the tenant and
the requester's rows, so a stop or a change to them between approval and
dispatch cancels the attempt.

## The plan

One JSON object, closed by its schema, at most 524288 bytes, with no duplicate
key at any depth. The fields:

| Field | Meaning |
|---|---|
| `schema` | `helm.authority.provision.v1` or `helm.authority.narrow.v1`, matching the effect type. |
| `org_ref` | `org:<id>`. The effect's target, and the key of the provisioning the plan updates. |
| `version_ref`, `stage` | Recorded and returned by `GetProvisioning`; never interpreted. |
| `base_plan_digest` | The applied plan's digest, or empty when the organization has none. |
| `valid_from`, `valid_until` | The validity window of every mandate of the plan. It is part of a mandate's terms: an earlier `valid_from` or a later `valid_until` widens. |
| `effect_types` | `{effect_type, risk_class}`: registered in the tenant. |
| `principals` | `{id, kind, ensure_only?, external_subject?}`: registered if missing. |
| `disable_principals` | Principals to disable: only ones the applied plan lists, never the requester, and in a `narrow` plan never a human. |
| `mandates` | `{node, holder, parent, terms}`: one mandate per node. `terms` has `effect_types`, `targets` (null: any), and optionally `approval_required`, `approval_threshold`, `per_call_limit`, `condition` (CEL) and `risk_classes`. |
| `limits` | `{node, unit, measure, window, value, span?}`: a limit of a node's mandate. |

Rules the schema cannot state, which the gateway refuses a plan for (the effect
is `invalid_argument` at Propose, or `FAILED` at Dispatch, and nothing applies):

- principals and nodes are listed once each; exactly one mandate has a null
  parent, its node is the `org_ref`, every other parent is a node of the plan and
  the parents form a tree;
- every holder is a principal of the plan or one already registered and active;
- every effect type a mandate names is listed in `effect_types`, and every
  child's terms are within its parent's, and its limits no higher than the same
  limit above it;
- every limit names a node of the plan, and a node has at most one limit of a
  given unit, measure, window and span;
- no principal is both listed and disabled, and no holder of a plan mandate is
  disabled;
- `valid_until` is after `valid_from`; a condition compiles; no terms name, and
  no `effect_types` entry lists, a `helm.authority.*` effect type; a human
  principal the plan may create carries an `external_subject`, and one that must
  already be registered is `ensure_only`; `approval_required` and
  `risk_classes` name only effect types of their mandate's terms;
- the effect's target equals `org_ref`;
- amounts, limit values and spans are written as plain integer literals of at
  most 2^53-1: no fraction, exponent or sign, even where the value is whole,
  because the digest prints numbers as they are written.

Rules that read the organization's applied plan, which Propose checks so that an
approver is never asked for a plan that cannot apply (`failed_precondition`,
`PRECONDITION_FAILED`, no attempt):

- `disable_principals` lists only principals the applied plan lists, never the
  requester, and in a `narrow` plan no human;
- a `narrow` plan has an applied plan to narrow, and lists only nodes it has.

### The digest and compare-and-set

The **plan digest** is the lower-case hex SHA-256 of the RFC 8785 (JCS) form of
the arguments without `base_plan_digest`. The gateway computes it and never
trusts one it is given. Vectors, checked by `TestPlanDigestVector` against a Go
reference and an independent Python one, and by the gateway's own test against
its implementation:

| Plan (under `protocols/json-schemas/effects/authority/examples/`) | Plan digest |
|---|---|
| `provision.v1.valid.json` | `70d6c47ca51186780504038bdadb939319455ee16c14f59d4829fd1a8bdee5af` |
| `provision.v1.valid-escapes.json` | `81bbed39150fdb7cc7988f955bcdb6be75b150b07b8ca8cd0fe425ffb386b4ef` |

The second plan is what a naive encoder gets wrong. JCS escapes only the quote,
the backslash and the control characters: `&&`, `<` and `>` in a condition (which
`encoding/json` writes as `\u0026` and `\u003c`), non-ASCII text, a character
beyond the Basic Multilingual Plane and U+2028 stay as they are. The test shows
that `encoding/json`'s form of this plan gives another digest.

An organization has at most one applied plan. Applying a plan is a
compare-and-set: it applies only if its `base_plan_digest` is the applied
plan's digest, or empty when there is none; otherwise the effect fails with
`PRECONDITION_FAILED` and nothing changes. `Propose` makes the same check, so a
stale base is refused before an approver is asked (`failed_precondition`, no
attempt). Applying a plan whose digest is already the applied one changes
nothing and succeeds, whatever its base: a lost response is safe to retry.

### What applying does

Everything below runs in one transaction bound to the token's tenant under
forced row security: a plan applies whole or not at all. Principals and effect
types first, then the mandates from the root down, then limits, then
`disable_principals`.

- **Principals.** A principal that is missing is created, active. One that
  exists must be the same kind (`ensure_only` or not), and a disabled one is
  refused: nothing is re-enabled or re-typed. `disable_principals` disables
  (narrows: the principal row's version is bumped). A plan can only disable
  what the organization's own applied plan lists, so one organization's plan
  does not reach another's principals.
- **Effect types.** Registered with the plan's class. A class is only ever
  raised, which narrows and bumps the row's version: a plan that names a lower
  class than the registered one leaves it. An effect type's class is a fact of
  the tenant, shared by its organizations, so `narrow`, which registers nothing
  and raises nothing, refuses a plan whose class is higher than the registered
  one, or that lists an effect type not yet registered.
- **Mandates.** A node the applied plan has, unchanged (same holder, parent,
  terms and limits), **keeps its mandate id**. A node whose change only narrows
  (terms within the old, a condition kept or added, limits added or lowered) is
  **narrowed in place**: the mandate keeps its id and its version is bumped. Any
  other change (a wider term, a limit raised or dropped, another holder or
  parent) **revokes and re-creates** the node's mandate, and every mandate below
  it in the plan, because a limit only ever lowers and a child follows its
  parent's id. A node the plan no longer has is revoked. A new node is created:
  the root by the store's `CreateMandate`, with the requester as `created_by`
  and the human who approved the attempt as `approved_by`, so the schema's
  constraint that a root's approver is neither its requester nor its holder
  holds; the others by delegation from the parent's holder, which only narrows
  and is refused under an active stop on the tenant, the delegator or the chain.
  **A stop is not ended by re-creating**: a mandate that is under an active
  mandate stop is never revoked and re-created; the plan fails with
  `EMERGENCY_STOP_FENCED` until the stop is lifted. **Spending is not reset by
  re-creating**: a limit of a re-created mandate starts from the used amount and
  the distinct values of the limit it replaces, for every window bucket that
  exists, so a widening does not open a second budget. (An amount confirmed on
  the old limit after the plan applied is not carried.)
- **Limits.** Added with the mandate, or added or lowered on one that stays.
- **Record.** The organization's row in `authority_provisions` (digest,
  `version_ref`, `stage`, the node to mandate map, the applying attempt, a
  revision counter) is written by a compare-and-set on the base digest.

`helm.authority.narrow.v1` runs the same algorithm with widening forbidden: a
node that is not in the applied plan, a change that would revoke and re-create,
an effect type registered or raised, a principal that is not registered, or a
stale base fails the whole plan (`PRECONDITION_FAILED` or
`DELEGATION_SCOPE_VIOLATION` in the outcome, nothing applied). It can revoke
nodes, disable the organization's own non-human principals, lower or add limits
and narrow terms.

The read-back finds a plan by its digest in the organization's current
provisioning: `OBSERVED(SUCCEEDED)` when the applied digest is the plan's. A
plan applied and then superseded before its read-back ran reads as not applied
(`FAILED`, by absence, after the dispatch fence); `GetProvisioning` is the
authority on what is applied.

A dispatch that fails before it writes is `NOT_SENT`: the outcome is a certain
`FAILED` with its reason and the reservation is released. A database error
around the commit is `INDEFINITE`: the attempt is `UNKNOWN`, and `Observe` finds
the plan applied or not by its digest; it is never dispatched twice.

## The RPCs

`AuthorityAdminService` (Connect, on the gateway's listener):

| RPC | Scope | What it does |
|---|---|---|
| `EnsurePrincipals` | `helm.gateway.provision` | Creates the tenant's control row if it has none, and each listed principal that is not registered. Changes nothing that exists. Idempotent by nature, so it has no idempotency key. |
| `GetProvisioning` | `helm.gateway.read` | The applied plan of an organization: digest, `version_ref`, `stage`, `revision`, the applying attempt, the provisioner, and each node with its mandate id, holder, parent, current status and version. `not_found` when it has none. |
| `ListEffectTypes` | `helm.gateway.read` | The catalog: each effect type the gateway's adapters declare, with its risk class, declaration, target form, JSON Schema of its arguments and whether a mandate may grant it. The same for every tenant, ordered by effect type. It lists what this process performs: an adapter a deployment composes in (for example the model gateway's) is listed with the declaration it carries. `helm.authority.lift` is proposed through `Lift` and is not listed. |

The tenant comes only from the token. No request names a tenant or a workspace.

### One registry: the mapping to the kernel's

`helm-gateway` reads `authority_principals` and nothing else. The kernel's
`principal_bindings` table (ADR-0005 §3, written by
`POST /api/v1/admin/principal-bindings`) is the legacy runtime's registry of
which principals belong to which tenant; the gateway never reads or writes it.
They meet on one identifier only:

| Where | Field | Value |
|---|---|---|
| Token | `sub` | the Control Plane principal id |
| Gateway | `authority_principals.principal_id` | the same string, per tenant |
| Kernel | `principal_bindings.principal_id` | the same string, per tenant |
| Gateway | `authority_principals.kind` | `human`, `agent` or `service`: the gateway's own fact, never taken from a token claim |
| Gateway | `external_system`, `external_subject` | who vouches for the principal, e.g. `helm-control-plane` and the Control Plane's user id |

- Enrolment calls `EnsurePrincipals` for the gateway, and keeps binding the same
  id in the kernel while a legacy route still needs it. When the legacy routes
  are retired (ADR-0005 phase 4) only the gateway call remains.
- A **kind never changes**, a **disabled principal is never re-enabled**, and an
  external subject, once set, is never changed: each is an error
  (`IDENTITY_ISOLATION_VIOLATION`, `PRINCIPAL_INACTIVE`).
- **A human carries an external subject, and one subject names one principal per
  tenant.** Approver != requester (ADR-0001 I6) is checked on principal ids, so
  a person registered twice would count as two people. A unique index on
  `(tenant_id, external_system, external_subject)` refuses the second
  registration. The same holds for a human a plan creates. A subject may be
  attached, once, to a principal that has none.
- The kernel's one-tenant rule for a principal (ADR-0005 §11) is not enforced by
  the gateway: the same id in two tenants is two rows.

### What registering a human establishes

Registering grants no authority: authority comes from mandates. It does make a
human **eligible to approve**, because the gateway takes an approver's kind from
these rows and never from a token. The Control Plane is trusted to register only
people, exactly once each: it calls `EnsurePrincipals`, and it mints the decide
tokens and the step-up proofs those people present. A compromised Control Plane
issuer could register a human it controls and approve with it. The external
subject rule stops a person from being two principals; it does not stop the
issuer from inventing a person. Closing that gap needs the gateway to verify the
approver's passkey itself, against a credential registry it holds (§10.1 of the
target architecture); the step-up proof of this contract is the issuer's
attestation of that check, and says so.

## Bootstrapping a tenant

1. `EnsurePrincipals`: the organization's service principal (kind `service`,
   the requester of every plan), the workload principal that dispatches, and the
   owner and other humans (kind `human`, each with the Control Plane's user id as
   external subject).
2. `Propose` `helm.authority.provision.v1` with `base_plan_digest` empty. The
   owner approves with step-up. The Control Plane dispatches and observes.
3. Later plans carry the applied digest as `base_plan_digest`. A plan that only
   narrows goes as `helm.authority.narrow.v1` and needs no approval.
4. `GetProvisioning` shows the applied digest and the mandate of each node; the
   Control Plane compares the digest with its plan's.

## Errors and reason codes

Effects report through the effect API: a `DENIED` attempt with its reason code, a
`FAILED` outcome with the reason of the adapter's refusal. The reasons a plan can
carry:

| Where | Reason | When |
|---|---|---|
| Propose (`invalid_argument`) | `SCHEMA_VIOLATION` | the arguments break their closed schema or one of the rules above |
| Propose (`permission_denied`) | `INSUFFICIENT_PRIVILEGE` | a `narrow` plan from a principal that is not the organization's provisioner |
| Propose (`failed_precondition`) | `PRECONDITION_FAILED` | `base_plan_digest` is not the applied plan's digest; a `narrow` plan with nothing applied; `disable_principals` names a principal the applied plan does not list, the requester, or in a `narrow` plan a human |
| Propose (`DENIED`) | `INSUFFICIENT_PRIVILEGE`, `PRINCIPAL_INACTIVE`, `EMERGENCY_STOP_FENCED` | the requester is not an active service principal; a stop covers it or the tenant |
| Approve | `APPROVER_NOT_DISTINCT`, `INSUFFICIENT_PRIVILEGE`, `STEP_UP_REQUIRED` | the effect API's rules for approval |
| Dispatch outcome (`FAILED`) | `PRECONDITION_FAILED` | the base moved after Propose; a holder is not registered; the plan does not fit the organization |
| Dispatch outcome (`FAILED`) | `PRINCIPAL_INACTIVE` | a holder or a listed principal is disabled |
| Dispatch outcome (`FAILED`) | `DELEGATION_SCOPE_VIOLATION` | a child mandate is wider than its parent, or a narrow plan would widen |
| Dispatch outcome (`FAILED`) | `EMERGENCY_STOP_FENCED` | delegation under an active stop; a plan that would re-create a mandate under an active mandate stop |
| Dispatch outcome (`FAILED`) | `IDENTITY_ISOLATION_VIOLATION` | a plan re-types a principal or gives a human's subject to another |

`AuthorityAdminService` errors carry the codes in the service comment of the
proto; an `EnsurePrincipals` conflict is `already_exists`
(`IDENTITY_ISOLATION_VIOLATION`).

## Limits and trust

- A plan is at most 524288 bytes: the effect API's argument cap is 64 KiB for
  every other effect. The transport's request cap grows with it.
- Authority effects are the only path that widens authority, and the only one
  that narrows it in bulk. `Stop` (an operator's single-use token) and `Lift`
  are unchanged, and `helm.authority.lift` remains the one way to end a stop.
- What the approval establishes: the approver approved the plan bytes whose
  digest the approval digest names, and presented a step-up proof for it. It does
  not establish that the approver's client rendered those bytes truthfully
  (§10.1 of the target architecture).
- Who may approve is the Control Plane's decision: any active human principal of
  the tenant other than the requester can decide any attempt (ApprovalRule
  approvers are gap K5), so "a distinct human" is distinct from the requester
  principal, not a proof that the approver is not the plan's author.
- A person is one principal only as far as the registrar says so: one external
  subject names one principal per `(system, id)`, and the system name is the
  registrar's. A human registered without a subject (a legacy row) is not
  deduplicated.
- The plan digest compares plans, not authority: two plans with the same effect
  have different digests if they differ in any byte after JCS.
