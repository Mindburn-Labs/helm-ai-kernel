# Authority rows (HELM-750 s2a, s2b)

Status: the effect gateway's admission transaction (`helm-gateway`, HELM-751
s2; `docs/architecture/gateway-effect-api.md`) reads these rows. Nothing in
`helm-ai-kernel` reads them: the Guardian's decision, the scoped
emergency-stop fence (`docs/EMERGENCY_STOP_FENCE.md`) and the freeze
controller are unchanged. No shipped binary writes them yet; the store below
is a library until the authority-change effects (`helm.authority.*`,
contract 5) dispatch through the gateway.

## What exists

- **Schema:** `core/pkg/kernel/authority/mandates/schema.sql`, applied by
  `helm-ai-kernel migrate` as the "authority rows" step and by
  `helm-gateway migrate` in its first version. It creates
  six tables: `authority_tenants`, `authority_principals`,
  `authority_effect_types`, `authority_mandates`, `authority_limits` and
  `authority_stops`. Each has `tenant_id` and forced row security under the
  kernel tenant policy (`app.current_tenant`). The startup check
  `TenantTablesWithoutForcedRowSecurity` in `ValidateRuntime` therefore covers
  them.
- **Read model:** `core/pkg/kernel/authority/mandates`: the schema, a
  mandate's terms and the narrowing rule between them (`Terms.Within`),
  mandate conditions, and the delegation chain read under `FOR SHARE`
  (`ChainInTx`). The gateway imports only this package.
- **Store:** `core/pkg/kernel/authority/authorityrows`. It is a typed store for
  tenants, principals, effect types, mandates, delegation, revocation,
  narrowing, limits and stops. Every call runs in one READ COMMITTED
  transaction bound to its tenant. It is a declared library root in
  `scripts/ci/dead-packages-allowlist.txt` until an authority-change effect
  calls it (CTL-046).

## Rules the store enforces

- **Delegation only narrows.** A child mandate must be within every mandate
  above it:
  - its effect types are a subset;
  - its per-call limit and approval threshold are present wherever an
    ancestor sets one, and no higher;
  - its validity window lies inside each ancestor's;
  - under an ancestor's target list it carries a subset of that list;
  - it never lowers an ancestor's risk class for an effect type, and keeps
    every approval requirement an ancestor sets on its effect types.

  Conditions are not compared: admission requires every link's condition to
  hold, so a child's condition only narrows. Narrowing a mandate in place may
  add a condition but never replace one. Only the parent's holder may delegate, and every link in the chain must be
  active.
- **A stop cannot be bypassed by delegating.** Delegation is refused while an
  active stop covers the tenant, the delegator, or any mandate in the chain.
  Delegation takes the tenant row, the principals and the chain root to leaf
  `FOR SHARE`, in the ADR-0001 order, and reads stops after those locks. A
  narrowing or stop that has not committed yet therefore makes it wait, and it
  then sees the change.
- **Narrowing bumps the control row.** Stop, revoke, narrow, add a limit and
  lower a limit each `UPDATE` their scope's control row (tenant, principal,
  mandate, effect type or limit) and bump its `version`, in the same
  transaction as the detail row (ADR-0001 §5.1). A refused transition changes
  nothing.
- **Widening needs an approval.** Activating a root mandate and lifting a
  stop take a `WideningApproval`. It names a requester and an active, human
  approver. The approver cannot be the requester, or the principal whose
  authority widens: the new mandate's holder, or the stopped principal or
  mandate holder. The schema also requires this: a root mandate carries
  `approved_by`, which differs from `created_by` and `holder_id`, and a lifted
  stop carries `lift_requested_by` and `lift_approved_by`, with the two
  distinct. HELM-751 replaces the argument
  with the approval record written by the gateway's Approve path.
- **Stops expire and lift.** A stop is active until `expires_at` or until it
  is lifted. `ActiveStops` takes the time as an input, and it ignores
  `created_at` on purpose: a stop that committed while admission waited for a
  lock must still be seen.
- **Amounts are integer minor units.** Negative amounts are refused. A
  version overflow is a database error, not a wrap-around.

## Mandate terms added in s2b

- **`targets`:** the allowlisted targets, as exact strings. NULL allows any
  target.
- **`condition`:** a CEL condition over the effect, with `input.args` (the
  parsed argument object), `input.target` and `input.effect_type`. It runs in
  the kernel's CEL environment with its cost limit (`authority.Compile`). A
  condition that does not compile is refused when the mandate is activated,
  delegated or narrowed. The walking skeleton's mandate uses
  `input.args.head.startsWith("helm/")`.
- **`risk_classes`:** a risk class per effect type that raises the effect type
  row's class for this mandate. High or irreversible escalates to approval.
- **`approval_required`:** the effect types for which every call under this
  mandate needs approval, whatever their risk class. A medium effect can
  require approval this way (ADR-0001 §4); the skeleton's
  `github.pull_request.create_draft` does. A child keeps every ancestor's
  entries for the effect types it covers.

At admission (HELM-751 s2) every link of the chain must allow the effect type
and the target and satisfy its condition. The chain is re-checked for
narrowing, and a link wider than its parent is denied with
`DELEGATION_SCOPE_VIOLATION`. A stop on any holder or delegator of the chain,
on any of its mandates, on the tenant or on the effect type denies with
`EMERGENCY_STOP_FENCED`.

## Differences from the ADR-0001 reference schema

- The tables live in the kernel schema with an `authority_` prefix, not in an
  `authority` schema. The kernel's migration, catalog check and tests are
  scoped to `current_schema()`.
- `tenant_id` and `principal_id` are the kernel's text ids, and row security
  uses `app.current_tenant`, which S5 kept. Mandate, limit and stop ids are
  UUIDv7.
- Added columns:
  - `approval_threshold`, the typed approval rule on a mandate;
  - `created_by` and `approved_by` on mandates;
  - `issued_by`, `lift_requested_by` and `lift_approved_by` on stops;
  - `targets`, `condition`, `risk_classes` and `approval_required` on
    mandates (s2b).
- Counters, attempts, permits and the exposure ledger are the gateway's
  schema (`core/pkg/gateway/admission/schema`), not this one.

## Verification

```sh
HELM_TEST_POSTGRES_URL=postgres://... bash scripts/ci/postgres_proofs.sh
cd core && go test ./pkg/kernel/authority/... ./pkg/postgresmigration
```

The Postgres proofs are listed in `scripts/ci/postgres-proofs.txt`. They cover:

- narrowing-only delegation over random chains;
- a delegation that waits for a concurrent narrowing;
- delegation refused under a tenant, delegator or chain stop, including a stop
  that is still committing;
- root-mandate activation refused without a proper approver;
- stop expiry and approved lift;
- a version bump on every narrowing;
- tenant isolation under a restricted role;
- the catalog check over the new tables, including `ValidateRuntime` under a
  serving role;
- the s2b terms surviving the database, refused widenings of targets and risk
  classes, a condition that does not compile, and a replaced condition.
