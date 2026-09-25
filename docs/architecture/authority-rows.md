# Authority rows (HELM-750 s2a)

Status: schema and library store only. Nothing on the request path reads
these rows yet. The Guardian's decision, the scoped emergency-stop fence
(`docs/EMERGENCY_STOP_FENCE.md`) and the freeze controller are unchanged. The
admission transaction (HELM-751, HELM-750 s2b) is the first runtime caller.

## What exists

- **Schema:** `core/pkg/postgresmigration/migrations/001_authority_rows.sql`,
  applied by `helm-ai-kernel migrate` as the "authority rows" step. It creates
  six tables: `authority_tenants`, `authority_principals`,
  `authority_effect_types`, `authority_mandates`, `authority_limits` and
  `authority_stops`. Each has `tenant_id` and forced row security under the
  kernel tenant policy (`app.current_tenant`). The startup check
  `TenantTablesWithoutForcedRowSecurity` in `ValidateRuntime` therefore covers
  them.
- **Store:** `core/pkg/kernel/authority/authorityrows`. It is a typed store for
  tenants, principals, effect types, mandates, delegation, revocation,
  narrowing, limits and stops. Every call runs in one READ COMMITTED
  transaction bound to its tenant. It is a declared library root in
  `scripts/ci/dead-packages-allowlist.txt` until the admission transaction
  imports it.

## Rules the store enforces

- **Delegation only narrows.** A child mandate must be within every mandate
  above it:
  - its effect types are a subset;
  - its per-call limit and approval threshold are present wherever an
    ancestor sets one, and no higher;
  - its validity window lies inside each ancestor's.

  Only the parent's holder may delegate, and every link in the chain must be
  active. The chain is read under `FOR SHARE`, root to leaf, so a narrowing
  that has not committed yet makes the delegation wait for it.
- **Narrowing bumps the control row.** Stop, revoke, narrow, add a limit and
  lower a limit each `UPDATE` their scope's control row (tenant, principal,
  mandate, effect type or limit) and bump its `version`, in the same
  transaction as the detail row (ADR-0001 §5.1). A refused transition changes
  nothing.
- **Widening needs an approval.** Activating a root mandate and lifting a
  stop take a `WideningApproval`. It names a requester and a distinct, active,
  human approver. The schema also requires this: a root mandate carries
  `approved_by`, and a lifted stop carries `lift_requested_by` and
  `lift_approved_by`, with the two distinct. HELM-751 replaces the argument
  with the approval record written by the gateway's Approve path.
- **Stops expire and lift.** A stop is active until `expires_at` or until it
  is lifted. `ActiveStops` takes the time as an input, and it ignores
  `created_at` on purpose: a stop that committed while admission waited for a
  lock must still be seen.
- **Amounts are integer minor units.** Negative amounts are refused. A
  version overflow is a database error, not a wrap-around.

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
  - `issued_by`, `lift_requested_by` and `lift_approved_by` on stops.
- Counters, attempts, approvals, permits and the exposure ledger arrive with
  the admission transaction (HELM-751).

## Verification

```sh
HELM_TEST_POSTGRES_URL=postgres://... bash scripts/ci/postgres_proofs.sh
cd core && go test ./pkg/kernel/authority/authorityrows ./pkg/postgresmigration
```

The Postgres proofs are listed in `scripts/ci/postgres-proofs.txt`. They cover:

- narrowing-only delegation over random chains;
- a delegation that waits for a concurrent narrowing;
- stop expiry and approved lift;
- a version bump on every narrowing;
- tenant isolation under a restricted role;
- the catalog check over the new tables, including `ValidateRuntime` under a
  serving role.
