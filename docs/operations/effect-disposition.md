---
title: Signed Active-Work Disposition
status: internal-foundation
last_reviewed: 2026-07-18
---

# Signed active-work disposition

The Kernel can durably accept a Control Plane instruction about connector work
that is already `STARTED` or `UNCERTAIN`. Every command is bound to one active
tenant/workspace FENCE, one exact reservation head, and one position in an
append-only disposition chain. The Kernel returns a separately signed receipt.

This is source-owned contract, persistence, and real-PostgreSQL evidence. It is
internal and pre-production. There is no deployed Control Plane outbox,
authenticated Data Plane retrieval route, connector disposition adapter, or
controlled-live cancellation, compensation, or reconciliation proof.

## No execution authority

The allowed actions are:

- `HOLD` — keep automatic retry and terminal inference quarantined;
- `RECONCILE_SOURCE` — request a source-system observation using the original
  execution and idempotency identities;
- `REQUEST_CANCEL` — record operator intent to request cancellation; and
- `REQUEST_COMPENSATE` — record operator intent to request a compensating
  operation.

Acceptance is not permission to perform any of those external effects. Every
`effect-disposition-receipt.v1` contains `execution_authority: NONE`. A Data
Plane that cancels or compensates still needs a separate, current, governed
effect authority and source-specific connector path. Neither the command nor
its receipt may be presented as an EffectPermit.

## Exact authority binding

The Control Plane signs `effect-disposition-command.v1` under a
deployment-pinned authority ID, key ref, audience, and key lifetime. The
command binds:

- tenant, workspace, and workload audience;
- the exact current FENCE command ID/hash, epoch, and Kernel receipt hash;
- admission ID and exact active reservation sequence/head/state;
- connector ID/version/action and the original execution, proof-session,
  intent, effect, idempotency, and effect-hash identities;
- action, disposition ref, actor, and reason;
- monotonic disposition sequence and predecessor receipt hash; and
- issue/expiry timestamps with a maximum ten-minute lifetime.

The first disposition has sequence 1 and no predecessor. Every successor must
name the immediately preceding Kernel receipt hash. A new FENCE epoch makes an
old command stale even if the reservation did not change.

## Transaction behavior

`EffectDispositionService.Record` verifies the Control Plane signature before
opening the storage transaction. The PostgreSQL operation then:

1. establishes authenticated tenant/workspace RLS context;
2. acquires the shared tenant/workspace FENCE lock;
3. returns an exact committed command replay, or rejects changed content;
4. checks command liveness against the PostgreSQL clock;
5. requires the command's exact FENCE to be the current active FENCE;
6. loads and cryptographically verifies the exact current reservation and its
   historical signed authorities;
7. requires `STARTED` or `UNCERTAIN` and exact reservation bindings;
8. loads and cryptographically re-verifies every existing chain record, then
   requires the next sequence and predecessor hash;
9. emits a self-hashed Kernel receipt with `execution_authority: NONE`, signs
   it under the deployment-pinned Kernel trust root, and appends the immutable
   record; and
10. commits the command, FENCE snapshot, receipt, and signature atomically.

Concurrent commands for the same next chain position have one winner. The
loser conflicts unless it is an exact replay of the committed command.
`Recover` and `ListForEffect` re-verify Control Plane and Kernel signatures,
FENCE receipt integrity, reservation authority, and chain continuity. These
read paths create no execution authority.

## Signed close binding

Once any disposition exists for an effect, terminal close must acknowledge the
latest one. The connector acknowledgement and Kernel close receipt both carry
the exact latest `disposition_receipt_hash`; their `reconciliation_ref` must
equal that command's `disposition_ref`. A missing, stale, or substituted hash
fails closed.

While the scope is fenced, close requires a disposition bound to the exact
current FENCE. Rotating the FENCE invalidates the earlier disposition for close
until a fresh successor is recorded. `HOLD` explicitly blocks terminal close;
another signed current-FENCE successor must request reconciliation, cancel, or
compensation before verified source evidence can close the reservation.

This binding proves which operator instruction the source observation answers.
It does not prove the connector actually performed a cancel or compensation;
the acknowledgement outcome and sealed EvidencePack must describe the real
source observation explicitly.

## Persistence invariants

Migration `004_effect_dispositions.sql` adds forced-RLS, append-only
`approval_effect_dispositions`. Database triggers enforce scope, JSON/shadow
parity, immutable rows, active reservation binding, active exact FENCE binding,
and monotonic chain order. The application layer additionally verifies both
signatures and all historical authorities during record, recovery, and list.

Runtime roles need only `SELECT, INSERT`. Production must use a dedicated
least-privilege writer without DDL, superuser, or `BYPASSRLS`. Signing inside a
database transaction also requires bounded KMS/HSM latency and explicit
failure telemetry before deployment.

## Portable and database verification

The source-owned `reference_packs/effect-disposition-v1` pack contains canonical
command, envelope, signing payload, receipt, receipt signing payload, and
negative mutations. Go and independent Python implementations verify hashes,
signature domains, pinned identities and lifetimes, exact cross-artifact
bindings, chain semantics, and the `NONE` authority invariant.

Run:

```bash
make verify-effect-disposition-vectors
make verify-effect-close-vectors
HELM_TEST_POSTGRES_URL='postgres://...' make test-effect-reservation-postgres
make docs-coverage
make docs-truth
```

The PostgreSQL proof covers no-FENCE rejection, chained dispositions, exact and
conflicting replay, recovery, listing, concurrent single-winner insertion,
stale-FENCE rejection, expiry, forced-RLS isolation, append-only rejection, and
mandatory current-FENCE non-`HOLD` disposition binding at close. Direct
wrong-scope insert and delete attempts are rejected. These are local and CI
proofs, including rejection of a structurally valid but cryptographically
forged row at both successor append and close. They are not deployed or
controlled-live evidence.

## Remaining production gates

- implement the Control Plane's durable signed-command ledger, leased outbox,
  retry/reconciliation state, and pinned Kernel receipt verification;
- expose workload-authenticated Data Plane record/recover/list boundaries with
  least-privilege credentials and replay-safe worker semantics;
- implement certified connector adapters for source reconciliation and keep
  cancel/compensate behind separate current governed effect authority;
- bind real connector acknowledgements and sealed EvidencePacks to disposition
  results and surface unresolved active work in the operator Console;
- deploy and rotate Control Plane and Kernel keys through source-owned KMS/HSM
  configuration, including historical verification retention;
- prove crash recovery, KMS latency/failure behavior, load, failover,
  backup/restore, and controlled-live source outcomes; and
- pass source-owned release gates before any production, Emergency Stop, or GA
  claim.
