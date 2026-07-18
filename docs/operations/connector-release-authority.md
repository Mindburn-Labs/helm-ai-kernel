# Connector release authority contract

Status: source-owned contract, offline verifier, and durable PostgreSQL
projection; internal, pre-production.

`connector-release-authority.v1` is the Kernel-owned signed statement that an
exact connector release is certified or revoked. It closes the contract-level
confusion between mutable connector metadata, candidate certification evidence,
and release authority. It does not yet prove a deployed source-authority writer,
Data Plane admission integration, or a live connector effect.

## Authority boundary

`svc-helm-certification` may produce content-hashed candidate evidence. That
evidence has no merge, deployment, activation, or connector-execution authority.
A separate source-owned release review must verify the binary signature and the
certification artifact, then issue this contract under a deployment-pinned
release-authority key.

The signed statement binds:

- exact connector ID and version;
- global or explicit tenant/workspace scope;
- normalized binary, connector-signature, and certification hashes plus their
  references and signer/authority identities;
- executor kind, sandbox profile, and drift policy;
- a monotonic registry revision bounded to the JCS/JavaScript safe-integer
  range (and therefore a positive PostgreSQL `BIGINT`) plus predecessor hash;
- certified validity or a terminal revocation targeting the immediately prior
  authority hash;
- source authority ID, signing key reference, signing time, JCS self-hash, and
  detached Ed25519 signature.

References are discovery metadata; their `sha256:` hashes provide immutable
binding. A caller-provided `verified=true` boolean is never release authority.

## Current-state rule

A valid signature proves provenance of one historical statement only. Current
authority additionally requires a durable exact-version projection to prove
that no later revision exists. A later revocation makes the certified statement
historical even if its validity window has not expired. The near-effect boundary
must reload that current state immediately before every connector start,
including cached and recovered admissions.

The legacy `pkg/registry/connectors` in-memory ID-keyed store is non-authoritative
metadata and must not be migrated or backfilled into this contract. Existing
rows lack signed provenance, exact-version history, and anti-rollback revision
evidence.

## PostgreSQL authority projection

`core/pkg/registry/connectors/migrations/001_connector_release_authorities.sql`
is applied only by the migration owner. Runtime startup does not execute DDL.
Deployment provisioning must grant the source-authority writer `SELECT,
INSERT` and the runtime `SELECT`; it must grant neither role `UPDATE`, `DELETE`,
schema `CREATE`, database `TEMPORARY`, superuser, nor `BYPASSRLS`. Because
PostgreSQL grants database `TEMPORARY` to `PUBLIC` by default, deployment must
revoke that public grant (or prove an equivalent non-inherited denial) before
using either service role. The migration itself revokes table/function access
from `PUBLIC` but does not create roles or provision those deployment-specific
grants. A database trigger independently rejects mutation of existing history.

Every row is keyed by exact scope, connector ID, connector version, and
monotonic revision. The writer verifies the detached Ed25519 signature before
opening a transaction, obtains an exclusive advisory lock for that exact
release, verifies the stored head again, and accepts only revision 1, the exact
idempotent replay, or `head + 1` with the exact predecessor hash. Connector
binary, signature, certification, executor, sandbox, and drift-policy material
cannot change under the same version. A database `BEFORE INSERT` trigger uses
the same lock and independently enforces shadow-envelope parity, current-head
succession, immutable material, and terminal revocation even for direct SQL.
The Go writer remains the required cryptographic verifier. Revocation is
terminal. Trigger functions pin `search_path` to `pg_catalog` and dynamically
schema-qualify their trigger relation, preventing temporary-table namespace
shadowing.

Tenant/workspace rows are protected by forced RLS; global rows are visible as
global authority. Service-held database credentials and trusted tenant identity
remain mandatory: custom PostgreSQL GUCs are an internal RLS context, not an
end-user authentication mechanism.
The migration connection must pin `search_path` to a deployment-owned schema.

Runtime diagnostics may call `LoadCurrent`. Non-effecting planning may call
`LoadCurrentCertified`, which verifies validity against the database clock
rather than caller-supplied time. Neither method authorizes connector start.
`LockCurrentCertifiedForEffectAdmission` is the transaction-composition seam
used only by the durable effect reservation boundary: it takes the shared
exact-release lock, verifies the current head and database time, and leaves the
caller responsible for appending `ADMITTED` before commit. It does not run a
callback or start a connector. See
`docs/operations/effect-reservation.md`.

## Portable verification

Run:

```bash
make verify-connector-release-authority-vectors
```

The source-owned Go fixture, compiled JSON Schemas, and independent Python
verifier prove canonical certified-to-revoked chaining, bounded revisions,
exact scope/material continuity, monotonic signed/valid timelines, self-hashes,
pinned identity/key metadata, validity boundaries, and Ed25519 domain
separation. The JSON Schemas enforce statement/envelope structure; Go and
Python enforce cross-statement semantic equality and ordering. The pack
includes two signed statements and thirteen negative mutations.

## Remaining production gates

- a source-owned signing/import path with audited trust-root rotation;
- a production approval `BindingProvider` that derives approval connector
  authority only from the verified current certified release;
- deployment wiring for the implemented durable effect reservation boundary;
- active-work disposition beyond listing, source connector ACK, signed close
  evidence, and controlled deployment proof.
