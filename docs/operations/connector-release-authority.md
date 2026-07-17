# Connector release authority contract

Status: source-owned contract and offline verifier; internal, pre-production.

`connector-release-authority.v1` is the Kernel-owned signed statement that an
exact connector release is certified or revoked. It closes the contract-level
confusion between mutable connector metadata, candidate certification evidence,
and release authority. It does not yet prove a deployed durable registry,
runtime admission enforcement, or a live connector effect.

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
- a monotonic registry revision and predecessor hash;
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

## Portable verification

Run:

```bash
make verify-connector-release-authority-vectors
```

The source-owned Go fixture and independent Python verifier prove canonical
certified-to-revoked chaining, self-hashes, pinned identity/key metadata,
validity boundaries, and Ed25519 domain separation. The pack includes two
signed statements and eight negative mutations.

## Remaining production gates

- a migration-owned, read-only-at-runtime PostgreSQL projection keyed by exact
  scope, connector ID, version, and revision;
- a source-owned signing/import path with audited trust-root rotation;
- a production approval `BindingProvider` that derives approval connector
  authority only from the verified current certified release;
- transactionally ordered revocation versus dispatch admission;
- Data Plane atomic admission persistence and near-effect current-state checks;
- active-work disposition, close/uncertainty evidence, connector ACK, and
  controlled deployment proof.
