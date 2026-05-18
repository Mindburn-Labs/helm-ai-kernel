# Spawn Reverse Engineering

Date: 2026-05-17

Spawn is UX reference only. No Spawn code is imported.

## Command Surface

- [KEEP] Useful UX: `spawn`, `spawn <agent> <cloud>`, `spawn matrix`, `spawn list`, `spawn tree`, `spawn status`, `spawn last`, `spawn fix`, `spawn update`, `spawn delete`, `spawn agents`, `spawn clouds`, `spawn version`, and `spawn help`.
- [MERGE] HELM Launchpad mirrors only the safe subset: `launch matrix`, `apps`, `substrates`, `plan`, launch, `status`, `logs`, `repair`, and `delete --cascade`.

## Manifest Structure

- [KEEP] Spawn manifest uses top-level `agents`, `clouds`, and `matrix`.
- [MERGE] HELM uses separate signed/validated app and substrate specs plus policy packs; matrix is derived, not trusted as authority.

## App And Cloud Matrix

- [KEEP] Spawn advertises many agent/cloud combinations, including local, Hetzner, AWS Lightsail, DigitalOcean, GCP, Daytona, and Sprite.
- [REFACTOR] HELM must classify each cell by license, redistribution, artifact, policy, sandbox, healthcheck, e2e, teardown, receipt, and EvidencePack verification.

## Unsafe Defaults HELM Must Not Copy

- [REMOVE] `curl | bash`, `irm | iex`, and process substitution remote scripts.
- [REMOVE] Host shell rc mutation for credentials.
- [REMOVE] Permission bypass or skip defaults.
- [REMOVE] Recursive spawn in MVP.
- [REMOVE] Broad root SSH/cloud persistence without policy and idempotency reconciliation.
- [REMOVE] Mutable live git updates.
