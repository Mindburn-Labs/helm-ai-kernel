# HELM Skill Packs Repo Audit

Date: 2026-05-18

## Verdict

[REBUILD] Before this remediation, `core/pkg/skills` implemented Forge-style skill evolution and promotion, but not the requested OSS Skill Packs product surface. The missing surface included `helm-ai-kernel skills ...`, repo-scoped agent projection, Codex plugin export, scan attestations, receipts, and Skill Pack schemas.

## Current Implementation

[DELETED] The Forge skill lifecycle (`core/pkg/skills`) had no importer and was removed (helm-tracker#266).

[DELETED] The `core/pkg/registry/skills` bundle registry was reached only by the unshipped `skill_lint` and `skill_pack` mains and was removed with them (helm-tracker#266).

[MERGE] New OSS Skill Packs surface now lives in `core/pkg/skillpacks` and `core/cmd/helm-ai-kernel/skills_cmd.go`.

[KEEP] First-party repo-local skills are under `registry/skills/helm/`.

## Implemented In This Slice

- `skills search`
- `skills inspect`
- `skills verify`
- `skills scan`
- `skills install`
- `skills export`
- `skills list`
- `skills disable`
- `skills revoke`
- `skills receipt`
- `skills marketplace init`
- `skills marketplace add`
- `skills plugin inspect`
- `skills plugin scan`
- `skills plugin export`

## Enforced In This Slice

- Skills explicitly do not grant tool permissions.
- Repo scope is the safe default.
- User/global install escalates and does not project files.
- Policy-bypass and secret-exfiltration instructions deny.
- MCP auto-enable and side-effect tool requests escalate.
- Symlink escape denies.
- Opaque binary payloads deny until provenance is implemented.
- Install writes `SKILL_INSTALL_RECEIPT` and `SKILL_PROJECTION_RECEIPT`.
- Revoke writes `SKILL_REVOKE_RECEIPT`.
- Codex plugin export marks MCP as `pending_quarantined` and hooks `off_by_default`.

## Missing For Full Coverage

Historical audit heading. "Full coverage" here means inventory completeness for
this skill-pack survey, not a product completeness or GA claim.

[REFACTOR] Add signature verification backed by actual public keys. Since helm-tracker#311 the first-party packs are pinned by a content digest compiled into the binary and every other pack is unsigned; the string comparison this audit found is removed.

[REFACTOR] Add full JSON Schema validation in the loader, not only typed manifest checks.

[REFACTOR] Add policy TOML parser validation for `policies/skills/*.toml`. Since helm-tracker#311 the scan reads no policy file: its rules are compiled in, and a test parses `policies/skills/first-party.safe.toml` and binds each key to behaviour.

[DEFER] Add GitHub remote skill fetch and pinned source verification.

[DEFER] Add Claude Code, Cursor, and OpenCode projection smoke tests.

[DEFER] Add Enterprise-managed global/user install approval receipts.

[DEFER] Add EvidencePack export for complete Skill Pack install/revoke campaigns.

## Files Added

- `core/cmd/helm-ai-kernel/skills_cmd.go`
- `core/pkg/skillpacks/*`
- `schemas/skills/*.schema.json`
- `registry/skills/helm/repo-auditor/*`
- `policies/skills/first-party.safe.toml`
- `core/pkg/skillpacks/skillpacks_test.go`
- `core/cmd/helm-ai-kernel/skills_cmd_test.go`
