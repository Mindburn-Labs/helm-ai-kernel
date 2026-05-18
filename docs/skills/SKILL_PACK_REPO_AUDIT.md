# HELM Skill Packs Repo Audit

Date: 2026-05-18

## Verdict

[REBUILD] Before this remediation, `core/pkg/skills` implemented Forge-style skill evolution and promotion, but not the requested OSS Skill Packs product surface. The missing surface included `helm-ai-kernel skills ...`, repo-scoped agent projection, Codex plugin export, scan attestations, receipts, and Skill Pack schemas.

## Current Implementation

[KEEP] Existing Forge skill lifecycle remains separate and untouched.

[KEEP] Existing `core/pkg/registry/skills` conformance package remains a lower-level bundle registry.

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

## Missing For 100%

[REFACTOR] Add signature verification backed by actual public keys instead of first-party repo references.

[REFACTOR] Add full JSON Schema validation in the loader, not only typed manifest checks.

[REFACTOR] Add policy TOML parser validation for `policies/skills/*.toml`.

[DEFER] Add GitHub remote skill fetch and pinned source verification.

[DEFER] Add Claude Code, Cursor, and OpenCode projection smoke tests.

[DEFER] Add Enterprise-managed global/user install approval receipts.

[DEFER] Add EvidencePack export for complete Skill Pack install/revoke campaigns.

## Files Added

- `core/cmd/helm-ai-kernel/skills_cmd.go`
- `core/pkg/skillpacks/*`
- `schemas/skills/*.schema.json`
- `registry/skills/helm/repo-auditor/*`
- `registry/skills/helm/codex-multi-agent-director/*`
- `policies/skills/first-party.safe.toml`
- `core/pkg/skillpacks/skillpacks_test.go`
- `core/cmd/helm-ai-kernel/skills_cmd_test.go`
