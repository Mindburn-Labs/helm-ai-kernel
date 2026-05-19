# Codex Capability Audit For HELM Skill Packs

Date: 2026-05-18

## Sources

- Current repo state.
- Official OpenAI Codex docs for Skills, Plugins, Plugin Build, Hooks, and MCP.

## Findings

[KEEP] Codex skills are instruction packages. HELM treats them as procedural guidance only.

[KEEP] Codex plugins package skills, apps, MCP config, and hooks. HELM treats plugin installation as distribution, not authority.

[KEEP] MCP servers/tools must remain quarantined until HELM scan, schema pin, policy, CPI, PEP, and approval checks pass.

[KEEP] Codex hooks are useful preflight UX but are not HELM's authority boundary.

[REBUILD] HELM needed an OSS `skills` CLI that can scan, project, export, revoke, and receipt repo-scoped skills. That surface now exists as an MVP.

## HELM Decisions

- Repo-scoped Codex projection goes to `.agents/skills/<publisher>/<skill>/SKILL.md`.
- Codex plugin export writes `.codex-plugin/plugin.json` and bundled `skills/<id>/SKILL.md`.
- Plugin MCP config is emitted as pending/quarantined.
- Plugin hooks are emitted off by default.
- User/global install escalates and requires an approval receipt path that remains future Enterprise work.

## Known Limitations

[DEFER] This audit does not prove local Codex UI reload behavior.

[DEFER] This audit does not claim Codex plugin marketplace install e2e.

[DEFER] This audit does not rely on hooks for enforcement; HELM PEP/CPI/MCP/sandbox remains the enforcement boundary.
