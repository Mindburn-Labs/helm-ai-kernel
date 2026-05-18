# Codex Capability Audit

Date: 2026-05-17

## Sources

- [KEEP] Local command probes requested by the mission: `codex --version || true`, `codex --help || true`, and local `.codex` / `AGENTS.md` discovery.
- [KEEP] Official OpenAI Codex docs and `openai/codex` repository docs/release surface, including CLI features, security/approvals, AGENTS.md, MCP, subagents, remote connections, app features, computer use, and models.
- [DEFER] Local Codex CLI binary is unhealthy in this environment, so exact local CLI version/capability output could not be captured from `codex --version`.

## Detected Environment

- [KEEP] Workspace: `/Users/ivan/Code/Mindburn-Labs`.
- [KEEP] Host shell: `zsh`; current date/timezone from session: 2026-05-17, Europe/Sofia.
- [KEEP] `codex` resolves through `/Users/ivan/.local/share/mise/shims/codex` to `/opt/homebrew/bin/mise`.
- [REBUILD] Local `codex --version` and `codex --help` produced no usable output through the parent shell probe. Subagent reconciliation found a local `@openai/codex` install at `0.98.0` with a missing native vendor binary. Treat local CLI as broken until repaired.

## Capabilities

- [KEEP] Approval modes: This Codex desktop/tool session is configured with approval policy `never`, so approval prompts are unavailable. Official Codex supports approval policies including `untrusted`, `on-request`, and `never`; older help-center wording also describes Suggest, Auto Edit, and Full Auto UX modes.
- [KEEP] Sandbox modes: This session has full filesystem access and network enabled. Official Codex supports `read-only`, `workspace-write`, and `danger-full-access`; `workspace-write` normally disables network unless configured.
- [KEEP] Multiple terminals: This environment supports multiple persistent shell sessions via `exec_command` / `write_stdin`. No dedicated terminal-tab UI is exposed.
- [KEEP] MCP tools: This session has built-in tools and discoverable MCP/plugin surfaces. Official Codex supports MCP clients in CLI/IDE, `codex mcp` configuration, and experimental `codex mcp-server`.
- [KEEP] `AGENTS.md`: The repo-root `/Users/ivan/Code/Mindburn-Labs/AGENTS.md` was injected into this session. Official docs state Codex loads global and project `AGENTS.md` guidance root-to-leaf. In this tool-backed session, automatic global loading cannot be proven.
- [KEEP] Subagents/tasks: This session exposes `spawn_agent`; the implementation still created `.codex/agents/*.md` task files because the mission explicitly required task-file decomposition. Official Codex documents subagents and local `.codex/agents/` / `~/.codex/agents/` definitions.
- [DEFER] Mobile/remote approvals: No mobile approval surface is exposed here. Official Codex supports remote work from ChatGPT mobile against a connected host.
- [DEFER] Desktop/computer-use: No desktop/computer-use tool is exposed here. Official Codex app supports Computer Use via plugin with macOS Screen Recording and Accessibility permissions.
- [KEEP] Model switching: This session does not permit switching the active model from inside the run. Official Codex supports model selection via CLI/config/app controls.

## Implementation Impact

- [REBUILD] Do not rely on local Codex CLI execution for Launchpad conformance until the local install is repaired.
- [KEEP] Treat Codex as an `external_proprietary_adapter` / BYO account/tool cell in the Launchpad registry, not as an OSS app redistributed by HELM.
- [KEEP] Permission-bypass defaults must be blocked in Codex policy packs.
- [KEEP] MCP tools must be governed by HELM, not assumed safe because Codex supports MCP.
