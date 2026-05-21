# Workstation Adapter Feasibility Matrix

M0 scores what a manifest-first adapter can reliably observe today without private APIs. Scores are `0` unavailable, `1` partial/manual, `2` supported through stable local artifacts or documented exports.

| Capability | Codex | Claude Code | M0 source path |
| --- | ---: | ---: | --- |
| Run manifest | 2 | 2 | User-supplied `run.manifest.json`; both tools can be wrapped by local scripts or hooks. |
| Tool event stream | 1 | 2 | Codex App Server/event surfaces and OTel logs are useful where available; Claude Code hooks expose structured lifecycle points. |
| Git diff summary | 2 | 2 | Derived from local git state, independent of agent vendor. |
| Validation output | 2 | 2 | Derived from local test/build commands and hashed output summaries. |
| Network events | 1 | 1 | Codex can export network proxy allow/deny logs when configured; Claude Code requires hook/proxy capture. |
| MCP events | 1 | 1 | Both require configured MCP logs or wrapper events for complete evidence. |
| Memory writes | 1 | 1 | First release models proposed writes from explicit event records; native memory stores remain vendor-specific. |
| Recurring loops | 1 | 1 | First release records schedules from explicit manifests; enforcement and lifecycle registry are M3+. |
| Deterministic replay from artifacts | 2 | 2 | HELM-owned canonical import path produces stable receipt and ProofGraph roots from the same artifact set. |

## M0 Verdict

Codex is the first adapter because the local CLI/App Server direction and OTel event categories line up with a manifest-first receipt importer. Claude Code is second because hooks and local settings are strong, but parity depends on which local hook payloads are available in the customer environment.

M0-M2 should ship as `observe-only`. M3 can be started only after the fixture set proves deterministic import for allowed observe, allowed draft, denied network, denied memory, recurring loop, and tainted-context cases.
