# Workstation Adapter Feasibility Matrix (M0, historical)

This is the M0 planning artifact that chose the first two workstation adapters.
Its sequencing advice has been overtaken — see "Status of the M0 gate" at the
bottom before treating anything here as guidance. The scoring table is kept as
the record of what was known at M0.

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

## Status of the M0 gate

That gate is satisfied and M3 has shipped. Do not read the paragraph above as
open sequencing work.

- All six named fixture classes exist:
  `fixtures/workstation/{allowed-observe,allowed-draft,denied-network,denied-memory,denied-recurring-loop,prompt-injection-tainted}`.
- The workstation surface is no longer observe-only. `helm-ai-kernel
  workstation` dispatches `decide` and `enforce`
  (`core/cmd/helm-ai-kernel/workstation_cmd.go`), implemented in
  `core/cmd/helm-ai-kernel/workstation_m3_cmd.go`. `workstation enforce` exits
  `126` on a `DENY` verdict instead of running the wrapped command, so it acts
  on the verdict rather than only recording it.

The rest of this page is a historical scoring record. Current adapter behavior
lives in `core/pkg/workstation/` and `core/cmd/helm-ai-kernel/workstation_*.go`.
