# MAMA — EXPERIMENTAL Multi-Agent Runtime

**Status: EXPERIMENTAL. Unstable public API. Do not depend on this package for production workloads until it graduates out of `experimental/`.**

## What it is

MAMA is scaffolding for a production agent runtime with lanes-based concurrency — a subagent roster, an executor constrained by `allowed URN` boundaries, a mode machine (Observe → Explore → Plan → Probe → Commit → Replay → Distill), and a canonical `MissionState` typed structure that replaces raw unstructured transcripts.

## Why it is experimental

This package is intentionally *separate* from `core/pkg/researchruntime/`, which is a research pipeline (harvester → planner → verifier → synthesizer → publisher). MAMA is the *production-agent* concept: real-time agent dispatch with lane isolation, not a research orchestration. That distinction is important enough to preserve as a first-class concept — but the current implementation (~350 LoC across `runtime/`, `agents/`, `lanes/`, `http/`, `command/`) is placeholder scaffolding, not a working runtime. It is wired into the `helm` CLI and the `serving/` profile for shape-validation but is not production-ready.

## Graduation trigger

MAMA matures out of `experimental/` when the [Titan cognitive-runtime architecture](https://mindburn.org/titan) crystallizes and HELM has a clear, stable contract for production agent orchestration. Until then, this is a design sketch. Open design questions:

- Lane isolation semantics: per-agent or per-mission?
- Executor boundary: single `allowed URN` or a capability-envelope list?
- ModeMachine determinism: is the transition graph a Guardian-gated or externally-driven?
- Relationship to `core/pkg/effects/` — does MAMA own effect dispatch or delegate?
- Integration with MCP delegation sessions.

## Subpackages

| Path | Purpose | LoC |
|------|---------|-----|
| `runtime/` | `MissionState`, `ExecutionMode` types | ~123 |
| `agents/` | Executor + Roster types | ~74 |
| `lanes/` | ARC exploration lane (stub) | ~33 |
| `command/` | Command registry | ~53 |
| `http/` | REST surface (stub) | ~71 |

## Stability guarantees

None. Expect:
- Breaking API changes between minor releases.
- Reorganization into larger packages (may merge with `effects/` or `kernel/`).
- Deletion if the design doesn't reach production-grade.

## Tracking

Roadmap item P0-12 (MAMA decision) is marked complete via this relocation. Next design pass is gated on the Titan cognitive-runtime architecture. Before shipping any new dependency on MAMA, open an issue proposing graduation to stable.
