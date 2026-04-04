# ADR-004: All Runtime Mutation Goes Through Forge

**Status:** Accepted
**Date:** 2026-04-04

## Context

Uncontrolled agent self-modification is an existential risk. An agent that can silently add tools, modify its own skills, or escalate its own permissions without governance is not safe for enterprise deployment.

## Decision

**Forge is the only valid path for agent-authored skill and workflow mutation.**

- No virtual employee can add, modify, or remove skills outside of Forge.
- Skill proposals enter a promotion ladder: C0 (sandbox) -> C1 (shadow) -> C2 (canary) -> C3 (production).
- Manager review is required for promotion from C1 to C2 and from C2 to C3.
- Unauthorized self-promotion is structurally impossible (promotion requires external approval receipt).
- Canary evaluation runs against production-like signal streams before promotion.
- Skill lineage is tracked via ProofGraph for full auditability.

## Consequences

- `core/pkg/skills/` (currently empty) becomes the Forge implementation.
- Every skill has a lineage chain in ProofGraph.
- Rollback from any promotion level is always possible.
- Watchers (monitoring agents) are observers only, never authorities -- they cannot promote skills.
