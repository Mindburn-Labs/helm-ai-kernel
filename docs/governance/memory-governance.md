# Memory Governance (R5)

**Status:** preview specification (doc-led; manifest hooks merged in
`capability_manifest.v1.json → memory_access`).
**Origin:** Step AOS dual-domain three-step memory (用户域/智能体域,
记-理-忆). HELM does not build memory; HELM governs it.

## Position

Agent memory is an effect surface. Writes, cross-domain reads, and deletions
change future agent behavior and may move personal data across boundaries —
so they belong behind the same decision-receipt loop as any other effect.
"Agent memory is user-deletable" must be a **certifiable property**, not a
settings-page promise.

## Domain model (adopted)

| Domain | Contents | Default policy |
| --- | --- | --- |
| **User domain** | Facts, episodes/scenarios, preferences, profile | Personal data: `data_boundary` at most `device_boundary` unless an explicit grant raises it; writes receipted; user deletion must be honored with a deletion receipt |
| **Agent domain** | Domain knowledge, methods/experience, cognition/personality | Operator-governed: writes receipted; retention per `retention_policy` schemas; exportable for audit |

Cross-domain reads (agent-domain logic consuming user-domain facts, or user
profile leaking into agent-domain "experience") are **deny by default**
(`memory_access.cross_domain_read: false`) and require an explicit capability
manifest grant plus, for personal data categories, a capability token.

## Rules

1. **Memory operations are capabilities.** `memory.write`, `memory.read`,
   `memory.delete` per domain are registered capabilities with manifests;
   unregistered memory paths fail closed.
2. **Deletion is provable.** `memory.delete` on the user domain produces a
   deletion receipt (aligning with the existing `deletion_receipt` schema
   family) including scope, before/after digests where computable, and any
   downstream propagation notices.
3. **Derived memory inherits classification.** Summaries/embeddings derived
   from user-domain data carry the user-domain boundary until a reviewed
   declassification step (itself receipted).
4. **Replay hygiene.** Memory contents are never sufficient evidence for a
   HELM claim; only receipts, packs, and source-owned artifacts are (standing
   workspace rule, restated for memory stores).
5. **Certification property.** A connector/agent earns the
   `memory.user-deletable` certification mark only by demonstrating delete →
   receipt → post-delete read returns nothing, replayed from a conformance
   vector.

## Out of scope

Recall latency, memory compression, and "记-理-忆" pipeline design are
implementation concerns of the memory provider, not the boundary.
