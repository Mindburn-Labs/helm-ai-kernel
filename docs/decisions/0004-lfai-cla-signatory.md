---
title: "ADR-0004 — LFAI CLA Signatory + Contribution Path"
status: Proposed
date: 2026-04-15
deciders: conformance-lead, ceo/legal
supersedes: none
---

# ADR-0004 — LFAI CLA Signatory and Contribution Path

## Context

The production deployment plan submits HELM Conformance Profile v1 (roadmap P4-04) to LF AI & Data for neutral standards hosting. LFAI requires either:
1. A **Contributor License Agreement (Individual CLA)** signed per-contributor, OR
2. A **Corporate CLA** signed by a named entity whose employees contribute.

Since Mindburn Labs is the contributing entity, the Corporate CLA route is the right choice — it lets any current or future Mindburn employee contribute without repeated CLA friction.

## Required signatory profile

The Corporate CLA must be signed by someone who:
1. Has **legal authority to bind the entity** — typically an officer (CEO, CFO, CTO) or legally empowered delegate with a board-authorized power of attorney.
2. Understands the **IP assignment and licensing** terms being granted (LFAI CLAs are broad — contributors grant copyright + patent license to LFAI for the contribution).
3. Is available for **ongoing signatory obligations** — the CLA usually requires the signer to attest annually that the contributor list remains current.

For Mindburn Labs, this is **the company's CEO** or equivalent officer. A non-officer engineer cannot sign, even with internal authority, because LFAI's intake requires entity-binding authority.

## Pre-signing checklist

Before executing the LFAI CCLA:

- [ ] **Entity verification**: Mindburn Labs must exist as a legal entity at the time of signing (LLC, Inc., or equivalent). If the entity is in formation, wait until incorporation finalizes.
- [ ] **Tax ID**: CLAs require EIN (or equivalent country-specific business ID). Confirm on hand.
- [ ] **Address of record**: matches the entity's business registration. Document.
- [ ] **Contribution scope**: explicitly list which artifacts Mindburn contributes — HELM Conformance Profile v1 spec + checklist.yaml + TLA+ invariants at `proofs/` + golden fixtures. **NOT** the full HELM OSS codebase — CLAs scope to specific named contributions.
- [ ] **IP clean**: verify no encumbered IP (prior employer work, open-source with copyleft, etc.) is in the contributed artifacts. All HELM OSS is Apache-2.0 original work by Mindburn employees; this is a clean signing.
- [ ] **Export control review**: cryptography-adjacent contributions (TLA+ specs describing the delegation model) typically fall under ECCN 5D002 with TSU license exception; verify acceptable for LFAI which has members in sanctioned jurisdictions.
- [ ] **Counsel review**: have outside counsel (or internal legal if available) review the CCLA terms before signing. Typical turnaround: 1–2 weeks.

## Signatory options

| Option | Pros | Cons |
|--------|------|------|
| CEO | Default choice; clearest legal authority; signals Mindburn's investment | CEO bandwidth; legal review still needed |
| CTO with delegated authority via board resolution | CEO bandwidth preserved; keeps technical stakeholder engaged | Requires board resolution (1–4 weeks additional) |
| External counsel as attorney-in-fact | CEO fully offloaded | More expensive; less culturally natural |

## Decision (recommendation pending CEO confirmation)

**Signatory**: CEO of Mindburn Labs.

**Timeline**:
- Week of 2026-05-20: brief CEO + distribute CLA draft + legal review begins.
- Week of 2026-06-03: legal review complete; CLA ready for signature.
- 2026-06-10: submit signed CCLA to LFAI.
- 2026-06-17: LFAI processes; we are cleared to contribute.
- 2026-06-24 onward: submit Conformance Profile v1 via formal WG intake.

This timeline aligns with the Week-6–7 milestone in the production plan's 26-week calendar.

## Alternative to LFAI CCLA

If LFAI process is too slow for the EU AI Act 2026-08-02 deadline, fall back to:
1. Keep Conformance Profile v1 solely in `Mindburn-Labs/helm-oss` under Apache-2.0.
2. Maintain it as a Mindburn-governed standard.
3. Revisit LFAI submission in 2026-Q4 after the deadline pressure eases.

Standards-body amplification is valuable but not on the critical path for the EU AI Act deliverable.

## Action items

- [ ] (conformance-lead) by 2026-05-06: download current LFAI CCLA template; route to outside counsel.
- [ ] (ceo) by 2026-05-20: confirm willingness to sign as signatory-of-record.
- [ ] (legal) by 2026-06-03: counsel review complete.
- [ ] (ceo) by 2026-06-10: sign and submit.

## References

- LF AI & Data CCLA template: https://lfaidata.foundation/join/
- HELM OSS licensing: Apache-2.0, see `LICENSE` at repo root.
- `docs/standards/submissions/lfai-conformance-profile-v1.md` — the submission this ADR unblocks.
- Roadmap item P4-04, P4-06.
