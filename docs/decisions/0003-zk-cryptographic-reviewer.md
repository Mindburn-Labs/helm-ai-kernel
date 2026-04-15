---
title: "ADR-0003 — External ZK Cryptographic Reviewer Shortlist"
status: Proposed
date: 2026-04-15
deciders: security-lead, crypto-eng
supersedes: none
---

# ADR-0003 — External ZK Cryptographic Reviewer Shortlist

## Context

The GDPR Article 17 zero-knowledge compliance circuit (roadmap P4-03) is scheduled for GA by 2026-07-15, 2.5 weeks before the EU AI Act high-risk deadline. Publishing a ZK circuit without external cryptographic review is irresponsible — circuit bugs in production ZK are catastrophic (invalid proofs accepted, subjects' data leaked, regulator trust destroyed).

This ADR shortlists qualified external reviewers, narrows to a primary and backup, and documents the engagement-letter requirements.

## Shortlist (alphabetical, all firms or named individuals active in ZK auditing 2025-2026)

### 1. Trail of Bits
- **Profile**: NY-based security firm; audits Filecoin, Matter Labs, Scroll, Aztec.
- **Expertise match**: deep gnark / Groth16 / PLONK familiarity.
- **Typical engagement**: 4–8 weeks; ~$180K–$400K depending on scope.
- **Availability (2026-Q2)**: typically 8–12 week lead time.
- **Contact**: opensource@trailofbits.com

### 2. Least Authority
- **Profile**: Oakland-based; audits Ethereum Foundation projects, Ocean Protocol, Filecoin.
- **Expertise match**: ZK + privacy-preserving computation is their stated core.
- **Typical engagement**: 3–6 weeks; ~$120K–$280K.
- **Availability (2026-Q2)**: moderate lead time ~6 weeks.
- **Contact**: contact@leastauthority.com

### 3. Veridise (Phillip R. Jones et al.)
- **Profile**: Austin-based; specializes in ZK circuit verification with its own tooling (Veridise Picus, Coda).
- **Expertise match**: circuit-specific auditing is their unique differentiator. Picus can formally verify gnark circuits, not just review.
- **Typical engagement**: 2–4 weeks; ~$80K–$200K.
- **Availability (2026-Q2)**: typically responsive within 2 weeks.
- **Contact**: hello@veridise.com

### 4. Daira-Emma Hopwood (independent consultant)
- **Profile**: Longtime Electric Coin Company (Zcash) senior cryptographer; Halo2 author.
- **Expertise match**: exceptional for Halo2/PLONK-style circuits; less directly relevant for gnark/Groth16 but adaptable.
- **Typical engagement**: independent; ~$20K–$60K for a scoped review.
- **Availability**: highly variable.
- **Contact**: via ZKProof community or public Twitter DMs.

### 5. Runtime Verification
- **Profile**: Urbana-IL based; formal verification focus; audits smart contracts for Ethereum Foundation, Optimism, Polkadot.
- **Expertise match**: Formal methods (K framework) are their differentiator. Can express circuit invariants as K specs.
- **Typical engagement**: 4–8 weeks; ~$150K–$350K.
- **Availability (2026-Q2)**: tight; typically 10+ weeks.
- **Contact**: contact@runtimeverification.com

## Decision

**Primary reviewer**: **Veridise**.

Rationale:
1. **Tool fit**: Picus was built to verify gnark circuits. That's a 10× advantage over general-purpose audit firms that would hand-review the circuit.
2. **Timeline fit**: 2–4 weeks for the engagement, plus 1 week of fix integration, fits the 2026-07-15 GA gate from a Week-18 start.
3. **Cost fit**: ~$100K engagement is within a realistic budget at this stage; Trail of Bits at $300K+ would stress pre-revenue cash.
4. **Specificity**: their public portfolio includes circuit verification for Circom, Noir, gnark — exactly our target.

**Backup (if Veridise unavailable)**: **Least Authority**.

Rationale:
1. Closest expertise match among remaining options.
2. Availability typically better than Trail of Bits.
3. ZK as stated core practice.

**Reject for now**: Trail of Bits (tighter availability, higher cost), Daira-Emma independently (scheduling risk for a time-gated deliverable), Runtime Verification (longest lead time).

## Engagement letter requirements

The engagement letter must cover:
1. **Scope**: GDPR Article 17 circuit (circuit definition + gnark Go wrapper + verifier WASM bundle). Not the broader HELM codebase.
2. **Deliverables**: written audit report, list of findings classified by severity, proposed fixes, re-audit pass after fixes applied.
3. **Timeline**: kickoff by 2026-06-01, initial findings by 2026-06-22, re-audit complete by 2026-07-10, signoff by 2026-07-15.
4. **IP**: all audit findings and fix recommendations belong to Mindburn Labs under Apache-2.0 for public disclosure post-release. Veridise Picus-generated proofs remain their tooling IP.
5. **Disclosure**: coordinated disclosure — findings not published until fixes ship.
6. **Payment terms**: 30% on signature, 50% on initial report, 20% on re-audit pass.

## Fallback plan if all reviewers unavailable by 2026-06-01

Delay the circuit's GA to Q4 2026. Do not ship without external review. The EU AI Act deadline is a strong incentive but not strong enough to justify an unreviewed ZK circuit going live.

## Action items

- [ ] (conformance-lead) by 2026-05-01: email Veridise for scope + availability.
- [ ] (conformance-lead) by 2026-05-08: email Least Authority as simultaneous backup.
- [ ] (ceo or equivalent) by 2026-05-15: sign engagement letter with selected primary.
- [ ] (crypto-eng) by 2026-05-29: have v0 circuit ready for kickoff, including gnark implementation + test vectors.

## References

- Roadmap item P4-03 — ZK GDPR Article 17 circuit
- Production deployment plan item K — full circuit implementation plan
- Veridise Picus paper: https://ipc.ai/papers/picus
- Common ZK circuit vulnerabilities catalog: https://github.com/0xPARC/zk-bug-tracker
