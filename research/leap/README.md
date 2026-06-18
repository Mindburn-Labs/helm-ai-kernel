# LEAP Research Note

Status: docs-only research note. HELM does not depend on LEAP, Lean, or an SMT
toolchain.

## Verified Public Artifact

- Paper: [LEAP: Supercharging LLMs for Formal Mathematics with Agentic Frameworks](https://arxiv.org/abs/2606.03303), arXiv:2606.03303v2, published June 3, 2026.
- Artifact link from the paper: [google-deepmind/superhuman/leap](https://github.com/google-deepmind/superhuman/tree/main/leap).

## Pattern Used

HELM Formal Verification Worker v0 borrows the pattern of verifier-guided
repair/search: a candidate proof path is useful only when an independent
verifier accepts it, and unsuccessful or budget-exhausted paths fail closed.

For Kernel v0 this is intentionally smaller than LEAP:

- one invariant: no irreversible side effect may execute before an approval
  checkpoint;
- one deterministic backend;
- no Lean runtime;
- no SMT runtime;
- no claim that HELM integrates Google LEAP or proves all enterprise actions
  correct.

## Kernel Boundary

The source-owned Kernel contracts are:

- `protocols/json-schemas/verification/proof_obligation.schema.json`
- `protocols/json-schemas/verification/proof_result.schema.json`
- `core/pkg/kernel/cpi.FormalVerifier`

Proof evidence belongs in existing EvidencePack extension paths such as
`99_EXT/helm-formal-proof/...`, declared in `00_INDEX.json`.
