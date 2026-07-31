# adversarial-policy-v1

Adversarial multi-turn policy-adherence vectors for the governed capability
registry specs (`docs/governance/`). Inspired by ClawEval-class benchmarks:
does policy hold under adversarial pressure mid-orchestration — injected tool
results, scope-creep lures, forged approvals, manifest drift, expired tokens,
unverifiable rollback promises, cross-domain memory reads, tier violations,
boundary downgrades.

## Contents

- `vectors.json` — 12 scenario vectors with policy inputs and expected
  fail-closed decisions.
- `verify_vectors.py` — stdlib-only verifier; encodes the policy table from
  the governance docs as executable rules and checks every vector against it.

## Run

```bash
python3 reference_packs/adversarial-policy-v1/verify_vectors.py
```

Exit 0 = all vectors consistent with the encoded policy table.

## Scope honesty

This pack verifies vector ↔ policy-table consistency. Driving the real Go
guardian through these scenarios (wired replay) is follow-up work and is not
claimed here. These are unsigned expectation vectors; no signature or
post-quantum claims.
