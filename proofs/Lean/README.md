# HELM AI Kernel Lean proofs

Machine-checked proofs of HELM kernel invariants. The current scope is
the **ceiling-precedence** theorem (also called *EffectPermitSoundness*):
no P1 policy bundle, however constructed, can cause `Decide` to return
ALLOW for a request a P0 ceiling forbids.

Workstream F / F2 + F3 — Phase 3 of the helm-ai-kernel formal proof execution
plan. Companion to the TLA+ spec `proofs/GuardianPipeline.tla`, an abstract
safety model of the six-gate pipeline (the other TLA+ specs were retired in
HELM-756); the Lean proof targets the single safety property that admits a
clean function-level statement.

## Local validation

Requires the Lean 4 toolchain (`elan` + `lake`). Install elan:

```
curl https://raw.githubusercontent.com/leanprover/elan/master/elan-init.sh -sSf | sh
```

Then build the proof:

```
cd proofs/Lean
lake build
```

A green build means the kernel of Lean accepted every theorem in
`proofs/EffectPermitSoundness.lean`. A red build either means the
toolchain mismatched (`lean-toolchain` pins `leanprover/lean4:v4.15.0`)
or a tactic failed — neither is silent.

CI runs the same command (see `.github/workflows/lean.yml`); local
parity is a hard requirement when adding theorems.

## What the proof proves

Given the abstract model in `EffectPermitSoundness.lean`:

* `Verdict := allow | deny | escalate`
* `Ceiling := Request → Bool`
* `Bundle := Request → Verdict`
* `Decide c b r := if c r then b r else .deny`

The four theorems are:

| Theorem                          | Statement                                                                       |
|----------------------------------|---------------------------------------------------------------------------------|
| `ceiling_precedence`             | `Decide c b r = .allow → c r = true`                                            |
| `ceiling_deny_blocks_allow`      | `c r = false → Decide c b r ≠ .allow` (contrapositive of the above)             |
| `decide_passthrough_on_allow`    | `c r = true → b r = .allow → Decide c b r = .allow` (system is not a no-op)     |
| `decide_deny_on_ceiling_deny`    | `c r = false → Decide c b r = .deny`                                            |

The contrapositive form (`ceiling_deny_blocks_allow`) is the form the
prose claims in marketing material and procurement Q&A reference.

## Scope and limitations

This proof is intentionally minimal. It establishes the **abstract**
contract: the function-level composition of ceiling and bundle layers.
It does **not** verify the following:

1. **Go-level fidelity.** The Lean `Decide` is a Lean function; the
   running kernel is in Go. The Lean proof guarantees the contract holds
   when faithfully implemented; it does not detect implementation drift.
2. **The internal structure of `Request`.** The proof treats `Request`
   as opaque. A bug that mutates the request between the ceiling check
   and the bundle evaluation would not be caught here; the
   conformance suite under `tests/conformance/` covers that surface.
3. **Bundle authenticity.** Signature verification, TUF trust roots,
   and Sigstore anchoring (Workstream E + G) are out of scope. The
   theorem assumes the bundle is whatever bytes the kernel chose to
   load; integrity of that loading path is verified elsewhere.
4. **Concurrency / re-entrancy.** `Decide` is modeled as a pure
   function. The Go implementation's concurrent access patterns and
   ordering guarantees are not modeled here or in the TLA+ spec.
   `GuardianPipeline.tla` (model-checked by the `tla` workflow) is an
   abstract six-gate safety model; its only tie to the Go code is the
   gate-name mapping test `core/pkg/guardian/spec_roster_test.go`.
5. **The full P0 / P1 / P2 layering.** The model collapses to two
   layers (ceiling + bundle). P2 (per-request override / break-glass)
   is not modeled; that layer is required by construction to be
   either monotonic (cannot upgrade a `.deny` to `.allow`) or
   explicitly logged as a break-glass action — both are surface
   contracts, not part of the safety theorem.
6. **Obligations and advice.** The verdict carries no obligations
   here. Obligation-handling soundness (e.g. the kernel must apply
   every obligation a permitted decision carries) is a separate axis
   not yet modeled.

These omissions are deliberate. The ceiling-precedence theorem, in this
minimal form, is the **single** property the kernel must preserve to be
sound — anything else is defense in depth.

## Adding theorems

1. Add the theorem to `proofs/EffectPermitSoundness.lean` (or a new
   sibling file under `proofs/`, with a `roots` entry in
   `lakefile.lean`).
2. `lake build` must remain green.
3. Document the theorem and its scope in this file.
4. Update the Conformance Profile v1.1 axis in
   `tests/conformance/profile-v1/checklist.yaml` if the new theorem
   shifts the implementer-must-prove bar.

## External review

No merge gate requires an external review of this proof. The `lean` workflow
builds it on changes under `proofs/`, and that workflow is not part of the
required `ci / gate`. Before publishing the v1.1 profile axis
"formal soundness", an independent reviewer with Lean 4 experience
should re-derive the proof from the model definitions on a clean
checkout. The proof's brevity (under 50 lines of tactic prose) is
deliberate — it is meant to be re-read end-to-end in one sitting.
