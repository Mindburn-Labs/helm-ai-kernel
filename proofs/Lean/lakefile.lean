import Lake
open Lake DSL

/-
  Lake build configuration for the HELM AI Kernel Lean proofs.

  Workstream F / F2 + F3 — Phase 3 of the helm-ai-kernel 100% SOTA execution
  plan. The single library target `EffectPermitSoundness` lives one
  directory up from this lakefile (so the .lean source can sit next to
  the existing TLA+ specs in proofs/), reached via `srcDir`.

  Run locally:

      cd proofs/Lean
      lake build

  Requires Lean 4 toolchain (elan + lake) — see lean-toolchain for the
  pinned version. CI installs elan and runs the same command from
  .github/workflows/lean.yml.
-/

package helmAiKernelProofs where
  -- No special build options; the proof is self-contained and uses no
  -- external libraries. Mathlib would let us drop a few `simp` calls
  -- but is not required and would slow CI considerably.

@[default_target]
lean_lib EffectPermitSoundness where
  -- The .lean source lives one directory up so it sits alongside the
  -- existing TLA+ specs in proofs/. Lake resolves module name
  -- `EffectPermitSoundness` against `srcDir` + ".lean".
  srcDir := ".."
  roots := #[`EffectPermitSoundness]
