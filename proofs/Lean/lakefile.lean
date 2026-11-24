import Lake
open Lake DSL

package helmAiKernelProofs where
  -- Treat Lean's `sorry` warning as an error. The CI gate checks this.
  moreLeanArgs := #["-DwarningAsError=true"]

@[default_target]
lean_lib EffectPermitSoundness where
  srcDir := ".."
  roots := #[`EffectPermitSoundness]
