package contracts

// VPL (Verified Planning Loop) — canonical execution protocol.
// Per ARCHITECTURE.md §5: propose → validate → verdict → execute → receipt → checkpoint.
//
// The VPL is implemented across Guardian (policy evaluation), SafeExecutor
// (gated execution), and ProofGraph (receipt chain). These constants provide
// canonical naming for the loop phases.

// VPLPhase represents a phase in the Verified Planning Loop.
type VPLPhase string

const (
	// VPLPhasePropose is the initial phase where a request enters the system.
	VPLPhasePropose VPLPhase = "PROPOSE"
	// VPLPhaseValidate is the policy evaluation phase (Guardian/PEP).
	VPLPhaseValidate VPLPhase = "VALIDATE"
	// VPLPhaseVerdict is the phase where a policy decision is rendered.
	VPLPhaseVerdict VPLPhase = "VERDICT"
	// VPLPhaseExecute is the gated execution phase (SafeExecutor).
	VPLPhaseExecute VPLPhase = "EXECUTE"
	// VPLPhaseReceipt is the phase where cryptographic proof is generated.
	VPLPhaseReceipt VPLPhase = "RECEIPT"
	// VPLPhaseCheckpoint is the proof condensation evaluation phase.
	VPLPhaseCheckpoint VPLPhase = "CHECKPOINT"
)

// VGLStage represents a stage in the Verified Genesis Loop.
// Per ARCHITECTURE.md §3: law formation protocol.
type VGLStage string

const (
	// VGLStageCompile is the policy compilation stage.
	VGLStageCompile VGLStage = "COMPILE"
	// VGLStageVariantSelect is the context-dependent variant selection stage.
	VGLStageVariantSelect VGLStage = "VARIANT_SELECT"
	// VGLStageMirror is the deterministic semantic mirror generation stage.
	VGLStageMirror VGLStage = "MIRROR"
	// VGLStageWargame is the blast-radius wargaming stage.
	VGLStageWargame VGLStage = "WARGAME"
	// VGLStageApproval is the ORG_GENESIS_APPROVAL ceremony stage.
	VGLStageApproval VGLStage = "APPROVAL"
	// VGLStageActivate is the runtime activation stage.
	VGLStageActivate VGLStage = "ACTIVATE"
)
