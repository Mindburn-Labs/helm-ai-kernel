package governance

import ()

// ChangeClass defines the risk level of a self-modification.
type ChangeClass string

const (
	ChangeClassC0 ChangeClass = "C0_CONFIG"  // Trivial config change
	ChangeClassC1 ChangeClass = "C1_CONTENT" // Content update (prompts, docs)
	ChangeClassC2 ChangeClass = "C2_LOGIC"   // Logic update (code, methods)
	ChangeClassC3 ChangeClass = "C3_KERNEL"  // Core Kernel architecture change
)

type EvolutionGovernance struct{}
