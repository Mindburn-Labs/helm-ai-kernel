package runtime

import "errors"

// ExecutionMode strictly types the phases of the MAMA agentic pipeline.
type ExecutionMode string

const (
	ModeObserve   ExecutionMode = "observe"
	ModeExplore   ExecutionMode = "explore"
	ModePlan      ExecutionMode = "plan"
	ModeProbe     ExecutionMode = "probe"
	ModeCommit    ExecutionMode = "commit"
	ModeReplay    ExecutionMode = "replay"
	ModeDistill   ExecutionMode = "distill"
	ModeBlindEval ExecutionMode = "blind-eval"
)

// ModeTransitioner handles the deterministic advancement of the runtime.
type ModeTransitioner struct {
	CurrentMode ExecutionMode
}

var ErrInvalidTransition = errors.New("invalid execution mode transition")

// Transition forces standard progression or backtracking without skipping phases.
func (m *ModeTransitioner) Transition(target ExecutionMode) error {
	// For blind-eval, we never switch modes.
	if m.CurrentMode == ModeBlindEval && target != ModeDistill {
		return ErrInvalidTransition
	}

	// Strict Graph from Canonical Standard 9.2
	switch m.CurrentMode {
	case ModeObserve:
		if target != ModeExplore && target != ModePlan {
			return ErrInvalidTransition
		}
	case ModeExplore:
		// Explore only goes to Plan.
		if target != ModePlan {
			return ErrInvalidTransition
		}
	case ModePlan:
		if target != ModeProbe && target != ModeCommit {
			return ErrInvalidTransition
		}
	case ModeProbe:
		if target != ModePlan {
			return ErrInvalidTransition
		}
	case ModeCommit:
		if target != ModeObserve && target != ModeReplay {
			return ErrInvalidTransition
		}
	case ModeReplay:
		if target != ModeDistill {
			return ErrInvalidTransition
		}
	case ModeDistill:
		if target != ModeObserve {
			return ErrInvalidTransition
		}
	}

	m.CurrentMode = target
	return nil
}
