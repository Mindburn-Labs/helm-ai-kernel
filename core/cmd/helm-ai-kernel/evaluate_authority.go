package main

import (
	"fmt"
	"strings"
)

const (
	evaluateAuthorityArgsKey             = "__helm_evaluate_authority_v1"
	evaluateAuthorityExecutionProfileKey = "execution_profile"
	evaluateRequestMaxBodyBytes          = 1 << 20
	evaluateAuthorityMaxDepth            = 64
	evaluateAuthorityMaxNodes            = 4096
)

type evaluateAuthorityBinding struct {
	TenantID    string
	PrincipalID string
	WorkspaceID string
	SessionID   string
	Tool        string
	EffectLevel string
}

// validateEvaluateAuthorityArgs keeps the CP's reserved authority envelope
// bound to the authenticated route identity. Ordinary direct-daemon requests
// remain valid without the envelope; when present, it must be the exact
// six-field memory binding. The additive organization-runtime execution
// profile is accepted only for non-memory bindings, and may not be shadowed
// inside source args.
func validateEvaluateAuthorityArgs(args map[string]any, expected evaluateAuthorityBinding) error {
	state := evaluateAuthorityWalkState{}
	return walkEvaluateAuthorityArgs(args, true, expected, &state)
}

type evaluateAuthorityWalkState struct {
	depth int
	nodes int
}

func (s *evaluateAuthorityWalkState) enter(composite bool) error {
	s.nodes++
	if s.nodes > evaluateAuthorityMaxNodes {
		return fmt.Errorf("evaluate args exceed authority validation node limit")
	}
	if composite {
		if s.depth >= evaluateAuthorityMaxDepth {
			return fmt.Errorf("evaluate args exceed authority validation depth limit")
		}
		s.depth++
	}
	return nil
}

func (s *evaluateAuthorityWalkState) leave(composite bool) {
	if composite {
		s.depth--
	}
}

func walkEvaluateAuthorityArgs(value any, topLevel bool, expected evaluateAuthorityBinding, state *evaluateAuthorityWalkState) error {
	composite := false
	switch value.(type) {
	case map[string]any, []any:
		composite = true
	}
	if err := state.enter(composite); err != nil {
		return err
	}
	if composite {
		defer state.leave(true)
	}

	switch typed := value.(type) {
	case map[string]any:
		for key, nested := range typed {
			if key == evaluateAuthorityArgsKey {
				if !topLevel {
					return fmt.Errorf("evaluate args reserved authority key may only appear at the top level")
				}
				binding, ok := nested.(map[string]any)
				if !ok {
					return fmt.Errorf("evaluate args reserved authority binding must be an object")
				}
				if err := validateEvaluateAuthorityBinding(binding, expected); err != nil {
					return err
				}
				continue
			}
			if err := walkEvaluateAuthorityArgs(nested, false, expected, state); err != nil {
				return err
			}
		}
	case []any:
		for _, nested := range typed {
			if err := walkEvaluateAuthorityArgs(nested, false, expected, state); err != nil {
				return err
			}
		}
	}
	return nil
}

func validateEvaluateAuthorityBinding(binding map[string]any, expected evaluateAuthorityBinding) error {
	if strings.TrimSpace(expected.WorkspaceID) == "" {
		return fmt.Errorf("evaluate args reserved authority binding requires an authenticated workspace")
	}
	want := map[string]string{
		"tenant_id":    expected.TenantID,
		"workspace_id": expected.WorkspaceID,
		"principal_id": expected.PrincipalID,
		"session_id":   expected.SessionID,
		"tool":         expected.Tool,
		"effect_level": expected.EffectLevel,
	}
	if profile, present := binding[evaluateAuthorityExecutionProfileKey]; present {
		if profile != "organization-runtime" || isMemoryEvaluateAction(expected.Tool) {
			return fmt.Errorf("evaluate args reserved authority binding has an invalid execution profile")
		}
	}
	expectedFields := len(want)
	if _, present := binding[evaluateAuthorityExecutionProfileKey]; present {
		expectedFields++
	}
	if len(binding) != expectedFields {
		return fmt.Errorf("evaluate args reserved authority binding has unexpected fields")
	}
	for key, wantValue := range want {
		got, ok := binding[key].(string)
		if !ok || got != wantValue {
			return fmt.Errorf("evaluate args reserved authority binding does not match authenticated request")
		}
	}
	return nil
}
