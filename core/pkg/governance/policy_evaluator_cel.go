package governance

import (
	"sync"

	"github.com/google/cel-go/cel"
)

// CELPolicyEvaluator retains the environment, program cache and system rule fields.
type CELPolicyEvaluator struct {
	env         *cel.Env
	prgCache    map[string]cel.Program
	mu          sync.RWMutex
	systemRules []string // Hardcoded System Policy for GAP-02
}
