package governance

import (
	"sync"

	"github.com/google/cel-go/cel"
)

// CELPolicyEvaluator implements PolicyEvaluator using CEL with Caching and System Policy.
type CELPolicyEvaluator struct {
	env         *cel.Env
	prgCache    map[string]cel.Program
	mu          sync.RWMutex
	systemRules []string // Hardcoded System Policy for GAP-02
}
