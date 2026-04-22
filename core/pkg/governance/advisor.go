package governance

import (
	"context"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/artifacts"
)

// Advisor represents a module that can provide governance advice (artifacts).
type Advisor interface {
	// Advise analyzes the intent and context, and returns an ArtifactEnvelope
	// containing the specific evidence (policy, alert, prediction).
	Advise(ctx context.Context, intent string, contextData map[string]any) (*artifacts.ArtifactEnvelope, error)

	// Name returns the identifier of this advisor (e.g. "policy.inductor")
	Name() string
}
