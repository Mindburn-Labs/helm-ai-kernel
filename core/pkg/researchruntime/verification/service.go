package verification

import (
	"context"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/researchruntime"
)

// Config controls the thresholds applied during verification.
type Config struct {
	MinPrimarySourceCount     int
	MinEditorScore            float64
	RequireAllSourcesVerified bool
}

// DefaultConfig returns production-safe defaults.
func DefaultConfig() Config {
	return Config{
		MinPrimarySourceCount:     2,
		MinEditorScore:            0.7,
		RequireAllSourcesVerified: true,
	}
}

// VerifyInput bundles everything the service needs to make a decision.
type VerifyInput struct {
	Draft       *researchruntime.DraftManifest
	Sources     []researchruntime.SourceSnapshot
	EditorScore float64
	Issues      []string // diagnostic notes from the editor agent
}

// VerifyResult is the gate decision returned to the caller.
type VerifyResult struct {
	Verdict     string   // "allow", "deny", "require_override"
	ReasonCodes []string // machine-readable error codes; nil on allow
	Score       float64  // echo of the editor score for logging
}

// Service runs source, citation, and score checks against a draft.
type Service struct {
	config Config
}

// New constructs a verification Service with the given Config.
func New(config Config) *Service {
	return &Service{config: config}
}

// Verify runs all checks and returns a VerifyResult. It never returns nil.
func (s *Service) Verify(_ context.Context, input *VerifyInput) *VerifyResult {
	var codes []string
	codes = append(codes, s.checkSourceCount(input.Sources)...)
	codes = append(codes, s.checkSourcesVerified(input.Sources)...)
	codes = append(codes, s.checkEditorScore(input.EditorScore)...)
	codes = append(codes, s.evalPolicy(input)...)

	if len(codes) > 0 {
		return &VerifyResult{Verdict: "deny", ReasonCodes: codes, Score: input.EditorScore}
	}
	return &VerifyResult{Verdict: "allow", Score: input.EditorScore}
}
