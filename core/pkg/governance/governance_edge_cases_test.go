package governance

import (
	"context"
)

// ── CEL Deterministic Validator Tests ────────────────────────────

type mockPDP struct {
	version string
}

func (m *mockPDP) Evaluate(_ context.Context, req PDPRequest) (*PDPResponse, error) {
	return &PDPResponse{Decision: DecisionAllow, DecisionID: req.RequestID, PolicyVersion: m.version}, nil
}
func (m *mockPDP) PolicyVersion() string { return m.version }
