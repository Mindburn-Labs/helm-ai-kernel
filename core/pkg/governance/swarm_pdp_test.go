package governance

import (
	"context"

	"time"
)

// MockPDP implements PolicyDecisionPoint for testing.
type MockPDP struct {
	version   string
	responses map[string]*PDPResponse
	delay     time.Duration
}

func NewMockPDP(version string) *MockPDP {
	return &MockPDP{
		version:   version,
		responses: make(map[string]*PDPResponse),
		delay:     0,
	}
}

func (m *MockPDP) Evaluate(ctx context.Context, req PDPRequest) (*PDPResponse, error) {
	if m.delay > 0 {
		time.Sleep(m.delay)
	}

	// Check for pre-configured response
	if resp, ok := m.responses[req.RequestID]; ok {
		return resp, nil
	}

	// Default ALLOW response
	return &PDPResponse{
		Decision:      DecisionAllow,
		DecisionID:    "decision-" + req.RequestID,
		PolicyVersion: m.version,
		IssuedAt:      time.Now(),
		Trace: DecisionTrace{
			RulesFired: []string{"default-allow"},
		},
	}, nil
}

func (m *MockPDP) PolicyVersion() string {
	return m.version
}

func (m *MockPDP) SetResponse(requestID string, resp *PDPResponse) {
	m.responses[requestID] = resp
}

func (m *MockPDP) SetDelay(d time.Duration) {
	m.delay = d
}
