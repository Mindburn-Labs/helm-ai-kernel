package governance

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
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

func TestNewSwarmPDP(t *testing.T) {
	mockPDP := NewMockPDP("v1.0")
	swarm := NewSwarmPDP(mockPDP, nil)

	require.NotNil(t, swarm)
	require.Equal(t, "v1.0", swarm.PolicyVersion())
	require.NotNil(t, swarm.GetMetrics())
}

func TestSwarmPDP_SingleEvaluate(t *testing.T) {
	mockPDP := NewMockPDP("v1.0")
	swarm := NewSwarmPDP(mockPDP, nil)

	req := PDPRequest{
		RequestID: "req-1",
		Effect: EffectDescriptor{
			EffectID:   "effect-1",
			EffectType: "authorize",
		},
	}

	resp, err := swarm.Evaluate(context.Background(), req)
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.Equal(t, DecisionAllow, resp.Decision)
}

func TestSwarmPDP_BatchEvaluate(t *testing.T) {
	mockPDP := NewMockPDP("v1.0")
	swarm := NewSwarmPDP(mockPDP, nil)

	requests := []PDPRequest{
		{RequestID: "req-1", Effect: EffectDescriptor{EffectType: "authorize"}},
		{RequestID: "req-2", Effect: EffectDescriptor{EffectType: "transfer"}},
		{RequestID: "req-3", Effect: EffectDescriptor{EffectType: "trade"}},
		{RequestID: "req-4", Effect: EffectDescriptor{EffectType: "log"}},
	}

	result, err := swarm.EvaluateBatch(context.Background(), requests)
	require.NoError(t, err)
	require.NotNil(t, result)
	require.Len(t, result.Responses, 4)
	require.Greater(t, result.ParallelLanes, 0)
}

func TestSwarmPDP_DomainDecomposition(t *testing.T) {
	mockPDP := NewMockPDP("v1.0")
	config := &SwarmPDPConfig{
		MaxParallelPDPs:     16,
		EnableMetrics:       true,
		DomainDecomposition: true,
	}
	swarm := NewSwarmPDP(mockPDP, config)

	// Create requests across different domains
	requests := []PDPRequest{
		{RequestID: "auth-1", Effect: EffectDescriptor{EffectType: "authorize"}},
		{RequestID: "auth-2", Effect: EffectDescriptor{EffectType: "grant"}},
		{RequestID: "comp-1", Effect: EffectDescriptor{EffectType: "transfer"}},
		{RequestID: "risk-1", Effect: EffectDescriptor{EffectType: "trade"}},
		{RequestID: "audit-1", Effect: EffectDescriptor{EffectType: "log"}},
	}

	result, err := swarm.EvaluateBatch(context.Background(), requests)
	require.NoError(t, err)
	require.Equal(t, 4, result.ParallelLanes) // 4 domains
	require.Len(t, result.Responses, 5)
}

func TestSwarmPDP_EmptyBatch(t *testing.T) {
	mockPDP := NewMockPDP("v1.0")
	swarm := NewSwarmPDP(mockPDP, nil)

	result, err := swarm.EvaluateBatch(context.Background(), []PDPRequest{})
	require.NoError(t, err)
	require.NotNil(t, result)
	require.Len(t, result.Responses, 0)
	require.Equal(t, 0, result.ParallelLanes)
}

func TestSwarmPDP_MergeDecisions_StrictMode(t *testing.T) {
	mockPDP := NewMockPDP("v1.0")
	config := DefaultSwarmPDPConfig()
	config.StrictMerge = true
	swarm := NewSwarmPDP(mockPDP, config)

	tests := []struct {
		name      string
		decisions []Decision
		expected  Decision
	}{
		{"empty", []Decision{}, DecisionDeny},
		{"single allow", []Decision{DecisionAllow}, DecisionAllow},
		{"single deny", []Decision{DecisionDeny}, DecisionDeny},
		{"deny wins", []Decision{DecisionAllow, DecisionDeny, DecisionAllow}, DecisionDeny},
		{"require approval", []Decision{DecisionAllow, DecisionRequireApproval}, DecisionRequireApproval},
		{"deny over require", []Decision{DecisionRequireApproval, DecisionDeny}, DecisionDeny},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := swarm.MergeDecisions(tt.decisions)
			require.Equal(t, tt.expected, result)
		})
	}
}

func TestSwarmPDP_Metrics(t *testing.T) {
	mockPDP := NewMockPDP("v1.0")
	swarm := NewSwarmPDP(mockPDP, nil)

	// Run two batches
	requests := []PDPRequest{
		{RequestID: "req-1", Effect: EffectDescriptor{EffectType: "authorize"}},
		{RequestID: "req-2", Effect: EffectDescriptor{EffectType: "transfer"}},
	}

	_, err := swarm.EvaluateBatch(context.Background(), requests)
	require.NoError(t, err)

	_, err = swarm.EvaluateBatch(context.Background(), requests)
	require.NoError(t, err)

	metrics := swarm.GetMetrics()
	require.Equal(t, 2, metrics.TotalBatches)
	require.Equal(t, 4, metrics.TotalRequests)
	require.Greater(t, metrics.TotalCriticalSteps, 0)
}

func TestSwarmPDP_Hash(t *testing.T) {
	mockPDP := NewMockPDP("v1.0")
	swarm := NewSwarmPDP(mockPDP, nil)

	hash1 := swarm.Hash()
	require.NotEmpty(t, hash1)

	// Hash should be deterministic
	hash2 := swarm.Hash()
	require.Equal(t, hash1, hash2)

	// After batch, hash should change
	requests := []PDPRequest{
		{RequestID: "req-1", Effect: EffectDescriptor{EffectType: "authorize"}},
	}
	_, _ = swarm.EvaluateBatch(context.Background(), requests)

	hash3 := swarm.Hash()
	require.NotEqual(t, hash1, hash3)
}

func TestSwarmPDP_ParallelPerformance(t *testing.T) {
	// Test that parallel is faster than sequential
	mockPDP := NewMockPDP("v1.0")
	mockPDP.SetDelay(10 * time.Millisecond)

	swarm := NewSwarmPDP(mockPDP, DefaultSwarmPDPConfig())

	requests := make([]PDPRequest, 10)
	for i := 0; i < 10; i++ {
		requests[i] = PDPRequest{
			RequestID: "req-" + string(rune('0'+i)),
			Effect:    EffectDescriptor{EffectType: "authorize"},
		}
	}

	start := time.Now()
	result, err := swarm.EvaluateBatch(context.Background(), requests)
	elapsed := time.Since(start)

	require.NoError(t, err)
	require.Len(t, result.Responses, 10)

	// With 16 parallel workers and 10ms delay per request,
	// parallel should complete in ~10ms (one batch), not 100ms (sequential)
	require.Less(t, elapsed, 100*time.Millisecond, "Parallel should be faster than sequential")
}

func TestSwarmPDP_NoDomainDecomposition(t *testing.T) {
	mockPDP := NewMockPDP("v1.0")
	config := &SwarmPDPConfig{
		MaxParallelPDPs:     16,
		EnableMetrics:       true,
		DomainDecomposition: false, // Disabled
	}
	swarm := NewSwarmPDP(mockPDP, config)

	requests := []PDPRequest{
		{RequestID: "req-1", Effect: EffectDescriptor{EffectType: "authorize"}},
		{RequestID: "req-2", Effect: EffectDescriptor{EffectType: "transfer"}},
		{RequestID: "req-3", Effect: EffectDescriptor{EffectType: "trade"}},
	}

	result, err := swarm.EvaluateBatch(context.Background(), requests)
	require.NoError(t, err)
	require.Equal(t, 1, result.ParallelLanes) // All in one group
}

func TestClassifyDomain(t *testing.T) {
	tests := []struct {
		effectType string
		expected   PolicyDomain
	}{
		{"authorize", DomainAuthorization},
		{"grant", DomainAuthorization},
		{"revoke", DomainAuthorization},
		{"delegate", DomainAuthorization},
		{"transfer", DomainCompliance},
		{"payment", DomainCompliance},
		{"settlement", DomainCompliance},
		{"trade", DomainRisk},
		{"position", DomainRisk},
		{"exposure", DomainRisk},
		{"log", DomainAudit},
		{"report", DomainAudit},
		{"archive", DomainAudit},
		{"unknown", DomainGeneral},
	}

	for _, tt := range tests {
		t.Run(tt.effectType, func(t *testing.T) {
			result := classifyDomain(tt.effectType)
			require.Equal(t, tt.expected, result)
		})
	}
}

func TestDefaultSwarmPDPConfig(t *testing.T) {
	config := DefaultSwarmPDPConfig()
	require.Equal(t, 16, config.MaxParallelPDPs)
	require.True(t, config.EnableMetrics)
	require.True(t, config.DomainDecomposition)
	require.True(t, config.StrictMerge)
}
