package enforcement

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/compliance/jkg"
)

func TestNewEnforcementEngine(t *testing.T) {
	g := jkg.NewGraphWithDefaults()
	evaluator := NewTestPolicyEvaluator(Permit)
	e := NewEnforcementEngine(g, evaluator, nil)

	require.NotNil(t, e)
	require.NotNil(t, e.graph)
	require.NotNil(t, e.query)
	require.NotNil(t, e.compiler)
	require.NotNil(t, e.evaluator)
	require.NotNil(t, e.metrics)
}

func TestDefaultEnforcementConfig(t *testing.T) {
	c := DefaultEnforcementConfig()

	require.Equal(t, 50, c.MaxConcurrentEvaluations)
	require.Equal(t, 5*time.Second, c.EvaluationTimeout)
	require.True(t, c.CacheEnabled)
}

func TestCheckNilRequest(t *testing.T) {
	g := jkg.NewGraph()
	e := NewEnforcementEngine(g, nil, nil)

	_, err := e.Check(context.Background(), nil)
	require.Error(t, err)
}

func TestCheckEmptyGraph(t *testing.T) {
	g := jkg.NewGraph()
	e := NewEnforcementEngine(g, nil, nil)

	req := &EnforcementRequest{
		EntityID:      "test-entity",
		EntityType:    "CASP",
		Jurisdictions: []jkg.JurisdictionCode{jkg.JurisdictionEU},
	}

	result, err := e.Check(context.Background(), req)
	require.NoError(t, err)
	require.Equal(t, Permit, result.Overall)
	require.Empty(t, result.ByObligation)
}

func TestCheckWithObligations(t *testing.T) {
	g := jkg.NewGraphWithDefaults()
	evaluator := NewTestPolicyEvaluator(Permit)
	e := NewEnforcementEngine(g, evaluator, nil)

	req := &EnforcementRequest{
		EntityID:      "test-casp",
		EntityType:    "crypto_exchange",
		Jurisdictions: []jkg.JurisdictionCode{jkg.JurisdictionEU},
		Frameworks:    []string{"MiCA"},
		Context:       map[string]interface{}{"entity": map[string]string{"type": "CASP"}},
	}

	result, err := e.Check(context.Background(), req)
	require.NoError(t, err)
	require.NotEmpty(t, result.ByObligation)
	require.NotEmpty(t, result.RequestID)
	require.NotEmpty(t, result.GraphVersion)
	require.Greater(t, result.EvaluationTime, time.Duration(0))
}

func TestCheckNonCompliant(t *testing.T) {
	g := jkg.NewGraphWithDefaults()
	evaluator := NewTestPolicyEvaluator(Deny)
	e := NewEnforcementEngine(g, evaluator, nil)

	req := &EnforcementRequest{
		EntityID:      "test-casp",
		EntityType:    "crypto_exchange",
		Jurisdictions: []jkg.JurisdictionCode{jkg.JurisdictionEU},
		Frameworks:    []string{"MiCA"},
	}

	result, err := e.Check(context.Background(), req)
	require.NoError(t, err)
	require.Equal(t, Deny, result.Overall)
	require.Greater(t, result.RiskScore, 0.0)
}

func TestCheckMultiJurisdiction(t *testing.T) {
	g := jkg.NewGraphWithDefaults()
	evaluator := NewTestPolicyEvaluator(Permit)
	e := NewEnforcementEngine(g, evaluator, nil)

	req := &EnforcementRequest{
		EntityID:      "global-entity",
		EntityType:    "financial_institution",
		Jurisdictions: []jkg.JurisdictionCode{jkg.JurisdictionEU, jkg.JurisdictionUS},
	}

	result, err := e.Check(context.Background(), req)
	require.NoError(t, err)

	// Should have results from both jurisdictions
	require.Contains(t, result.ByJurisdiction, jkg.JurisdictionEU)
	require.Contains(t, result.ByJurisdiction, jkg.JurisdictionUS)
}

func TestCheckConflictDetection(t *testing.T) {
	g := jkg.NewGraphWithDefaults()
	evaluator := NewTestPolicyEvaluator(Permit)
	e := NewEnforcementEngine(g, evaluator, nil)

	req := &EnforcementRequest{
		EntityID:      "cross-border-entity",
		EntityType:    "financial_institution",
		Jurisdictions: []jkg.JurisdictionCode{jkg.JurisdictionEU, jkg.JurisdictionUS},
	}

	result, err := e.Check(context.Background(), req)
	require.NoError(t, err)

	// Should detect EU-US conflicts
	require.NotEmpty(t, result.Conflicts)
}

func TestCheckWithoutEvaluator(t *testing.T) {
	g := jkg.NewGraphWithDefaults()
	e := NewEnforcementEngine(g, nil, nil) // No evaluator

	req := &EnforcementRequest{
		EntityID:      "test-entity",
		EntityType:    "CASP",
		Jurisdictions: []jkg.JurisdictionCode{jkg.JurisdictionEU},
		Frameworks:    []string{"MiCA"},
	}

	result, err := e.Check(context.Background(), req)
	require.NoError(t, err)
	// Without evaluator, should default to Permit
	require.Equal(t, Permit, result.Overall)
}

func TestEnforcementMetrics(t *testing.T) {
	g := jkg.NewGraphWithDefaults()
	evaluator := NewTestPolicyEvaluator(Permit)
	e := NewEnforcementEngine(g, evaluator, nil)

	req := &EnforcementRequest{
		EntityID:      "test-entity",
		EntityType:    "CASP",
		Jurisdictions: []jkg.JurisdictionCode{jkg.JurisdictionEU},
	}

	// Run a few checks
	_, _ = e.Check(context.Background(), req)
	_, _ = e.Check(context.Background(), req)

	metrics := e.GetMetrics()
	require.Equal(t, int64(2), metrics.TotalEvaluations)
	require.Greater(t, metrics.AvgEvaluationTime, time.Duration(0))
}

func TestRiskScoreCalculation(t *testing.T) {
	g := jkg.NewGraphWithDefaults()

	// Create evaluator that denies for specific patterns
	evaluator := NewTestPolicyEvaluator(Deny)
	e := NewEnforcementEngine(g, evaluator, nil)

	req := &EnforcementRequest{
		EntityID:      "test-entity",
		EntityType:    "CASP",
		Jurisdictions: []jkg.JurisdictionCode{jkg.JurisdictionEU},
	}

	result, err := e.Check(context.Background(), req)
	require.NoError(t, err)

	// With all obligations non-compliant, risk score should be 1.0
	require.Equal(t, 1.0, result.RiskScore)
}

func TestRefreshGraph(t *testing.T) {
	g1 := jkg.NewGraph()
	e := NewEnforcementEngine(g1, nil, nil)

	hash1 := e.GetGraph().Hash()

	g2 := jkg.NewGraphWithDefaults()
	e.RefreshGraph(g2)

	hash2 := e.GetGraph().Hash()

	require.NotEqual(t, hash1, hash2)
}

func TestCELEvaluator(t *testing.T) {
	evaluator := NewTestPolicyEvaluator(Permit)

	result, err := evaluator.Evaluate(context.Background(), "test_expr", nil)
	require.NoError(t, err)
	require.Equal(t, Permit, result)

	// Set specific result
	evaluator.SetResult("deny_expr", Deny)

	result, err = evaluator.Evaluate(context.Background(), "deny_expr", nil)
	require.NoError(t, err)
	require.Equal(t, Deny, result)
}

func TestJurisdictionResults(t *testing.T) {
	g := jkg.NewGraphWithDefaults()
	evaluator := NewTestPolicyEvaluator(Permit)
	e := NewEnforcementEngine(g, evaluator, nil)

	req := &EnforcementRequest{
		EntityID:      "test-entity",
		EntityType:    "CASP",
		Jurisdictions: []jkg.JurisdictionCode{jkg.JurisdictionEU},
		Frameworks:    []string{"MiCA"},
	}

	result, err := e.Check(context.Background(), req)
	require.NoError(t, err)

	jr := result.ByJurisdiction[jkg.JurisdictionEU]
	require.NotNil(t, jr)
	require.Greater(t, jr.TotalObligations, 0)
	require.Greater(t, jr.Compliant, 0)
}

func TestRequestIDGeneration(t *testing.T) {
	g := jkg.NewGraph()
	e := NewEnforcementEngine(g, nil, nil)

	req := &EnforcementRequest{
		EntityID:      "test-entity",
		Jurisdictions: []jkg.JurisdictionCode{jkg.JurisdictionEU},
	}

	result, _ := e.Check(context.Background(), req)
	require.NotEmpty(t, result.RequestID)
	require.Len(t, result.RequestID, 12)
}

func TestRiskWeight(t *testing.T) {
	tests := []struct {
		level    jkg.RiskLevel
		expected float64
	}{
		{jkg.RiskCritical, 4.0},
		{jkg.RiskHigh, 3.0},
		{jkg.RiskMedium, 2.0},
		{jkg.RiskLow, 1.0},
		{jkg.RiskInfo, 0.5},
	}

	for _, tt := range tests {
		require.Equal(t, tt.expected, riskWeight(tt.level))
	}
}
