package compiler

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/compliance/jkg"
)

func TestNewCompiler(t *testing.T) {
	c := NewCompiler()
	require.NotNil(t, c)
	require.NotNil(t, c.patterns)
	require.NotNil(t, c.entityMap)
	require.NotNil(t, c.metrics)
}

func TestParseMiCAObligation(t *testing.T) {
	c := NewCompiler()

	text := `Crypto-asset service providers shall obtain authorization from the competent authority 
		before providing crypto-asset services. The authorization shall be subject to conditions 
		set out in Article 63.`

	ast, err := c.Parse(text, "MiCA", "Art. 59")
	require.NoError(t, err)
	require.NotNil(t, ast)
	require.Equal(t, "MiCA", ast.Framework)
	require.Equal(t, "Art. 59", ast.ArticleRef)
	require.NotEmpty(t, ast.ObligationID)
	require.NotEmpty(t, ast.Tokens)

	// Should detect CASP subject
	require.NotNil(t, ast.Subject)
	require.Contains(t, ast.Subject.EntityTypes, "CASP")
}

func TestParseProhibitionObligation(t *testing.T) {
	c := NewCompiler()

	text := `AI providers shall not place on the market or put into service AI systems that 
		deploy subliminal techniques or purposefully manipulative techniques.`

	ast, err := c.Parse(text, "EU AI Act", "Art. 5")
	require.NoError(t, err)
	require.Equal(t, jkg.ObligationProhibition, ast.Type)
}

func TestParseReportingObligation(t *testing.T) {
	c := NewCompiler()

	text := `Financial institutions must report suspicious transactions to FinCEN 
		within 30 days of detection.`

	ast, err := c.Parse(text, "BSA", "31 CFR 1020.320")
	require.NoError(t, err)
	require.Equal(t, jkg.ObligationReporting, ast.Type)

	// Should detect timeframe
	require.NotNil(t, ast.Timeframe)
	require.NotEmpty(t, ast.Timeframe.CELExpr)
}

func TestParseThreshold(t *testing.T) {
	c := NewCompiler()

	text := `Obliged entities shall apply enhanced customer due diligence for 
		transactions exceeding €15,000 or when there is a suspicion of money laundering.`

	ast, err := c.Parse(text, "AMLD6", "Art. 18")
	require.NoError(t, err)
	require.NotEmpty(t, ast.Thresholds)
	require.Equal(t, float64(15000), ast.Thresholds[0].Value)
}

func TestParseEmptyText(t *testing.T) {
	c := NewCompiler()

	_, err := c.Parse("", "MiCA", "Art. 1")
	require.Error(t, err)
}

func TestCompilePolicy(t *testing.T) {
	c := NewCompiler()

	text := `Crypto-asset service providers shall maintain adequate capital reserves 
		of no less than €150,000 at all times.`

	ast, err := c.Parse(text, "MiCA", "Art. 67")
	require.NoError(t, err)

	policy, err := c.Compile(ast)
	require.NoError(t, err)
	require.NotNil(t, policy)
	require.NotEmpty(t, policy.PolicyID)
	require.NotEmpty(t, policy.SubjectExpr)
	require.NotEmpty(t, policy.FullExpr)
	require.NotEmpty(t, policy.Hash)
	require.Equal(t, 1, policy.Version)
}

func TestCompileFromText(t *testing.T) {
	c := NewCompiler()

	text := `Credit institutions must report all cash transactions over $10,000 
		to the appropriate authority within 15 days.`

	policy, err := c.CompileFromText(text, "BSA", "31 CFR 1010.311")
	require.NoError(t, err)
	require.NotNil(t, policy)
	require.Equal(t, "BSA", policy.Framework)
	require.Greater(t, policy.Confidence, 0.0)
}

func TestCompileNilAST(t *testing.T) {
	c := NewCompiler()

	_, err := c.Compile(nil)
	require.Error(t, err)
}

func TestRiskLevelAssessment(t *testing.T) {
	c := NewCompiler()

	tests := []struct {
		text      string
		framework string
		expected  jkg.RiskLevel
	}{
		{
			text:      "AI providers shall not deploy manipulative systems",
			framework: "EU AI Act",
			expected:  jkg.RiskCritical, // Prohibition + high-risk framework
		},
		{
			text:      "CASP shall maintain records",
			framework: "MiCA",
			expected:  jkg.RiskHigh,
		},
		{
			text:      "Entities may apply simplified due diligence",
			framework: "Local Regulation",
			expected:  jkg.RiskMedium,
		},
	}

	for _, tt := range tests {
		ast, _ := c.Parse(tt.text, tt.framework, "Art. 1")
		policy, err := c.Compile(ast)
		require.NoError(t, err)
		require.Equal(t, tt.expected, policy.RiskLevel, "failed for: %s", tt.text)
	}
}

func TestEntityMapping(t *testing.T) {
	c := NewCompiler()

	tests := []struct {
		text     string
		expected string
	}{
		{"Crypto-asset service providers shall...", "CASP"},
		{"Credit institutions must...", "CREDIT_INSTITUTION"},
		{"E-money institutions shall...", "EMI"},
		{"Investment firms must...", "INVESTMENT_FIRM"},
		{"AI system providers shall...", "AI_PROVIDER"},
	}

	for _, tt := range tests {
		ast, _ := c.Parse(tt.text, "Test", "Art. 1")
		require.NotNil(t, ast.Subject, "failed for: %s", tt.text)
		require.Contains(t, ast.Subject.EntityTypes, tt.expected, "failed for: %s", tt.text)
	}
}

func TestTimeframeExtraction(t *testing.T) {
	c := NewCompiler()

	tests := []struct {
		text    string
		hasTime bool
	}{
		{"Report within 30 days of discovery", true},
		{"Submit immediately upon detection", true},
		{"Provide ongoing monitoring", true},
		{"Maintain records", false},
	}

	for _, tt := range tests {
		ast, _ := c.Parse(tt.text, "Test", "Art. 1")
		if tt.hasTime {
			require.NotNil(t, ast.Timeframe, "expected timeframe for: %s", tt.text)
		}
	}
}

func TestConfidenceCalculation(t *testing.T) {
	c := NewCompiler()

	// Rich text with multiple elements should have higher confidence
	richText := `Crypto-asset service providers shall report suspicious transactions 
		exceeding €10,000 to the competent authority within 24 hours.`

	// Sparse text with few elements
	sparseText := "Entities must comply."

	richAST, _ := c.Parse(richText, "MiCA", "Art. 1")
	sparseAST, _ := c.Parse(sparseText, "MiCA", "Art. 1")

	require.Greater(t, richAST.Confidence, sparseAST.Confidence)
}

func TestCompilerMetrics(t *testing.T) {
	c := NewCompiler()

	// Compile a few policies
	_, _ = c.CompileFromText("CASP shall obtain authorization", "MiCA", "Art. 59")
	_, _ = c.CompileFromText("Banks must report CTRs", "BSA", "31 CFR 1010")
	_, _ = c.CompileFromText("", "Invalid", "Art. 0") // Should fail

	metrics := c.GetMetrics()
	require.Equal(t, int64(3), metrics.TotalCompiled)
	require.Equal(t, int64(2), metrics.SuccessCount)
	require.Equal(t, int64(1), metrics.ErrorCount)
	require.Greater(t, metrics.AvgConfidence, 0.0)
	require.Equal(t, int64(1), metrics.ByFramework["MiCA"])
	require.Equal(t, int64(1), metrics.ByFramework["BSA"])
}

func TestGeneratedCELExpressions(t *testing.T) {
	c := NewCompiler()

	text := `Obliged entities shall apply customer due diligence when 
		establishing a business relationship.`

	policy, err := c.CompileFromText(text, "AMLD6", "Art. 14")
	require.NoError(t, err)

	// Check that expressions are valid CEL-like syntax
	require.Contains(t, policy.SubjectExpr, "entity.type")
	require.NotEmpty(t, policy.FullExpr)
}

func TestHashDeterminism(t *testing.T) {
	c := NewCompiler()

	text := "CASP shall maintain records for 5 years."

	policy1, _ := c.CompileFromText(text, "MiCA", "Art. 68")
	policy2, _ := c.CompileFromText(text, "MiCA", "Art. 68")

	require.Equal(t, policy1.Hash, policy2.Hash)
	require.Len(t, policy1.Hash, 16)
}

func TestFilterTokens(t *testing.T) {
	tokens := []*Token{
		{Type: TokenSubject, Value: "CASP"},
		{Type: TokenThreshold, Value: "10000"},
		{Type: TokenSubject, Value: "Bank"},
	}

	subjects := filterTokens(tokens, TokenSubject)
	require.Len(t, subjects, 2)

	thresholds := filterTokens(tokens, TokenThreshold)
	require.Len(t, thresholds, 1)
}

func TestExtractNumber(t *testing.T) {
	tests := []struct {
		input    string
		expected float64
	}{
		{"over 10,000 EUR", 10000},
		{"€15,000,000", 15000000},
		{"$500.50", 500.50},
		{"no numbers here", 0},
	}

	for _, tt := range tests {
		result := extractNumber(tt.input)
		require.Equal(t, tt.expected, result, "failed for: %s", tt.input)
	}
}

func TestArticleReferenceExtraction(t *testing.T) {
	c := NewCompiler()

	text := `As set out in Article 59(2), crypto-asset service providers 
		shall comply with the requirements of Regulation (EU) 2023/1114.`

	ast, _ := c.Parse(text, "MiCA", "Art. 59")

	// Should have reference tokens
	refs := filterTokens(ast.Tokens, TokenReference)
	require.NotEmpty(t, refs)
}
