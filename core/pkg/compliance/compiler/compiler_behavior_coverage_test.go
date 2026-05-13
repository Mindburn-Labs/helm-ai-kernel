package compiler

import (
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/compliance/jkg"
)

// ── Parse ───────────────────────────────────────────────────────

func TestParse_EmptyText(t *testing.T) {
	c := NewCompiler()
	_, err := c.Parse("", "MiCA", "Art.1")
	if err == nil {
		t.Error("should reject empty text")
	}
}

func TestParse_ExtractsSubjectTokens(t *testing.T) {
	c := NewCompiler()
	ast, err := c.Parse("Crypto-asset service providers shall report transactions", "MiCA", "Art.67")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if ast.Subject == nil {
		t.Fatal("Subject clause should be extracted")
	}
	found := false
	for _, et := range ast.Subject.EntityTypes {
		if et == "CASP" {
			found = true
		}
	}
	if !found {
		t.Error("should detect CASP entity type")
	}
}

func TestParse_DetectsProhibition(t *testing.T) {
	c := NewCompiler()
	ast, _ := c.Parse("Banks shall not provide services without authorization", "MiCA", "Art.10")
	if ast.Type != jkg.ObligationProhibition {
		t.Errorf("expected PROHIBITION, got %s", ast.Type)
	}
}

func TestParse_DetectsReporting(t *testing.T) {
	c := NewCompiler()
	ast, _ := c.Parse("Issuers must report all transactions above 10000 EUR", "MiCA", "Art.20")
	if ast.Type != jkg.ObligationReporting {
		t.Errorf("expected REPORTING, got %s", ast.Type)
	}
}

func TestParse_ExtractsThreshold(t *testing.T) {
	c := NewCompiler()
	ast, _ := c.Parse("Transactions over 15000 EUR require enhanced due diligence", "AMLD", "Art.11")
	if len(ast.Thresholds) == 0 {
		t.Error("should extract threshold")
	}
}

func TestParse_ExtractsTimeframe(t *testing.T) {
	c := NewCompiler()
	ast, _ := c.Parse("Obliged entities must notify within 24 hours", "MiCA", "Art.5")
	if ast.Timeframe == nil {
		t.Error("should extract timeframe clause")
	}
}

func TestParse_SetsConfidence(t *testing.T) {
	c := NewCompiler()
	ast, _ := c.Parse("Credit institutions shall register with the authority", "MiCA", "Art.3")
	if ast.Confidence <= 0 {
		t.Error("confidence should be positive")
	}
}

// ── Compile ─────────────────────────────────────────────────────

func TestCompile_NilAST(t *testing.T) {
	c := NewCompiler()
	_, err := c.Compile(nil)
	if err == nil {
		t.Error("should reject nil AST")
	}
}

func TestCompile_ProducesFullExpr(t *testing.T) {
	c := NewCompiler()
	ast, _ := c.Parse("CASPs must report transactions over 10000 EUR", "MiCA", "Art.67")
	policy, err := c.Compile(ast)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if policy.FullExpr == "" {
		t.Error("FullExpr should be non-empty")
	}
}

func TestCompile_SetsHash(t *testing.T) {
	c := NewCompiler()
	ast, _ := c.Parse("Investment firms shall register", "MiCA", "Art.2")
	policy, _ := c.Compile(ast)
	if policy.Hash == "" {
		t.Error("policy hash should be set")
	}
}

func TestCompile_SetsPolicyID(t *testing.T) {
	c := NewCompiler()
	ast, _ := c.Parse("Banks must comply", "AMLD", "Art.1")
	policy, _ := c.Compile(ast)
	if policy.PolicyID == "" {
		t.Error("policy ID should be set")
	}
}

// ── CompileFromText ─────────────────────────────────────────────

func TestCompileFromText_EndToEnd(t *testing.T) {
	c := NewCompiler()
	policy, err := c.CompileFromText("CASPs must not process prohibited transactions", "MiCA", "Art.99")
	if err != nil {
		t.Fatalf("CompileFromText: %v", err)
	}
	if policy.RiskLevel != jkg.RiskCritical {
		t.Errorf("expected CRITICAL risk for MiCA prohibition, got %s", policy.RiskLevel)
	}
}

// ── Metrics ─────────────────────────────────────────────────────

func TestGetMetrics_TracksSuccess(t *testing.T) {
	c := NewCompiler()
	_, _ = c.CompileFromText("Entities shall register", "MiCA", "Art.1")
	m := c.GetMetrics()
	if m.SuccessCount < 1 {
		t.Error("success count should increase after compilation")
	}
}

func TestGetMetrics_TracksErrors(t *testing.T) {
	c := NewCompiler()
	_, _ = c.CompileFromText("", "MiCA", "Art.1")
	m := c.GetMetrics()
	if m.ErrorCount < 1 {
		t.Error("error count should increase on parse failure")
	}
}

func TestParse_DetectsPermission(t *testing.T) {
	c := NewCompiler()
	ast, _ := c.Parse("Entities may choose to participate voluntarily", "MiCA", "Art.15")
	if ast.Type != jkg.ObligationPermission {
		t.Errorf("expected PERMISSION, got %s", ast.Type)
	}
}
