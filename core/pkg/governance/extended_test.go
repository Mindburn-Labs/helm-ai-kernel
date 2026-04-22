package governance

import (
	"strings"
	"testing"
)

// ─── 1: CEL validator rejects now() ───────────────────────────

func TestExt_CELValidatorRejectsNow(t *testing.T) {
	v := NewCELDPValidator()
	issues := v.ValidateExpression("now() > 100")
	if len(issues) == 0 {
		t.Fatal("expected issue for now()")
	}
}

// ─── 2: CEL validator rejects timestamp() ─────────────────────

func TestExt_CELValidatorRejectsTimestamp(t *testing.T) {
	v := NewCELDPValidator()
	issues := v.ValidateExpression("timestamp('2021-01-01')")
	if len(issues) == 0 {
		t.Fatal("expected issue for timestamp()")
	}
}

// ─── 3: CEL validator rejects random() ────────────────────────

func TestExt_CELValidatorRejectsRandom(t *testing.T) {
	v := NewCELDPValidator()
	issues := v.ValidateExpression("random() > 0.5")
	if len(issues) == 0 {
		t.Fatal("expected issue for random()")
	}
}

// ─── 4: CEL validator rejects double type ─────────────────────

func TestExt_CELValidatorRejectsDouble(t *testing.T) {
	v := NewCELDPValidator()
	issues := v.ValidateExpression("double(x) > 1")
	found := false
	for _, issue := range issues {
		if issue.Type == "banned_type" && issue.Name == "double" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected banned_type issue for double")
	}
}

// ─── 5: CEL validator allows simple comparison ────────────────

func TestExt_CELValidatorAllowsSimple(t *testing.T) {
	v := NewCELDPValidator()
	issues := v.ValidateExpression("x > 5 && y < 10")
	if len(issues) != 0 {
		t.Fatalf("expected no issues, got %v", issues)
	}
}

// ─── 6: CEL validator rejects dyn() ──────────────────────────

func TestExt_CELValidatorRejectsDyn(t *testing.T) {
	v := NewCELDPValidator()
	issues := v.ValidateExpression("dyn(x)")
	if len(issues) == 0 {
		t.Fatal("expected issue for dyn()")
	}
}

// ─── 7: CEL ValidateAndAnalyze returns valid=false on issues ──

func TestExt_CELValidateAndAnalyzeInvalid(t *testing.T) {
	v := NewCELDPValidator()
	info := v.ValidateAndAnalyze("uuid() == 'abc'")
	if info.Valid {
		t.Fatal("expression with uuid() should be invalid")
	}
	if info.ProfileID != CELDPProfileID {
		t.Fatalf("expected profile %s, got %s", CELDPProfileID, info.ProfileID)
	}
}

// ─── 8: CEL ValidateAndAnalyze returns valid=true for clean ──

func TestExt_CELValidateAndAnalyzeValid(t *testing.T) {
	v := NewCELDPValidator()
	info := v.ValidateAndAnalyze("a + b == 10")
	if !info.Valid {
		t.Fatal("simple arithmetic should be valid")
	}
}

// ─── 9: HashErrorMessage deterministic ────────────────────────

func TestExt_HashErrorMessageDeterministic(t *testing.T) {
	h1 := HashErrorMessage("  Error occurred  ")
	h2 := HashErrorMessage("error occurred")
	if h1 != h2 {
		t.Fatal("normalized messages should produce same hash")
	}
}

// ─── 10: HashErrorMessage case insensitive ────────────────────

func TestExt_HashErrorMessageCaseInsensitive(t *testing.T) {
	h1 := HashErrorMessage("ERROR OCCURRED")
	h2 := HashErrorMessage("error occurred")
	if h1 != h2 {
		t.Fatal("case should not affect hash")
	}
}

// ─── 11: ComputeTraceHash empty returns empty ─────────────────

func TestExt_ComputeTraceHashEmpty(t *testing.T) {
	if ComputeTraceHash(nil) != "" {
		t.Fatal("empty trace should return empty hash")
	}
}

// ─── 12: ComputeTraceHash deterministic ───────────────────────

func TestExt_ComputeTraceHashDeterministic(t *testing.T) {
	entries := []CELDPTraceEntry{{Step: 1, Expression: "x > 1", ResultHash: "abc"}}
	h1 := ComputeTraceHash(entries)
	h2 := ComputeTraceHash(entries)
	if h1 != h2 {
		t.Fatal("same entries should produce same hash")
	}
}

// ─── 13: NewCELDPError populates hash ─────────────────────────

func TestExt_NewCELDPErrorHash(t *testing.T) {
	e := NewCELDPError(CELDPErrorDivZero, "division by zero", nil)
	if e.MessageHash == "" {
		t.Fatal("message hash should be populated")
	}
	if e.Code != CELDPErrorDivZero {
		t.Fatalf("expected DIV_ZERO, got %s", e.Code)
	}
}

// ─── 14: Jurisdiction wildcard matches any region ─────────────

func TestExt_JurisdictionWildcardMatchesAny(t *testing.T) {
	r := NewJurisdictionResolver()
	r.AddRule(JurisdictionRule{RuleID: "r1", LegalRegime: "GLOBAL", Region: "*", Priority: 1})
	ctx, err := r.Resolve("acme", "", "", "random-region-42")
	if err != nil || ctx.LegalRegime != "GLOBAL" {
		t.Fatalf("wildcard should match, err=%v regime=%s", err, ctx.LegalRegime)
	}
}

// ─── 15: Jurisdiction conflict escalation empties regime ──────

func TestExt_JurisdictionConflictEscalationEmptiesRegime(t *testing.T) {
	r := NewJurisdictionResolver()
	r.AddRule(JurisdictionRule{RuleID: "r1", LegalRegime: "EU/GDPR", Region: "eu", Priority: 5})
	r.AddRule(JurisdictionRule{RuleID: "r2", LegalRegime: "UK/FCA", Region: "eu", Priority: 5})
	ctx, _ := r.Resolve("acme", "", "", "eu")
	if ctx.LegalRegime != "" {
		t.Fatalf("equal-priority conflict should empty regime, got %s", ctx.LegalRegime)
	}
}

// ─── 16: Jurisdiction priority resolution ─────────────────────

func TestExt_JurisdictionHigherPriorityWins(t *testing.T) {
	r := NewJurisdictionResolver()
	r.AddRule(JurisdictionRule{RuleID: "r1", LegalRegime: "US/CCPA", Region: "us", Priority: 1})
	r.AddRule(JurisdictionRule{RuleID: "r2", LegalRegime: "US/SOX", Region: "us", Priority: 10})
	ctx, _ := r.Resolve("acme", "", "", "us")
	if ctx.LegalRegime != "US/SOX" {
		t.Fatalf("higher priority should win, got %s", ctx.LegalRegime)
	}
}

// ─── 17: Jurisdiction missing entity returns error ────────────

func TestExt_JurisdictionMissingEntity(t *testing.T) {
	r := NewJurisdictionResolver()
	r.AddRule(JurisdictionRule{RuleID: "r1", LegalRegime: "X", Region: "y"})
	_, err := r.Resolve("", "", "", "y")
	if err == nil {
		t.Fatal("expected error for empty entity")
	}
}

// ─── 18: Jurisdiction missing region returns error ────────────

func TestExt_JurisdictionMissingRegion(t *testing.T) {
	r := NewJurisdictionResolver()
	_, err := r.Resolve("acme", "", "", "")
	if err == nil {
		t.Fatal("expected error for empty region")
	}
}

// ─── 19: Jurisdiction content hash populated ──────────────────

func TestExt_JurisdictionContentHash(t *testing.T) {
	r := NewJurisdictionResolver()
	r.AddRule(JurisdictionRule{RuleID: "r1", LegalRegime: "EU/GDPR", Region: "eu", Priority: 1})
	ctx, _ := r.Resolve("acme", "", "", "eu")
	if !strings.HasPrefix(ctx.ContentHash, "sha256:") {
		t.Fatalf("expected sha256: prefix, got %s", ctx.ContentHash)
	}
}

// ─── 20: Arbitrate STRICTEST_WINS deny trumps allow ───────────

func TestExt_ArbitrateStrictestDenyWins(t *testing.T) {
	inputs := []ArbitrationInput{
		{RuleID: "r1", Decision: "ALLOW", Priority: 1},
		{RuleID: "r2", Decision: "DENY", Priority: 1},
	}
	result := Arbitrate(inputs, StrategyStrictest)
	if result.Resolution != "DENY" {
		t.Fatalf("STRICTEST should pick DENY, got %s", result.Resolution)
	}
}

// ─── 21: Arbitrate single input returns nil ───────────────────

func TestExt_ArbitrateSingleInput(t *testing.T) {
	inputs := []ArbitrationInput{{RuleID: "r1", Decision: "ALLOW"}}
	result := Arbitrate(inputs, StrategyStrictest)
	if result != nil {
		t.Fatal("single input should return nil (no conflict)")
	}
}

// ─── 22: Arbitrate ESCALATE strategy falls through to strictest ─

func TestExt_ArbitrateEscalateFallsToStrictest(t *testing.T) {
	inputs := []ArbitrationInput{
		{RuleID: "r1", Decision: "ALLOW"},
		{RuleID: "r2", Decision: "DENY"},
	}
	// StrategyEscalate is not implemented — falls to default (strictest)
	result := Arbitrate(inputs, StrategyEscalate)
	if result.Resolution != "DENY" {
		t.Fatalf("expected DENY (strictest fallback), got %s", result.Resolution)
	}
}

// ─── 23: CEL validator multiple banned functions ──────────────

func TestExt_CELMultipleBannedFunctions(t *testing.T) {
	v := NewCELDPValidator()
	issues := v.ValidateExpression("now() + duration('1h')")
	if len(issues) < 2 {
		t.Fatalf("expected at least 2 issues, got %d", len(issues))
	}
}

// ─── 24: DecisionEngine Evaluate rejects E4 action ───────────

func TestExt_DecisionEngineRejectsE4(t *testing.T) {
	de, err := NewDecisionEngine(nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = de.Evaluate(nil, "intent-1", []byte(`{"action":"dangerous"}`))
	// Unknown action defaults to E3 without allowlist → policy violation
	if err == nil {
		t.Fatal("expected error for unknown E3 action not in allowlist")
	}
}

// ─── 25: Jurisdiction conflict records created ────────────────

func TestExt_JurisdictionConflictRecordsCreated(t *testing.T) {
	r := NewJurisdictionResolver()
	r.AddRule(JurisdictionRule{RuleID: "r1", LegalRegime: "A", Region: "x", Priority: 1})
	r.AddRule(JurisdictionRule{RuleID: "r2", LegalRegime: "B", Region: "x", Priority: 1})
	ctx, _ := r.Resolve("acme", "", "", "x")
	if len(ctx.Conflicts) == 0 {
		t.Fatal("expected conflict records for different regimes")
	}
}
