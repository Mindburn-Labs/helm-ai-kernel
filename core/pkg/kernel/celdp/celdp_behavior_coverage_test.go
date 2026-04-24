package celdp

import (
	"testing"
)

// ── Validator ───────────────────────────────────────────────────

func TestValidator_ValidExpression(t *testing.T) {
	v, err := NewValidator()
	if err != nil {
		t.Fatalf("NewValidator: %v", err)
	}
	res, err := v.Validate("1 + 2")
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if !res.Valid {
		t.Error("simple arithmetic should be valid")
	}
}

func TestValidator_ForbidsFloatLiterals(t *testing.T) {
	v, _ := NewValidator()
	res, err := v.Validate("3.14")
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if res.Valid {
		t.Error("float literals should be forbidden")
	}
}

func TestValidator_ForbidsNow(t *testing.T) {
	v, _ := NewValidator()
	res, err := v.Validate("now()")
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if res.Valid {
		t.Error("now() should be forbidden")
	}
}

func TestValidator_ForbidsMapIteration(t *testing.T) {
	v, _ := NewValidator()
	res, _ := v.Validate(`{"a": 1}.keys()`)
	if res.Valid {
		t.Error("map keys() should be forbidden due to non-determinism")
	}
}

func TestValidator_AllowsBooleanExpr(t *testing.T) {
	v, _ := NewValidator()
	res, _ := v.Validate("true && false")
	if !res.Valid {
		t.Error("boolean expressions should be valid")
	}
}

// ── Evaluator ───────────────────────────────────────────────────

func TestEvaluator_SimpleArithmetic(t *testing.T) {
	e, err := NewEvaluator()
	if err != nil {
		t.Fatalf("NewEvaluator: %v", err)
	}
	result, err := e.Evaluate("1 + 2", map[string]any{"input": map[string]any{}})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if result.Error != nil {
		t.Fatalf("unexpected CEL error: %s", result.Error.Message)
	}
	if result.Value != int64(3) {
		t.Errorf("expected 3, got %v", result.Value)
	}
}

func TestEvaluator_BooleanResult(t *testing.T) {
	e, _ := NewEvaluator()
	result, _ := e.Evaluate("true || false", map[string]any{"input": map[string]any{}})
	if result.Value != true {
		t.Errorf("expected true, got %v", result.Value)
	}
}

func TestEvaluator_InputAccess(t *testing.T) {
	e, _ := NewEvaluator()
	result, err := e.Evaluate(`input.name == "helm"`, map[string]any{
		"input": map[string]any{"name": "helm"},
	})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if result.Error != nil {
		t.Fatalf("unexpected error: %s", result.Error.Message)
	}
	if result.Value != true {
		t.Errorf("expected true, got %v", result.Value)
	}
}

func TestEvaluator_ValidationFailedReturnsError(t *testing.T) {
	e, _ := NewEvaluator()
	result, _ := e.Evaluate("3.14", map[string]any{"input": map[string]any{}})
	if result.Error == nil {
		t.Error("float literal should cause validation error")
	}
	if result.Error.ErrorCode != "HELM/CORE/CEL_DP/VALIDATION_FAILED" {
		t.Errorf("unexpected error code: %s", result.Error.ErrorCode)
	}
}

func TestEvaluator_RuntimeError(t *testing.T) {
	e, _ := NewEvaluator()
	// Accessing a missing key causes a runtime error
	result, _ := e.Evaluate(`input.nonexistent`, map[string]any{
		"input": map[string]any{},
	})
	if result.Error == nil {
		t.Error("expected runtime error for missing key")
	}
}

// ── CELError ────────────────────────────────────────────────────

func TestCELError_Initial(t *testing.T) {
	e := &CELError{ErrorCode: "ERR", JSONPointerPath: "/a/b"}
	if e.Initial() != "ERR/a/b" {
		t.Errorf("unexpected Initial: %s", e.Initial())
	}
}

func TestCompareErrors_DifferentCodes(t *testing.T) {
	a := CELError{ErrorCode: "A"}
	b := CELError{ErrorCode: "B"}
	if CompareErrors(a, b) >= 0 {
		t.Error("A should sort before B")
	}
}

func TestCompareErrors_SameCode_DifferentPath(t *testing.T) {
	a := CELError{ErrorCode: "X", JSONPointerPath: "/a"}
	b := CELError{ErrorCode: "X", JSONPointerPath: "/b"}
	if CompareErrors(a, b) >= 0 {
		t.Error("/a should sort before /b")
	}
}

func TestEvaluator_StringComparison(t *testing.T) {
	e, _ := NewEvaluator()
	result, _ := e.Evaluate(`"abc" == "abc"`, map[string]any{"input": map[string]any{}})
	if result.Value != true {
		t.Errorf("expected true, got %v", result.Value)
	}
}

func TestValidator_ListExpression(t *testing.T) {
	v, _ := NewValidator()
	res, _ := v.Validate("[1, 2, 3]")
	if !res.Valid {
		t.Error("list literal should be valid")
	}
}
