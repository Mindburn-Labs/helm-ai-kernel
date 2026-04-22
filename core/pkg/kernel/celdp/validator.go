package celdp

import (
	"github.com/google/cel-go/cel"
	exprpb "google.golang.org/genproto/googleapis/api/expr/v1alpha1"
)

type CELDPIssue struct {
	Message  string
	Severity string // ERROR
}

type CELDPValidationResult struct {
	Valid  bool
	Issues []CELDPIssue
}

type CELDPValidator struct {
	env *cel.Env
}

func NewValidator() (*CELDPValidator, error) {
	// Use standard env for parsing
	env, err := cel.NewEnv()
	if err != nil {
		return nil, err
	}
	return &CELDPValidator{env: env}, nil
}

func (v *CELDPValidator) Validate(exprSource string) (*CELDPValidationResult, error) {
	parsedAST, issues := v.env.Parse(exprSource)
	if issues != nil && issues.Err() != nil {
		return nil, issues.Err()
	}

	result := &CELDPValidationResult{
		Valid:  true,
		Issues: []CELDPIssue{},
	}

	// Traverse exprpb.Expr
	expr := parsedAST.Expr() //nolint:staticcheck // Deprecated but no alternative for AST traversal yet
	checkRecursively(expr, &result.Issues)

	if len(result.Issues) > 0 {
		result.Valid = false
	}

	return result, nil
}

func checkRecursively(e *exprpb.Expr, issues *[]CELDPIssue) {
	if e == nil {
		return
	}

	switch k := e.ExprKind.(type) {
	case *exprpb.Expr_ConstExpr:
		c := k.ConstExpr
		switch c.ConstantKind.(type) {
		case *exprpb.Constant_DoubleValue:
			*issues = append(*issues, CELDPIssue{Message: "Floating point literals are forbidden", Severity: "ERROR"})
		}

	case *exprpb.Expr_CallExpr:
		call := k.CallExpr
		if call.Function == "now" {
			*issues = append(*issues, CELDPIssue{Message: "now() is forbidden", Severity: "ERROR"})
		}
		if call.Function == "keys" || call.Function == "values" {
			*issues = append(*issues, CELDPIssue{Message: "Map iteration (keys/values) is forbidden due to non-determinism", Severity: "ERROR"})
		}

		// Recurse
		if call.Target != nil {
			checkRecursively(call.Target, issues)
		}
		for _, arg := range call.Args {
			checkRecursively(arg, issues)
		}

	case *exprpb.Expr_SelectExpr:
		sel := k.SelectExpr
		checkRecursively(sel.Operand, issues)

	case *exprpb.Expr_IdentExpr:
		// No children

	case *exprpb.Expr_ListExpr:
		l := k.ListExpr
		for _, el := range l.Elements {
			checkRecursively(el, issues)
		}

	case *exprpb.Expr_StructExpr:
		s := k.StructExpr
		for _, entry := range s.Entries {
			// entries in StructExpr can be Map entries or Object fields
			if entry.GetMapKey() != nil {
				checkRecursively(entry.GetMapKey(), issues)
			}
			checkRecursively(entry.Value, issues)
		}

	case *exprpb.Expr_ComprehensionExpr:
		comp := k.ComprehensionExpr
		checkRecursively(comp.IterRange, issues)
		checkRecursively(comp.AccuInit, issues)
		checkRecursively(comp.LoopCondition, issues)
		checkRecursively(comp.LoopStep, issues)
		checkRecursively(comp.Result, issues)
	}
}
