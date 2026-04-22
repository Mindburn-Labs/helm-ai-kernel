package celdp

import (
	"strings"

	"github.com/google/cel-go/cel"
)

type CELDPEvaluator struct {
	validator *CELDPValidator
	env       *cel.Env
}

type CELDPResult struct {
	Value interface{}
	Error *CELError
}

type CELError struct {
	ErrorCode       string `json:"error_code"`
	JSONPointerPath string `json:"json_pointer_path"`
	Message         string `json:"message"`
}

func NewEvaluator() (*CELDPEvaluator, error) {
	// Configure env with 'input' variable (map[string]any) for general usage
	// In a real kernel, this would be dynamic based on context.
	// For Spec 6.9 conformance, we need to allow input access.
	env, err := cel.NewEnv(
		cel.Variable("input", cel.MapType(cel.StringType, cel.DynType)),
	)
	if err != nil {
		return nil, err
	}
	v := &CELDPValidator{env: env}
	return &CELDPEvaluator{validator: v, env: env}, nil
}

func (e *CELDPEvaluator) Evaluate(expr string, input interface{}) (*CELDPResult, error) {
	// 1. Validate
	res, err := e.validator.Validate(expr)
	if err != nil {
		return nil, err
	}
	if !res.Valid {
		msgs := []string{}
		for _, iss := range res.Issues {
			msgs = append(msgs, iss.Message)
		}
		return &CELDPResult{
			Error: &CELError{
				ErrorCode: "HELM/CORE/CEL_DP/VALIDATION_FAILED",
				Message:   strings.Join(msgs, "; "),
			},
		}, nil
	}

	// 2. Compile
	ast, issues := e.env.Compile(expr)
	if issues != nil && issues.Err() != nil {
		return nil, issues.Err()
	}

	// 3. Program
	prg, err := e.env.Program(ast)
	if err != nil {
		return nil, err
	}

	// 4. Evaluate
	val, _, err := prg.Eval(input)
	if err != nil {
		return &CELDPResult{
			Error: &CELError{
				ErrorCode: "HELM/CORE/CEL_DP/RUNTIME_ERROR",
				Message:   err.Error(),
			},
		}, nil
	}

	// Return value
	return &CELDPResult{Value: val.Value()}, nil
}

func (e *CELError) Initial() string {
	return e.ErrorCode + e.JSONPointerPath
}

// CompareErrors for deterministic selection per Spec 6.9.
func CompareErrors(a, b CELError) int {
	if cmp := strings.Compare(a.ErrorCode, b.ErrorCode); cmp != 0 {
		return cmp
	}
	return strings.Compare(a.JSONPointerPath, b.JSONPointerPath)
}
