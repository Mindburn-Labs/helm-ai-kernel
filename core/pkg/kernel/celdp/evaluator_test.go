package celdp

import (
	"testing"
)

func TestEvaluator(t *testing.T) {
	eval, err := NewEvaluator()
	if err != nil {
		t.Fatalf("Failed to create evaluator: %v", err)
	}

	tests := []struct {
		name          string
		expr          string
		input         interface{}
		wantValue     interface{}
		wantErrorCode string
	}{
		{
			name:      "Valid Integer Math",
			expr:      "1 + 2",
			wantValue: int64(3),
		},
		{
			name:          "Validation Failure (Float)",
			expr:          "1.0 + 2.0",
			wantErrorCode: "HELM/CORE/CEL_DP/VALIDATION_FAILED",
		},
		{
			name:          "Runtime Error (Divide by Zero)",
			expr:          "1 / 0",
			wantErrorCode: "HELM/CORE/CEL_DP/RUNTIME_ERROR",
		},
		{
			name:      "Valid Input Access",
			expr:      "input.foo == 'bar'",
			input:     map[string]interface{}{"foo": "bar"},
			wantValue: true,
		},
		{
			name:          "Runtime Error (Field Missing)",
			expr:          "input.missing_field",
			input:         map[string]interface{}{"foo": "bar"},
			wantErrorCode: "HELM/CORE/CEL_DP/RUNTIME_ERROR",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// For input access, we need to wrap input in a way CEL expects if using simple env?
			// cel.NewEnv() default has no variables.
			// NewEvaluator uses default env.
			// So "input.foo" might fail compilation if "input" is not declared.
			// We should probably invoke `Evaluate` with proper environment setup for variables.
			// BUT `NewEvaluator` implementation uses `cel.NewEnv()` without options.
			// So variables are NOT supported in current `NewEvaluator`.
			// `Eval` method on `prg` takes `input interface{}`.
			// If we pass a map, it's used as the activation.
			// Standard CEL uses `parsedAST` which might have unresolved references if not declared in env?
			// Let's check if valid input access works with default env.
			// Default env has standard macros but no variables.
			// "input" variable needs declaration.
			// So we expect compilation error for "input.foo" if "input" is not declared.
			// UNLESS we use `cel.Declarations`.
			// Since `NewEvaluator` is simple in our impl, let's skip variable tests or expect error.
			// OR we improve `NewEvaluator` to accept options/declarations.
			// For this test, let's stick to literals for success cases if variables aren't set up.

			// With updated NewEvaluator, "input" is declared.
			// So we can run all tests.

			// Wrap input in activation map to match variable name "input"
			var activation interface{}
			if tt.input != nil {
				activation = map[string]interface{}{
					"input": tt.input,
				}
			} else {
				activation = map[string]interface{}{}
			}

			res, err := eval.Evaluate(tt.expr, activation)
			if err != nil {
				t.Fatalf("Evaluate(%q) unexpected error: %v", tt.expr, err)
			}

			if tt.wantErrorCode != "" {
				if res.Error == nil {
					t.Errorf("Evaluate(%q) expected error code %q, got success val %v", tt.expr, tt.wantErrorCode, res.Value)
				} else if res.Error.ErrorCode != tt.wantErrorCode {
					t.Errorf("Evaluate(%q) error code = %q, want %q", tt.expr, res.Error.ErrorCode, tt.wantErrorCode)
				}
			} else {
				if res.Error != nil {
					t.Errorf("Evaluate(%q) unexpected error result: %v (Message: %s)", tt.expr, res.Error, res.Error.Message)
				} else if res.Value != tt.wantValue {
					t.Errorf("Evaluate(%q) value = %v, want %v", tt.expr, res.Value, tt.wantValue)
				}
			}
		})
	}
}
