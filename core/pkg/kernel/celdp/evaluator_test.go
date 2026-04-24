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
