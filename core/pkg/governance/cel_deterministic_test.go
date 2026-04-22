package governance

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestCELDPValidatorBannedFunctions verifies banned function detection.
func TestCELDPValidatorBannedFunctions(t *testing.T) {
	validator := NewCELDPValidator()

	tests := []struct {
		name       string
		expr       string
		wantIssues int
		wantFunc   string
	}{
		{
			name:       "now() is banned",
			expr:       `timestamp > now()`,
			wantIssues: 1,
			wantFunc:   "now",
		},
		{
			name:       "timestamp() is banned",
			expr:       `timestamp("2024-01-01")`,
			wantIssues: 1,
			wantFunc:   "timestamp",
		},
		{
			name:       "random() is banned",
			expr:       `random() > 0.5`,
			wantIssues: 1,
			wantFunc:   "random",
		},
		{
			name:       "allowed expression",
			expr:       `user.role == "admin" && resource.size < 1000`,
			wantIssues: 0,
		},
		{
			name:       "size() is allowed",
			expr:       `list.size() > 0`,
			wantIssues: 0,
		},
		{
			name:       "multiple banned functions",
			expr:       `now() > timestamp("2024-01-01")`,
			wantIssues: 2,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			issues := validator.ValidateExpression(tc.expr)
			require.Len(t, issues, tc.wantIssues)

			if tc.wantIssues > 0 && tc.wantFunc != "" {
				require.Equal(t, tc.wantFunc, issues[0].Name)
				require.Equal(t, "banned_function", issues[0].Type)
			}
		})
	}
}

// TestCELDPValidatorBannedTypes verifies banned type detection.
func TestCELDPValidatorBannedTypes(t *testing.T) {
	validator := NewCELDPValidator()

	tests := []struct {
		name       string
		expr       string
		wantIssues int
	}{
		{
			name:       "double type is banned",
			expr:       `double(value) > 0.5`,
			wantIssues: 1,
		},
		{
			name:       "float type is banned",
			expr:       `float(value) > 0.5`,
			wantIssues: 1,
		},
		{
			name:       "int is allowed",
			expr:       `int(value) > 100`,
			wantIssues: 0,
		},
		{
			name:       "uint is allowed",
			expr:       `uint(value) > 0`,
			wantIssues: 0,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			issues := validator.ValidateExpression(tc.expr)
			require.Len(t, issues, tc.wantIssues)

			if tc.wantIssues > 0 {
				require.Equal(t, "banned_type", issues[0].Type)
			}
		})
	}
}

// TestCELDPValidatorDynamicOps verifies dynamic operation detection.
func TestCELDPValidatorDynamicOps(t *testing.T) {
	validator := NewCELDPValidator()

	tests := []struct {
		name       string
		expr       string
		wantIssues int
	}{
		{
			name:       "type() is nondeterministic",
			expr:       `type(value) == string`,
			wantIssues: 1,
		},
		{
			name:       "dyn() is nondeterministic",
			expr:       `dyn(value).field`,
			wantIssues: 1,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			issues := validator.ValidateExpression(tc.expr)
			require.Len(t, issues, tc.wantIssues)

			if tc.wantIssues > 0 {
				require.Equal(t, "nondeterministic", issues[0].Type)
			}
		})
	}
}

// TestCELDPErrorHashing verifies deterministic error message hashing.
func TestCELDPErrorHashing(t *testing.T) {
	t.Run("identical messages produce identical hash", func(t *testing.T) {
		hash1 := HashErrorMessage("division by zero")
		hash2 := HashErrorMessage("division by zero")
		require.Equal(t, hash1, hash2)
	})

	t.Run("normalized messages produce identical hash", func(t *testing.T) {
		hash1 := HashErrorMessage("Division by Zero")
		hash2 := HashErrorMessage("  division   by   zero  ")
		require.Equal(t, hash1, hash2)
	})

	t.Run("different messages produce different hash", func(t *testing.T) {
		hash1 := HashErrorMessage("division by zero")
		hash2 := HashErrorMessage("type error")
		require.NotEqual(t, hash1, hash2)
	})
}

// TestCELDPErrorCreation verifies error creation.
func TestCELDPErrorCreation(t *testing.T) {
	err := NewCELDPError(CELDPErrorDivZero, "Division by zero at position 42", nil)

	require.Equal(t, CELDPErrorDivZero, err.Code)
	require.NotEmpty(t, err.MessageHash)
	require.Nil(t, err.Span)
}

// TestCELDPTraceHash verifies trace hashing determinism.
func TestCELDPTraceHash(t *testing.T) {
	t.Run("empty trace", func(t *testing.T) {
		hash := ComputeTraceHash(nil)
		require.Empty(t, hash)
	})

	t.Run("deterministic hash", func(t *testing.T) {
		entries := []CELDPTraceEntry{
			{Step: 1, Expression: "x > 0", ResultHash: "abc123"},
			{Step: 2, Expression: "y < 10", ResultHash: "def456"},
		}

		hash1 := ComputeTraceHash(entries)
		hash2 := ComputeTraceHash(entries)
		require.Equal(t, hash1, hash2)
		require.NotEmpty(t, hash1)
	})

	t.Run("order matters", func(t *testing.T) {
		entries1 := []CELDPTraceEntry{
			{Step: 1, Expression: "x > 0", ResultHash: "abc123"},
			{Step: 2, Expression: "y < 10", ResultHash: "def456"},
		}
		entries2 := []CELDPTraceEntry{
			{Step: 1, Expression: "y < 10", ResultHash: "def456"},
			{Step: 2, Expression: "x > 0", ResultHash: "abc123"},
		}

		hash1 := ComputeTraceHash(entries1)
		hash2 := ComputeTraceHash(entries2)
		require.NotEqual(t, hash1, hash2)
	})
}

// TestCELDPValidateAndAnalyze verifies the combined validation.
func TestCELDPValidateAndAnalyze(t *testing.T) {
	validator := NewCELDPValidator()

	t.Run("valid expression", func(t *testing.T) {
		info := validator.ValidateAndAnalyze(`user.role == "admin"`)
		require.True(t, info.Valid)
		require.Equal(t, CELDPProfileID, info.ProfileID)
		require.Empty(t, info.Issues)
	})

	t.Run("invalid expression", func(t *testing.T) {
		info := validator.ValidateAndAnalyze(`timestamp > now()`)
		require.False(t, info.Valid)
		require.NotEmpty(t, info.Issues)
	})
}

// TestCELDPProfileID verifies profile constant.
func TestCELDPProfileID(t *testing.T) {
	require.Equal(t, "cel-dp-v1", CELDPProfileID)
}
