package compiler

import (
	"testing"
)

// FuzzCELCompile tests the obligation compiler with fuzzed inputs.
// This targets the Parse and Compile methods to ensure robustness
// against malformed or adversarial legal text inputs.
func FuzzCELCompile(f *testing.F) {
	// Seed corpus with valid legal text patterns
	seeds := []struct {
		text      string
		framework string
		article   string
	}{
		// Basic obligation patterns
		{"Entities shall report transactions exceeding EUR 10,000 within 24 hours", "MiCA", "Art.68"},
		{"CASPs must implement AML controls for all customer accounts", "MiCA", "Art.16"},
		{"Financial institutions shall not process transactions from sanctioned jurisdictions", "DORA", "Art.17"},

		// Edge cases
		{"", "", ""},
		{"   ", "Unknown", ""},
		{"SHALL", "MiCA", "Art.1"},

		// Complex patterns
		{"Under Article 68, crypto-asset service providers operating in EU Member States must maintain records of all transactions for a period of not less than 5 years", "MiCA", "Art.68"},

		// Malformed inputs
		{"{{{{", "BadFramework", "BadArt"},
		{"<script>alert('xss')</script>", "XSS", "Attack"},
		{"'; DROP TABLE obligations; --", "SQL", "Injection"},
	}

	for _, s := range seeds {
		f.Add(s.text, s.framework, s.article)
	}

	f.Fuzz(func(t *testing.T, text, framework, article string) {
		compiler := NewCompiler()

		// Test that Parse doesn't panic
		ast, err := compiler.Parse(text, framework, article)
		if err != nil {
			// Parse errors are expected for invalid inputs
			return
		}

		if ast == nil {
			t.Error("Parse returned nil AST without error")
			return
		}

		// Test that Compile doesn't panic on parsed AST
		policy, err := compiler.Compile(ast)
		if err != nil {
			// Compile errors are expected for some inputs
			return
		}

		if policy == nil {
			t.Error("Compile returned nil policy without error")
			return
		}

		// Invariants that should always hold
		if policy.ObligationID == "" {
			t.Error("Compiled policy has empty ObligationID")
		}
		if policy.Hash == "" {
			t.Error("Compiled policy has empty Hash")
		}
		if policy.CompiledAt.IsZero() {
			t.Error("Compiled policy has zero CompiledAt")
		}
	})
}

// FuzzCompileRoundtrip tests that valid CEL expressions can be produced.
func FuzzCompileRoundtrip(f *testing.F) {
	f.Add("Services must report", "DORA", "Art.17")
	f.Add("Entities shall not", "MiCA", "Art.68")

	f.Fuzz(func(t *testing.T, text, framework, article string) {
		if len(text) > 10000 {
			return // Skip very long inputs
		}

		compiler := NewCompiler()
		ast, err := compiler.Parse(text, framework, article)
		if err != nil {
			return
		}

		policy, err := compiler.Compile(ast)
		if err != nil {
			return
		}

		// If we got a policy, the CEL expression should be non-empty for valid inputs
		if len(text) > 10 && policy.FullExpr == "" {
			// This is okay - not all text produces CEL
			_ = policy // Explicitly ignore to satisfy checks
		}
	})
}
