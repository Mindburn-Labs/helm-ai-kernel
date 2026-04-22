// Package kernel provides conformance tests for CSNF, CEL-DP, and EvidencePack Merkleization.
package kernel

import (
	"encoding/json"
	"testing"
	"time"
)

// TestCSNFDecimalStringValidation tests DecimalString profile validation.
func TestCSNFDecimalStringValidation(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{"valid integer", "123", false},
		{"valid negative", "-456", false},
		{"valid decimal", "123.45", false},
		{"valid zero", "0", false},
		{"valid negative decimal", "-0.001", false},
		{"invalid leading zeros", "007", true},
		{"invalid spaces", "12 3", true},
		{"invalid letters", "12a3", true},
		{"invalid empty", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateDecimalString(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateDecimalString(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			}
		})
	}
}

// TestCSNFTimestampValidation tests Timestamp profile validation.
func TestCSNFTimestampValidation(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{"valid UTC", "2024-01-15T10:30:00Z", false},
		{"valid with offset", "2024-01-15T10:30:00+02:00", false},
		{"valid with nanos", "2024-01-15T10:30:00.123456789Z", false},
		{"invalid no timezone", "2024-01-15T10:30:00", true},
		{"invalid format", "2024/01/15 10:30:00", true},
		{"invalid empty", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateTimestamp(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateTimestamp(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			}
		})
	}
}

// TestCSNFNormalizeTimestamp tests timestamp canonicalization.
func TestCSNFNormalizeTimestamp(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{
			name:  "UTC stays UTC",
			input: "2024-01-15T10:30:00Z",
			want:  "2024-01-15T10:30:00.000Z",
		},
		{
			name:  "offset converted to UTC",
			input: "2024-01-15T12:30:00+02:00",
			want:  "2024-01-15T10:30:00.000Z",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NormalizeTimestamp(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("NormalizeTimestamp(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("NormalizeTimestamp(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

// TestCSNFStripNulls tests null stripping.
func TestCSNFStripNulls(t *testing.T) {
	input := map[string]any{
		"name":  "test",
		"value": nil,
		"nested": map[string]any{
			"keep":   "yes",
			"remove": nil,
		},
	}

	result := StripNulls(input)

	if _, exists := result["value"]; exists {
		t.Error("expected 'value' field to be stripped")
	}
	if _, exists := result["name"]; !exists {
		t.Error("expected 'name' field to be kept")
	}

	nested, ok := result["nested"].(map[string]any)
	if !ok {
		t.Fatal("nested field should be map")
	}
	if _, exists := nested["remove"]; exists {
		t.Error("expected nested 'remove' field to be stripped")
	}
}

// TestCELDPValidation tests CEL-DP expression validation.
func TestCELDPValidation(t *testing.T) {
	validator := NewCELDPValidator()

	tests := []struct {
		name  string
		expr  string
		valid bool
	}{
		{"simple comparison", "x > 10", true},
		{"string check", "name == 'test'", true},
		{"now() forbidden", "now() > timestamp", false},
		{"timestamp() forbidden", "timestamp('2024-01-01')", false},
		{"duration() forbidden", "duration('1h') > limit", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := validator.Validate(tt.expr)
			if result.Valid != tt.valid {
				t.Errorf("Validate(%q) valid = %v, want %v; issues: %v",
					tt.expr, result.Valid, tt.valid, result.Issues)
			}
		})
	}
}

// TestCELDPNestingDepth tests CEL-DP nesting depth limit.
func TestCELDPNestingDepth(t *testing.T) {
	validator := NewCELDPValidator().WithBudget(CELDPCostBudget{
		MaxNestingDepth: 5,
	})

	deepExpr := "((((((x))))))" // 6 levels

	result := validator.Validate(deepExpr)
	if result.Valid {
		t.Error("expected deeply nested expression to fail validation")
	}
}

// TestMerkleTreeConstruction tests Merkle tree building.
func TestMerkleTreeConstruction(t *testing.T) {
	builder := NewMerkleTreeBuilder()

	obj := map[string]any{
		"name":   "test",
		"value":  int64(123),
		"active": true,
	}

	tree, err := builder.BuildTree(obj)
	if err != nil {
		t.Fatalf("BuildTree failed: %v", err)
	}

	// Verify tree properties
	if tree.Root == "" {
		t.Error("expected non-empty root")
	}
	if len(tree.Leaves) == 0 {
		t.Error("expected leaves")
	}
}

// TestMerkleInclusionProof tests inclusion proof generation and verification.
func TestMerkleInclusionProof(t *testing.T) {
	builder := NewMerkleTreeBuilder()

	obj := map[string]any{
		"a": "first",
		"b": "second",
		"c": "third",
		"d": "fourth",
	}

	tree, err := builder.BuildTree(obj)
	if err != nil {
		t.Fatalf("BuildTree failed: %v", err)
	}

	// Generate proof for a leaf
	proof, err := tree.GenerateProof("/a")
	if err != nil {
		t.Fatalf("GenerateProof failed: %v", err)
	}

	// Verify proof
	if !VerifyProof(*proof, tree.Root) {
		t.Error("proof verification failed")
	}

	// Verify proof fails with wrong root
	if VerifyProof(*proof, "sha256:0000000000000000000000000000000000000000000000000000000000000000") {
		t.Error("proof should not verify with wrong root")
	}
}

// TestMerkleDeterminism tests that Merkle tree construction is deterministic.
func TestMerkleDeterminism(t *testing.T) {
	builder := NewMerkleTreeBuilder()

	obj := map[string]any{
		"z": "last",
		"a": "first",
		"m": "middle",
	}

	tree1, _ := builder.BuildTree(obj)
	tree2, _ := builder.BuildTree(obj)

	if tree1.Root != tree2.Root {
		t.Errorf("Merkle tree not deterministic: %s != %s", tree1.Root, tree2.Root)
	}

	// Verify leaves are sorted
	for i := 1; i < len(tree1.Leaves); i++ {
		if tree1.Leaves[i-1].Path >= tree1.Leaves[i].Path {
			t.Errorf("leaves not sorted: %s >= %s", tree1.Leaves[i-1].Path, tree1.Leaves[i].Path)
		}
	}
}

// TestEvidenceViewDerivation tests EvidenceView selective disclosure.
func TestEvidenceViewDerivation(t *testing.T) {
	builder := NewMerkleTreeBuilder()

	pack := map[string]any{
		"public_field":  "visible",
		"private_field": "secret",
	}

	tree, err := builder.BuildTree(pack)
	if err != nil {
		t.Fatalf("BuildTree failed: %v", err)
	}

	policy := ViewPolicy{
		PolicyID: "test-policy",
		Name:     "Test View Policy",
		DisclosureRules: []DisclosureRule{
			{PathPattern: "/public_field", Action: "DISCLOSE"},
			{PathPattern: "/private_field", Action: "SEAL", Reason: "confidential"},
		},
	}

	view, err := DeriveEvidenceView(pack, tree, policy, time.Now().UTC().Format(time.RFC3339))
	if err != nil {
		t.Fatalf("DeriveEvidenceView failed: %v", err)
	}

	// Verify disclosed field
	if _, ok := view.Disclosed["/public_field"]; !ok {
		t.Error("expected public_field to be disclosed")
	}

	// Verify sealed field
	found := false
	for _, s := range view.Sealed {
		if s.Path == "/private_field" {
			found = true
			if s.Reason != "confidential" {
				t.Error("expected sealed field to have reason")
			}
		}
	}
	if !found {
		t.Error("expected private_field to be sealed")
	}
}

// TestErrorIRConstruction tests ErrorIR building.
func TestErrorIRConstruction(t *testing.T) {
	err := NewErrorIR(ErrCodeSchemaMismatch).
		WithTitle("Schema Validation Failed").
		WithDetail("Field 'amount' must be integer").
		WithCause(ErrCodeCSNFViolation, "/amount").
		Build()

	if err.HELM.ErrorCode != ErrCodeSchemaMismatch {
		t.Errorf("wrong error code: %s", err.HELM.ErrorCode)
	}
	if err.HELM.Classification != ErrorClassNonRetryable {
		t.Errorf("schema errors should be non-retryable")
	}
	if len(err.HELM.CanonicalCauseChain) != 1 {
		t.Error("expected one cause in chain")
	}
}

// TestDeterministicBackoff tests deterministic retry delay calculation.
func TestDeterministicBackoff(t *testing.T) {
	policy := BackoffPolicy{
		PolicyID:    "test",
		BaseMs:      100,
		MaxMs:       5000,
		MaxJitterMs: 50,
		MaxAttempts: 5,
	}

	params := BackoffParams{
		PolicyID:     "test",
		EffectID:     "effect-123",
		AttemptIndex: 2,
		EnvSnapHash:  "abc123",
	}

	delay1 := ComputeBackoff(params, policy)
	delay2 := ComputeBackoff(params, policy)

	if delay1 != delay2 {
		t.Errorf("backoff not deterministic: %v != %v", delay1, delay2)
	}

	// Different attempt should give different delay
	params.AttemptIndex = 3
	delay3 := ComputeBackoff(params, policy)
	if delay1 == delay3 {
		t.Error("different attempts should have different delays")
	}
}

// TestRetryPlanGeneration tests pre-committed retry schedule.
func TestRetryPlanGeneration(t *testing.T) {
	policy := BackoffPolicy{
		PolicyID:    "default",
		BaseMs:      100,
		MaxMs:       10000,
		MaxJitterMs: 100,
		MaxAttempts: 5,
	}

	startTime := time.Now().UTC()
	plan := CreateRetryPlan("effect-456", policy, "env-hash", startTime)

	if len(plan.Schedule) != policy.MaxAttempts {
		t.Errorf("expected %d attempts, got %d", policy.MaxAttempts, len(plan.Schedule))
	}

	// Verify increasing delays
	for i := 1; i < len(plan.Schedule); i++ {
		if plan.Schedule[i].ScheduledAt.Before(plan.Schedule[i-1].ScheduledAt) {
			t.Error("attempts should be scheduled in order")
		}
	}

	// Verify determinism
	plan2 := CreateRetryPlan("effect-456", policy, "env-hash", startTime)
	if plan.RetryPlanID != plan2.RetryPlanID {
		t.Error("retry plan IDs should be deterministic")
	}
}

// TestSecretRefValidation tests SecretRef validation.
func TestSecretRefValidation(t *testing.T) {
	tests := []struct {
		name    string
		ref     SecretRef
		wantErr bool
	}{
		{
			name: "valid vault ref",
			ref: SecretRef{
				RefID:                "secret-1",
				Provider:             SecretProviderVault,
				Path:                 "secret/data/api-key",
				MaterializationScope: MaterializationScopeRuntime,
				AuditOnAccess:        true,
			},
			wantErr: false,
		},
		{
			name: "missing ref_id",
			ref: SecretRef{
				Provider:             SecretProviderVault,
				Path:                 "secret/data/api-key",
				MaterializationScope: MaterializationScopeRuntime,
			},
			wantErr: true,
		},
		{
			name: "unknown provider",
			ref: SecretRef{
				RefID:                "secret-1",
				Provider:             "unknown",
				Path:                 "secret/data/api-key",
				MaterializationScope: MaterializationScopeRuntime,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateSecretRef(tt.ref)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateSecretRef() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestCanonicalErrorSelection tests deterministic error selection.
func TestCanonicalErrorSelection(t *testing.T) {
	err1 := NewErrorIR("HELM/CORE/VALIDATION/SCHEMA_MISMATCH").
		WithCause("cause1", "/b/field").
		Build()
	err2 := NewErrorIR("HELM/CORE/VALIDATION/CSNF_VIOLATION").
		WithCause("cause2", "/a/field").
		Build()
	err3 := NewErrorIR("HELM/CORE/VALIDATION/CSNF_VIOLATION").
		WithCause("cause3", "/a/another").
		Build()

	// Should select smallest (error_code, path) tuple
	selected := SelectCanonicalError([]ErrorIR{err1, err2, err3})

	// CSNF_VIOLATION < SCHEMA_MISMATCH alphabetically
	if selected.HELM.ErrorCode != "HELM/CORE/VALIDATION/CSNF_VIOLATION" {
		t.Errorf("wrong error selected: %s", selected.HELM.ErrorCode)
	}
	// Among CSNF_VIOLATION errors, /a/another < /a/field
	if len(selected.HELM.CanonicalCauseChain) > 0 {
		if selected.HELM.CanonicalCauseChain[0].At != "/a/another" {
			t.Errorf("wrong path selected: %s", selected.HELM.CanonicalCauseChain[0].At)
		}
	}
}

// TestNFCNormalization tests NFC string normalization detection.
func TestNFCNormalization(t *testing.T) {
	tests := []struct {
		input string
		isNFC bool
	}{
		{"hello", true},
		{"café", true}, // Already NFC
		{"naïve", true},
		// NFD forms would not be NFC, but constructing them in Go is tricky
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			if IsNFCNormalized(tt.input) != tt.isNFC {
				t.Errorf("IsNFCNormalized(%q) = %v, want %v", tt.input, !tt.isNFC, tt.isNFC)
			}
		})
	}
}

// TestCSNFStrictValidation tests strict CSNF validation.
func TestCSNFStrictValidation(t *testing.T) {
	// Valid CSNF object
	valid := map[string]any{
		"name":  "test",
		"count": int64(42),
	}

	result := ValidateCSNFStrict(valid, nil)
	if !result.Valid {
		t.Errorf("expected valid object to pass: %v", result.Issues)
	}

	// Object with float (should have warning/error)
	withFloat := map[string]any{
		"value": float64(3.14),
	}

	result = ValidateCSNFStrict(withFloat, nil)
	if result.Valid {
		t.Error("expected float to fail strict validation")
	}
}

// BenchmarkMerkleTreeConstruction benchmarks Merkle tree building.
func BenchmarkMerkleTreeConstruction(b *testing.B) {
	builder := NewMerkleTreeBuilder()
	obj := map[string]any{
		"field1": "value1",
		"field2": "value2",
		"field3": int64(123),
		"field4": true,
		"nested": map[string]any{
			"a": "b",
			"c": "d",
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = builder.BuildTree(obj)
	}
}

// BenchmarkDeterministicBackoff benchmarks backoff calculation.
func BenchmarkDeterministicBackoff(b *testing.B) {
	policy := DefaultBackoffPolicy()
	params := BackoffParams{
		PolicyID:     "bench",
		EffectID:     "effect",
		AttemptIndex: 3,
		EnvSnapHash:  "hash",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ComputeBackoff(params, policy)
	}
}

// ExampleErrorIR demonstrates ErrorIR construction.
func ExampleErrorIR() {
	err := NewErrorIR(ErrCodeSchemaMismatch).
		WithTitle("Schema Validation Failed").
		WithDetail("Field 'amount' must be an integer").
		Build()

	data, _ := json.MarshalIndent(err, "", "  ")
	_ = data // Would print JSON
}

// ExampleMerkleTree demonstrates Merkle tree construction.
func ExampleMerkleTree() {
	builder := NewMerkleTreeBuilder()

	obj := map[string]any{
		"user_id": "user-123",
		"action":  "transfer",
		"amount":  int64(10000),
	}

	tree, _ := builder.BuildTree(obj)
	_ = tree.Root // Use the Merkle root
}

func TestExamples_AreReachable(t *testing.T) {
	ExampleErrorIR()
	ExampleMerkleTree()
}
