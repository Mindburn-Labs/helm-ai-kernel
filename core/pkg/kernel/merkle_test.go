package kernel

import (
	"testing"
)

//nolint:gocognit // test complexity is acceptable
func TestMerkleTreeBuilder(t *testing.T) {
	builder := NewMerkleTreeBuilder()

	t.Run("BuildTree with simple object", func(t *testing.T) {
		obj := map[string]any{
			"name":    "Alice",
			"age":     int64(30),
			"enabled": true,
		}

		tree, err := builder.BuildTree(obj)
		if err != nil {
			t.Fatalf("BuildTree failed: %v", err)
		}
		if tree.Root == "" {
			t.Error("Expected non-empty root")
		}
		if len(tree.Leaves) != 3 {
			t.Errorf("Expected 3 leaves, got %d", len(tree.Leaves))
		}
	})

	t.Run("BuildTree with nested object", func(t *testing.T) {
		obj := map[string]any{
			"user": map[string]any{
				"name": "Bob",
				"id":   int64(123),
			},
			"active": true,
		}

		tree, err := builder.BuildTree(obj)
		if err != nil {
			t.Fatalf("BuildTree failed: %v", err)
		}
		if tree.Root == "" {
			t.Error("Expected non-empty root")
		}
		// Should have leaves for user/name, user/id, active
		if len(tree.Leaves) < 3 {
			t.Errorf("Expected at least 3 leaves, got %d", len(tree.Leaves))
		}
	})

	t.Run("BuildTree with array", func(t *testing.T) {
		obj := map[string]any{
			"items": []any{"a", "b", "c"},
		}

		tree, err := builder.BuildTree(obj)
		if err != nil {
			t.Fatalf("BuildTree failed: %v", err)
		}
		if tree.Root == "" {
			t.Error("Expected non-empty root")
		}
		// Should have leaves for items/0, items/1, items/2
		if len(tree.Leaves) != 3 {
			t.Errorf("Expected 3 leaves, got %d", len(tree.Leaves))
		}
	})

	t.Run("BuildTree with empty object", func(t *testing.T) {
		obj := map[string]any{}

		tree, err := builder.BuildTree(obj)
		if err != nil {
			t.Fatalf("BuildTree failed: %v", err)
		}
		if tree.Root == "" {
			t.Error("Expected non-empty root for empty tree")
		}
		if len(tree.Leaves) != 0 {
			t.Errorf("Expected 0 leaves, got %d", len(tree.Leaves))
		}
	})

	t.Run("BuildTree determinism", func(t *testing.T) {
		obj := map[string]any{
			"z": "last",
			"a": "first",
			"m": "middle",
		}

		tree1, _ := builder.BuildTree(obj)
		tree2, _ := builder.BuildTree(obj)

		if tree1.Root != tree2.Root {
			t.Error("BuildTree should be deterministic")
		}
	})
}

func TestMerkleTreeGenerateProof(t *testing.T) {
	builder := NewMerkleTreeBuilder()

	obj := map[string]any{
		"name":  "Alice",
		"age":   int64(30),
		"valid": true,
	}

	tree, err := builder.BuildTree(obj)
	if err != nil {
		t.Fatalf("BuildTree failed: %v", err)
	}

	t.Run("GenerateProof for existing path", func(t *testing.T) {
		proof, err := tree.GenerateProof("/name")
		if err != nil {
			t.Fatalf("GenerateProof failed: %v", err)
		}
		if proof.LeafPath != "/name" {
			t.Errorf("LeafPath = %q, want /name", proof.LeafPath)
		}
		if proof.MerkleRoot != tree.Root {
			t.Error("MerkleRoot should match tree root")
		}
	})

	t.Run("GenerateProof for missing path", func(t *testing.T) {
		_, err := tree.GenerateProof("/nonexistent")
		if err == nil {
			t.Error("Expected error for missing path")
		}
	})
}

func TestVerifyProof(t *testing.T) {
	builder := NewMerkleTreeBuilder()

	obj := map[string]any{
		"name": "Alice",
		"age":  int64(30),
	}

	tree, _ := builder.BuildTree(obj)
	proof, _ := tree.GenerateProof("/name")

	t.Run("Valid proof", func(t *testing.T) {
		if !VerifyProof(*proof, tree.Root) {
			t.Error("Valid proof should verify")
		}
	})

	t.Run("Invalid root", func(t *testing.T) {
		if VerifyProof(*proof, "sha256:invalid") {
			t.Error("Proof should fail with wrong root")
		}
	})

	t.Run("Tampered proof", func(t *testing.T) {
		tamperedProof := *proof
		tamperedProof.LeafHash = "sha256:tampered"
		if VerifyProof(tamperedProof, tree.Root) {
			t.Error("Tampered proof should fail verification")
		}
	})
}

//nolint:gocognit // test complexity is acceptable
func TestDeriveEvidenceView(t *testing.T) {
	builder := NewMerkleTreeBuilder()

	pack := map[string]any{
		"name":   "Alice",
		"secret": "confidential",
		"public": true,
	}

	tree, _ := builder.BuildTree(pack)

	t.Run("Disclose policy", func(t *testing.T) {
		policy := ViewPolicy{
			PolicyID: "test-policy",
			Name:     "Test Policy",
			DisclosureRules: []DisclosureRule{
				{PathPattern: "*", Action: "DISCLOSE"},
			},
		}

		view, err := DeriveEvidenceView(pack, tree, policy, "2024-01-01T00:00:00Z")
		if err != nil {
			t.Fatalf("DeriveEvidenceView failed: %v", err)
		}
		if len(view.Disclosed) == 0 {
			t.Error("Expected disclosed fields")
		}
		if len(view.Proofs) == 0 {
			t.Error("Expected proofs for disclosed fields")
		}
	})

	t.Run("Seal policy", func(t *testing.T) {
		policy := ViewPolicy{
			PolicyID: "seal-policy",
			Name:     "Seal All",
			DisclosureRules: []DisclosureRule{
				{PathPattern: "*", Action: "SEAL", Reason: "confidential"},
			},
		}

		view, err := DeriveEvidenceView(pack, tree, policy, "2024-01-01T00:00:00Z")
		if err != nil {
			t.Fatalf("DeriveEvidenceView failed: %v", err)
		}
		if len(view.Sealed) == 0 {
			t.Error("Expected sealed fields")
		}
	})

	t.Run("Mixed policy", func(t *testing.T) {
		policy := ViewPolicy{
			PolicyID: "mixed-policy",
			Name:     "Mixed",
			DisclosureRules: []DisclosureRule{
				{PathPattern: "/name", Action: "DISCLOSE"},
				{PathPattern: "/secret", Action: "SEAL", Reason: "confidential"},
				{PathPattern: "/public", Action: "DISCLOSE"},
			},
		}

		view, err := DeriveEvidenceView(pack, tree, policy, "2024-01-01T00:00:00Z")
		if err != nil {
			t.Fatalf("DeriveEvidenceView failed: %v", err)
		}

		// Check disclosed
		if _, exists := view.Disclosed["/name"]; !exists {
			t.Error("Expected /name to be disclosed")
		}

		// Check sealed
		hasSecret := false
		for _, s := range view.Sealed {
			if s.Path == "/secret" {
				hasSecret = true
				break
			}
		}
		if !hasSecret {
			t.Error("Expected /secret to be sealed")
		}
	})

	t.Run("View determinism", func(t *testing.T) {
		policy := ViewPolicy{
			PolicyID: "test-policy",
			DisclosureRules: []DisclosureRule{
				{PathPattern: "*", Action: "DISCLOSE"},
			},
		}

		view1, _ := DeriveEvidenceView(pack, tree, policy, "2024-01-01T00:00:00Z")
		view2, _ := DeriveEvidenceView(pack, tree, policy, "2024-01-01T00:00:00Z")

		if view1.ViewHash != view2.ViewHash {
			t.Error("DeriveEvidenceView should be deterministic")
		}
	})
}

func TestMatchPath(t *testing.T) {
	tests := []struct {
		path     string
		pattern  string
		expected bool
	}{
		{"/name", "*", true},
		{"/user/name", "/user/*", true},
		{"/user/name/first", "/user/*", true},
		{"/other", "/user/*", false},
		{"/name", "/name", true},
		{"/name", "/other", false},
	}

	for _, tc := range tests {
		result := matchPath(tc.path, tc.pattern)
		if result != tc.expected {
			t.Errorf("matchPath(%q, %q) = %v, want %v", tc.path, tc.pattern, result, tc.expected)
		}
	}
}

func TestGetValueAtPath(t *testing.T) {
	obj := map[string]any{
		"user": map[string]any{
			"name": "Alice",
			"meta": map[string]any{
				"age": int64(30),
			},
		},
		"active": true,
	}

	tests := []struct {
		path     string
		expected any
	}{
		{"/active", true},
		{"/user/name", "Alice"},
		{"/user/meta/age", int64(30)},
		{"/nonexistent", nil},
	}

	for _, tc := range tests {
		result := getValueAtPath(obj, tc.path)
		if result != tc.expected {
			t.Errorf("getValueAtPath(%q) = %v, want %v", tc.path, result, tc.expected)
		}
	}
}
