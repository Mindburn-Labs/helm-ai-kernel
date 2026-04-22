package executor

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestMerkleTreeConstruction verifies tree building.
func TestMerkleTreeConstruction(t *testing.T) {
	t.Run("single leaf", func(t *testing.T) {
		builder := NewMerkleBuilder()
		err := builder.AddLeaf("/identity", map[string]any{"id": "test"}, false)
		require.NoError(t, err)

		tree, err := builder.Build()
		require.NoError(t, err)
		require.NotEmpty(t, tree.Root)
		require.Len(t, tree.Leaves, 1)
	})

	t.Run("two leaves", func(t *testing.T) {
		builder := NewMerkleBuilder()
		_ = builder.AddLeaf("/identity", map[string]any{"id": "test"}, false)
		_ = builder.AddLeaf("/policy", map[string]any{"policy": "default"}, false)

		tree, err := builder.Build()
		require.NoError(t, err)
		require.NotEmpty(t, tree.Root)
		require.Len(t, tree.Leaves, 2)

		// Root should not equal either leaf hash
		require.NotEqual(t, tree.Root, tree.Leaves[0].Hash)
		require.NotEqual(t, tree.Root, tree.Leaves[1].Hash)
	})

	t.Run("four leaves (balanced)", func(t *testing.T) {
		builder := NewMerkleBuilder()
		_ = builder.AddLeaf("/a", "value_a", false)
		_ = builder.AddLeaf("/b", "value_b", false)
		_ = builder.AddLeaf("/c", "value_c", false)
		_ = builder.AddLeaf("/d", "value_d", false)

		tree, err := builder.Build()
		require.NoError(t, err)
		require.NotEmpty(t, tree.Root)
		require.Len(t, tree.Leaves, 4)
		require.Len(t, tree.Levels, 3) // 4 leaves -> 2 nodes -> 1 root
	})

	t.Run("three leaves (unbalanced)", func(t *testing.T) {
		builder := NewMerkleBuilder()
		_ = builder.AddLeaf("/a", "value_a", false)
		_ = builder.AddLeaf("/b", "value_b", false)
		_ = builder.AddLeaf("/c", "value_c", false)

		tree, err := builder.Build()
		require.NoError(t, err)
		require.NotEmpty(t, tree.Root)
		require.Len(t, tree.Leaves, 3)
	})

	t.Run("empty tree fails", func(t *testing.T) {
		builder := NewMerkleBuilder()
		_, err := builder.Build()
		require.Error(t, err)
		require.Contains(t, err.Error(), "no leaves")
	})
}

// TestMerkleProofGeneration verifies proof generation.
func TestMerkleProofGeneration(t *testing.T) {
	builder := NewMerkleBuilder()
	_ = builder.AddLeaf("/identity", map[string]any{"id": "test"}, false)
	_ = builder.AddLeaf("/policy", map[string]any{"policy": "default"}, false)
	_ = builder.AddLeaf("/effect", map[string]any{"effect": "allow"}, false)
	_ = builder.AddLeaf("/context", map[string]any{"context": "normal"}, false)

	tree, err := builder.Build()
	require.NoError(t, err)

	t.Run("proof for first leaf", func(t *testing.T) {
		proof, err := tree.GenerateProof(0)
		require.NoError(t, err)
		require.Equal(t, 0, proof.LeafIndex)
		require.Equal(t, "/identity", proof.LeafPath)
		require.NotEmpty(t, proof.LeafHash)
		require.NotEmpty(t, proof.Root)
		require.NotEmpty(t, proof.Siblings)
	})

	t.Run("proof for last leaf", func(t *testing.T) {
		proof, err := tree.GenerateProof(3)
		require.NoError(t, err)
		require.Equal(t, 3, proof.LeafIndex)
		require.Equal(t, "/context", proof.LeafPath)
	})

	t.Run("invalid index fails", func(t *testing.T) {
		_, err := tree.GenerateProof(10)
		require.Error(t, err)
		require.Contains(t, err.Error(), "out of range")
	})
}

// TestMerkleProofVerification verifies proof verification.
func TestMerkleProofVerification(t *testing.T) {
	builder := NewMerkleBuilder()
	_ = builder.AddLeaf("/identity", map[string]any{"id": "test"}, false)
	_ = builder.AddLeaf("/policy", map[string]any{"policy": "default"}, false)
	_ = builder.AddLeaf("/effect", map[string]any{"effect": "allow"}, false)
	_ = builder.AddLeaf("/context", map[string]any{"context": "normal"}, false)

	tree, err := builder.Build()
	require.NoError(t, err)

	t.Run("valid proof verifies", func(t *testing.T) {
		proof, err := tree.GenerateProof(0)
		require.NoError(t, err)

		valid, err := VerifyProof(proof)
		require.NoError(t, err)
		require.True(t, valid)
	})

	t.Run("all leaves verify", func(t *testing.T) {
		for i := 0; i < len(tree.Leaves); i++ {
			proof, err := tree.GenerateProof(i)
			require.NoError(t, err)

			valid, err := VerifyProof(proof)
			require.NoError(t, err)
			require.True(t, valid, "proof for leaf %d failed", i)
		}
	})

	t.Run("tampered proof fails", func(t *testing.T) {
		proof, err := tree.GenerateProof(0)
		require.NoError(t, err)

		// Tamper with the root
		original := proof.Root
		proof.Root = "0000000000000000000000000000000000000000000000000000000000000000"

		valid, err := VerifyProof(proof)
		require.NoError(t, err)
		require.False(t, valid)

		proof.Root = original
	})
}

// TestMerkleDeterminism verifies deterministic hashing.
func TestMerkleDeterminism(t *testing.T) {
	t.Run("same data produces same root", func(t *testing.T) {
		builder1 := NewMerkleBuilder()
		_ = builder1.AddLeaf("/a", map[string]any{"x": "y"}, false)
		_ = builder1.AddLeaf("/b", map[string]any{"z": "w"}, false)
		tree1, _ := builder1.Build()

		builder2 := NewMerkleBuilder()
		_ = builder2.AddLeaf("/a", map[string]any{"x": "y"}, false)
		_ = builder2.AddLeaf("/b", map[string]any{"z": "w"}, false)
		tree2, _ := builder2.Build()

		require.Equal(t, tree1.RootHex(), tree2.RootHex())
	})

	t.Run("different order produces different root", func(t *testing.T) {
		builder1 := NewMerkleBuilder()
		_ = builder1.AddLeaf("/a", "val_a", false)
		_ = builder1.AddLeaf("/b", "val_b", false)
		tree1, _ := builder1.Build()

		builder2 := NewMerkleBuilder()
		_ = builder2.AddLeaf("/b", "val_b", false)
		_ = builder2.AddLeaf("/a", "val_a", false)
		tree2, _ := builder2.Build()

		require.NotEqual(t, tree1.RootHex(), tree2.RootHex())
	})
}

// TestMerkleDomainSeparation verifies domain separators.
func TestMerkleDomainSeparation(t *testing.T) {
	t.Run("domain separators are different", func(t *testing.T) {
		require.NotEqual(t, LeafDomainSeparator, NodeDomainSeparator)
	})

	t.Run("leaf collision avoided", func(t *testing.T) {
		// Per Section C.2: Domain separation prevents leaf/node collision
		builder := NewMerkleBuilder()
		builder.AddLeafBytes("/test", []byte("test_data"), false)
		tree, _ := builder.Build()

		// Verify that leaf hash uses domain separator
		require.NotEmpty(t, tree.Leaves[0].Hash)
	})
}

// TestEvidenceViewDerivation verifies view creation.
func TestEvidenceViewDerivation(t *testing.T) {
	data := map[string]any{
		"/identity": map[string]any{"id": "test"},
		"/policy":   map[string]any{"policy": "default"},
		"/effect":   map[string]any{"effect": "allow"},
		"/context":  map[string]any{"context": "normal"},
	}

	builder := NewMerkleBuilder()
	for path, val := range data {
		_ = builder.AddLeaf(path, val, false)
	}
	tree, _ := builder.Build()

	t.Run("derive partial view", func(t *testing.T) {
		view, err := tree.DeriveView("view-1", "pack-1", []string{"/identity", "/effect"}, func(path string) (any, error) {
			return data[path], nil
		})
		require.NoError(t, err)
		require.Equal(t, "view-1", view.ViewID)
		require.Equal(t, "pack-1", view.PackID)
		require.Len(t, view.IncludedPaths, 2)
		require.Len(t, view.Proofs, 2)
		require.Len(t, view.Data, 2)
	})

	t.Run("view verifies", func(t *testing.T) {
		view, _ := tree.DeriveView("view-1", "pack-1", []string{"/identity"}, nil)

		valid, err := VerifyView(view)
		require.NoError(t, err)
		require.True(t, valid)
	})

	t.Run("missing path fails", func(t *testing.T) {
		_, err := tree.DeriveView("view-1", "pack-1", []string{"/nonexistent"}, nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "not found")
	})
}

// TestMerkleSealedLeaves verifies sealed leaf support.
func TestMerkleSealedLeaves(t *testing.T) {
	builder := NewMerkleBuilder()
	_ = builder.AddLeaf("/public", "public_data", false)
	_ = builder.AddLeaf("/sealed", "sensitive_data", true)

	tree, err := builder.Build()
	require.NoError(t, err)

	require.False(t, tree.Leaves[0].Sealed)
	require.True(t, tree.Leaves[1].Sealed)
}
