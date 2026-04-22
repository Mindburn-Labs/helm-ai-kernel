package aigp

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMerkleTree_RootAndProof(t *testing.T) {
	hashes := []string{"aaa", "bbb", "ccc", "ddd"}
	tree := NewMerkleTree(hashes)

	assert.NotEmpty(t, tree.Root())

	// Every leaf should have a valid inclusion proof
	for i := range hashes {
		proof, err := tree.InclusionProof(i)
		require.NoError(t, err)
		assert.True(t, VerifyInclusion(proof), "proof for leaf %d should verify", i)
	}
}

func TestMerkleTree_SingleLeaf(t *testing.T) {
	tree := NewMerkleTree([]string{"solo"})
	assert.NotEmpty(t, tree.Root())

	proof, err := tree.InclusionProof(0)
	require.NoError(t, err)
	assert.True(t, VerifyInclusion(proof))
}

func TestMerkleTree_Empty(t *testing.T) {
	tree := NewMerkleTree(nil)
	assert.Empty(t, tree.Root())
}

func TestMerkleTree_TamperedProof(t *testing.T) {
	tree := NewMerkleTree([]string{"a", "b", "c", "d"})
	proof, _ := tree.InclusionProof(0)

	// Tamper with a sibling hash
	if len(proof.Siblings) > 0 {
		proof.Siblings[0].Hash = "tampered"
	}
	assert.False(t, VerifyInclusion(proof), "tampered proof should not verify")
}

func TestMerkleTree_OutOfRange(t *testing.T) {
	tree := NewMerkleTree([]string{"a", "b"})
	_, err := tree.InclusionProof(5)
	assert.Error(t, err)
}
