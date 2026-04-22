package merkle

import (
	"testing"
)

func TestMerkleTree(t *testing.T) {
	data := map[string]interface{}{
		"/a": "valueA",
		"/b": "valueB",
		"/c": "valueC",
	}

	tree, err := BuildMerkleTree(data)
	if err != nil {
		t.Fatalf("BuildMerkleTree failed: %v", err)
	}

	if tree.Root == "" {
		t.Error("Root is empty")
	}

	if len(tree.Leaves) != 3 {
		t.Errorf("Expected 3 leaves, got %d", len(tree.Leaves))
	}

	// Verify duplicate balancing: with 3 leaves, tree should be:
	//       Root
	//      /    \
	//     N1     N2
	//    /  \   /  \
	//   L1  L2 L3  L3 (dup)

	// Level 0: [L1, L2, L3] -> hash extraction: [H1, H2, H3]
	// Level 1: [Hash(H1,H2), Hash(H3,H3)] -> N1, N2
	// Level 2: [Hash(N1,N2)] -> Root

	// Let's verify proof manually for /c (L3)
	// Sibling of L3 is L3 itself (Right).
	// Parent is N2.
	// Sibling of N2 is N1 (Left).
	// Root is Hash(N1, N2).

	// Actually, `BuildMerkleTree` builds the tree but doesn't expose a `GenerateProof` method yet.
	// We can manually construct a proof struct to test VerifyInclusionProof.

	// Helper to get hash
	getHash := func(idx int) string { return tree.Leaves[idx].LeafHash }

	h1 := getHash(0) // /a
	h2 := getHash(1) // /b
	h3 := getHash(2) // /c

	n1 := buildNodeHash(h1, h2)
	n2 := buildNodeHash(h3, h3) // duplicated

	root := buildNodeHash(n1, n2)

	if tree.Root != root {
		t.Errorf("Root mismatch. Got %s, Calc %s", tree.Root, root)
	}

	// Test Verification
	proof := InclusionProof{
		LeafPath:   "/c",
		LeafHash:   h3,
		MerkleRoot: root,
		ProofPath: []ProofStep{
			{Side: "R", SiblingHash: h3}, // Sibling of L3 is L3
			{Side: "L", SiblingHash: n1}, // Sibling of N2 is N1
		},
	}

	if !VerifyInclusionProof(proof, root) {
		t.Error("VerifyInclusionProof failed for valid proof")
	}

	// Invalid Proof
	badProof := proof
	badProof.LeafHash = h1 // wrong leaf hash
	if VerifyInclusionProof(badProof, root) {
		t.Error("VerifyInclusionProof passed for invalid proof")
	}
}
