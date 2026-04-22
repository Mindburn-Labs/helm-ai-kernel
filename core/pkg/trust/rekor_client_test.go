package trust

import (
	"encoding/base64"
	"encoding/json"
	"testing"
)

func TestNewRekorClient(t *testing.T) {
	t.Run("requires log URL", func(t *testing.T) {
		_, err := NewRekorClient(RekorClientConfig{})
		if err == nil {
			t.Error("expected error for missing log URL")
		}
	})

	t.Run("creates client with valid config", func(t *testing.T) {
		client, err := NewRekorClient(RekorClientConfig{
			LogURL: "https://rekor.sigstore.dev",
		})
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if client == nil {
			t.Error("expected non-nil client")
		}
	})
}

func TestRekorClient_verifyInclusionProof(t *testing.T) {
	client := &RekorClient{
		logURL: "https://rekor.sigstore.dev",
	}

	t.Run("rejects nil inclusion proof", func(t *testing.T) {
		entry := &RekorEntry{
			LogIndex:       1,
			InclusionProof: nil,
		}

		err := client.verifyInclusionProof(entry)
		if err == nil {
			t.Error("expected error for nil inclusion proof")
		}
	})

	t.Run("verifies valid inclusion proof", func(t *testing.T) {
		// Create a simple valid proof for a single-element tree
		// The verifier JSON-marshals entry.Body, so we need to match that
		body := RekorBody{
			Kind:       "helmpack",
			APIVersion: "v1",
		}

		// Marshal like the verifier does
		leafData, _ := json.Marshal(body)
		leafHash := computeLeafHash(leafData)

		entry := &RekorEntry{
			LogIndex: 0,
			Body:     body,
			InclusionProof: &InclusionProof{
				LogIndex: 0,
				RootHash: leafHash, // For single element, root = leaf
				TreeSize: 1,
				Hashes:   []string{}, // No siblings needed for single element
			},
		}

		err := client.verifyInclusionProof(entry)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})
}

func TestRekorClient_verifySignedTreeHead(t *testing.T) {
	t.Run("detects tree size regression", func(t *testing.T) {
		client := &RekorClient{
			trustedRoot: &SignedTreeHead{
				TreeSize: 100,
				RootHash: "abc123",
			},
		}

		entry := &RekorEntry{
			InclusionProof: &InclusionProof{
				TreeSize: 50, // Smaller than trusted
				RootHash: "def456",
			},
		}

		err := client.verifySignedTreeHead(entry)
		if err == nil {
			t.Error("expected error for tree size regression")
		}
	})

	t.Run("allows tree growth", func(t *testing.T) {
		client := &RekorClient{
			trustedRoot: &SignedTreeHead{
				TreeSize: 100,
				RootHash: "abc123",
			},
		}

		entry := &RekorEntry{
			InclusionProof: &InclusionProof{
				TreeSize: 150, // Larger than trusted
				RootHash: "def456",
			},
		}

		err := client.verifySignedTreeHead(entry)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})
}

func TestComputeLeafHash(t *testing.T) {
	data := []byte("test data")
	hash := computeLeafHash(data)

	// Should be base64 encoded
	_, err := base64.StdEncoding.DecodeString(hash)
	if err != nil {
		t.Errorf("hash should be valid base64: %v", err)
	}

	// Should be deterministic
	hash2 := computeLeafHash(data)
	if hash != hash2 {
		t.Error("hash should be deterministic")
	}
}

func TestComputeRootFromProof(t *testing.T) {
	t.Run("returns leaf hash for empty proof", func(t *testing.T) {
		leafHash := base64.StdEncoding.EncodeToString([]byte("leaf"))

		root, err := computeRootFromProof(0, 1, leafHash, []string{})
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if root != leafHash {
			t.Error("root should equal leaf for empty proof")
		}
	})

	t.Run("computes root with single sibling", func(t *testing.T) {
		leafHash := computeLeafHash([]byte("left"))
		siblingHash := computeLeafHash([]byte("right"))

		root, err := computeRootFromProof(0, 2, leafHash, []string{siblingHash})
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}

		// Root should be different from inputs
		if root == leafHash || root == siblingHash {
			t.Error("root should combine both hashes")
		}
	})
}

func TestVerifyInclusionProofBytes(t *testing.T) {
	t.Run("rejects nil proof", func(t *testing.T) {
		err := VerifyInclusionProofBytes([]byte("data"), nil)
		if err == nil {
			t.Error("expected error for nil proof")
		}
	})

	t.Run("verifies matching proof", func(t *testing.T) {
		leafData := []byte("test leaf data")
		leafHash := computeLeafHash(leafData)

		proof := &InclusionProof{
			LogIndex: 0,
			RootHash: leafHash,
			TreeSize: 1,
			Hashes:   []string{},
		}

		err := VerifyInclusionProofBytes(leafData, proof)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("rejects mismatched root", func(t *testing.T) {
		leafData := []byte("test leaf data")

		proof := &InclusionProof{
			LogIndex: 0,
			RootHash: "wrong-root-hash",
			TreeSize: 1,
			Hashes:   []string{},
		}

		err := VerifyInclusionProofBytes(leafData, proof)
		if err == nil {
			t.Error("expected error for root mismatch")
		}
	})
}

func TestGetCheckpointRef(t *testing.T) {
	client := &RekorClient{}

	entry := &RekorEntry{
		LogID:    "rekor.sigstore.dev",
		LogIndex: 12345,
		InclusionProof: &InclusionProof{
			TreeSize: 100000,
			RootHash: "abc123xyz",
		},
	}

	ref := client.GetCheckpointRef(entry)

	if ref.LogID != entry.LogID {
		t.Errorf("wrong LogID: %s", ref.LogID)
	}
	if ref.LogIndex != entry.LogIndex {
		t.Errorf("wrong LogIndex: %d", ref.LogIndex)
	}
	if ref.TreeSize != entry.InclusionProof.TreeSize {
		t.Errorf("wrong TreeSize: %d", ref.TreeSize)
	}
	if ref.RootHash != entry.InclusionProof.RootHash {
		t.Errorf("wrong RootHash: %s", ref.RootHash)
	}
	if ref.VerifiedAt.IsZero() {
		t.Error("VerifiedAt should be set")
	}
}
