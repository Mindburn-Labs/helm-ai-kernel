package executor

import (
	"testing"
)

// ────────────────────────────────────────────────────────────────────────
// Merkle tree with 100 leaves
// ────────────────────────────────────────────────────────────────────────

// ────────────────────────────────────────────────────────────────────────
// Evidence pack with 50 entries
// ────────────────────────────────────────────────────────────────────────

// ────────────────────────────────────────────────────────────────────────
// Receipt chain 50 deep
// ────────────────────────────────────────────────────────────────────────

func TestStress_MerkleProfileIDConstant(t *testing.T) {
	if MerkleProfileID != "merkle-v1" {
		t.Fatalf("unexpected profile ID: %s", MerkleProfileID)
	}
}

func TestStress_LeafDomainSeparator(t *testing.T) {
	if len(LeafDomainSeparator) != 1 || LeafDomainSeparator[0] != 0x00 {
		t.Fatal("unexpected leaf domain separator")
	}
}

func TestStress_NodeDomainSeparator(t *testing.T) {
	if len(NodeDomainSeparator) != 1 || NodeDomainSeparator[0] != 0x01 {
		t.Fatal("unexpected node domain separator")
	}
}

type mockMCPClient struct{ result any }

func (m *mockMCPClient) Call(_ string, _ map[string]any) (any, error) { return m.result, nil }
