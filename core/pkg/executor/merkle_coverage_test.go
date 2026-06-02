package executor

import (
	"errors"
	"math"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMerkleBuilderAddLeafCanonicalError(t *testing.T) {
	builder := NewMerkleBuilder()
	err := builder.AddLeaf("/bad", math.Inf(1), false)
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to serialize leaf")
}

func TestVerifyProofRejectsMalformedHashes(t *testing.T) {
	tests := []struct {
		name  string
		proof *MerkleProof
		want  string
	}{
		{
			name:  "leaf hash",
			proof: &MerkleProof{LeafHash: "not-hex", Root: strings.Repeat("0", 64)},
			want:  "invalid leaf hash",
		},
		{
			name: "sibling hash",
			proof: &MerkleProof{
				LeafHash: strings.Repeat("0", 64),
				Root:     strings.Repeat("0", 64),
				Siblings: []MerkleSibling{{Hash: "not-hex", Position: "right"}},
			},
			want: "invalid sibling hash",
		},
		{
			name:  "root hash",
			proof: &MerkleProof{LeafHash: strings.Repeat("0", 64), Root: "not-hex"},
			want:  "invalid root hash",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			valid, err := VerifyProof(tt.proof)
			require.False(t, valid)
			require.Error(t, err)
			require.Contains(t, err.Error(), tt.want)
		})
	}
}

func TestEvidenceViewDeriveAndVerifyErrors(t *testing.T) {
	builder := NewMerkleBuilder()
	require.NoError(t, builder.AddLeaf("/identity", map[string]any{"id": "test"}, false))
	require.NoError(t, builder.AddLeaf("/policy", map[string]any{"policy": "default"}, false))
	tree, err := builder.Build()
	require.NoError(t, err)

	_, err = tree.DeriveView("view-err", "pack-1", []string{"/identity"}, func(string) (any, error) {
		return nil, errors.New("data unavailable")
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to get data")

	view, err := tree.DeriveView("view-root-mismatch", "pack-1", []string{"/identity"}, nil)
	require.NoError(t, err)
	view.Proofs[0].Root = strings.Repeat("0", 64)
	valid, err := VerifyView(view)
	require.False(t, valid)
	require.Error(t, err)
	require.Contains(t, err.Error(), "proof root mismatch")

	view, err = tree.DeriveView("view-invalid-proof", "pack-1", []string{"/identity"}, nil)
	require.NoError(t, err)
	view.Proofs[0].LeafHash = "not-hex"
	valid, err = VerifyView(view)
	require.False(t, valid)
	require.Error(t, err)

	malformedTree := &MerkleTree{
		Root:   []byte{0x01},
		Leaves: []MerkleLeaf{{Index: 3, Path: "/bad", Hash: []byte{0x01}}},
		Levels: [][][]byte{{{0x01}}},
	}
	_, err = malformedTree.DeriveView("view-bad-index", "pack-1", []string{"/bad"}, nil)
	require.Error(t, err)

	falseProofView := &EvidenceView{
		RootHash: strings.Repeat("f", 64),
		Proofs: []MerkleProof{{
			LeafPath: "/false",
			LeafHash: strings.Repeat("0", 64),
			Root:     strings.Repeat("f", 64),
		}},
	}
	valid, err = VerifyView(falseProofView)
	require.False(t, valid)
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid proof")
}

func TestMerkleCanonicalHelpersPropagateErrors(t *testing.T) {
	_, err := canonicalJSON(math.Inf(1))
	require.Error(t, err)

	_, err = canonicalJSON(invalidJSONBytes{})
	require.Error(t, err)

	_, err = marshalCanonical(map[string]any{"bad": math.Inf(1)})
	require.Error(t, err)

	_, err = marshalCanonical([]any{"ok", math.Inf(1)})
	require.Error(t, err)

	_, err = marshalCanonical(math.Inf(1))
	require.Error(t, err)

	canonicalArray, err := marshalCanonical([]any{"ok", float64(2)})
	require.NoError(t, err)
	require.Equal(t, `["ok",2]`, string(canonicalArray))
}

type invalidJSONBytes struct{}

func (invalidJSONBytes) MarshalJSON() ([]byte, error) {
	return []byte("{"), nil
}
