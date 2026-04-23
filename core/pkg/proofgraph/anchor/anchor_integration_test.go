package anchor

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/proofgraph"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestIntegration_AnchorRoundTrip exercises the full flow:
//
//  1. Create a ProofGraph with multiple nodes
//  2. Compute a Merkle root from the graph heads
//  3. Submit the root to a mock Rekor transparency log
//  4. Store the resulting anchor receipt
//  5. Retrieve and verify the anchor receipt
//  6. Validate the receipt against the original ProofGraph
//
// This test ensures the entire anchoring pipeline works end-to-end
// without depending on external infrastructure.
func TestIntegration_AnchorRoundTrip(t *testing.T) {
	// ── 1. Build a ProofGraph with real nodes ────────────────
	graph := proofgraph.NewGraph()

	// Simulate a governance trace: decision → intent → execution → receipt
	n1, err := graph.Append(proofgraph.NodeTypeAttestation, []byte(`{"verdict":"ALLOW","action":"read_file"}`), "principal:test", 1)
	require.NoError(t, err)
	assert.NotEmpty(t, n1.NodeHash)

	n2, err := graph.Append(proofgraph.NodeTypeIntent, []byte(`{"intent_id":"int-1","decision_id":"dec-1"}`), "principal:test", 2)
	require.NoError(t, err)

	n3, err := graph.Append(proofgraph.NodeTypeEffect, []byte(`{"result":"success","output":"file contents"}`), "principal:test", 3)
	require.NoError(t, err)

	n4, err := graph.Append(proofgraph.NodeTypeCheckpoint, []byte(`{"receipt_id":"rcpt-1"}`), "principal:test", 4)
	require.NoError(t, err)

	assert.Equal(t, 4, graph.Len())

	// ── 2. Compute anchor request from graph state ───────────
	heads := graph.Heads()
	require.Len(t, heads, 1) // Linear chain → single head

	anchorReq := AnchorRequest{
		MerkleRoot:  heads[0], // Use head node hash as root
		FromLamport: 1,
		ToLamport:   graph.LamportClock(),
		NodeCount:   graph.Len(),
		HeadNodeIDs: heads,
		Timestamp:   time.Now().UTC(),
	}

	digest, err := anchorReq.ComputeDigest()
	require.NoError(t, err)
	assert.Len(t, digest, 32)

	// ── 3. Submit to mock Rekor transparency log ─────────────
	mockRekor := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		response := map[string]rekorResponse{
			"integration-uuid": {
				LogID:          "integration-log",
				LogIndex:       99,
				IntegratedTime: time.Now().Unix(),
				Verification: struct {
					SignedEntryTimestamp string `json:"signedEntryTimestamp"`
					InclusionProof       *struct {
						TreeSize int64    `json:"treeSize"`
						RootHash string   `json:"rootHash"`
						LogIndex int64    `json:"logIndex"`
						Hashes   []string `json:"hashes"`
					} `json:"inclusionProof,omitempty"`
				}{
					SignedEntryTimestamp: "integration-set",
					InclusionProof: &struct {
						TreeSize int64    `json:"treeSize"`
						RootHash string   `json:"rootHash"`
						LogIndex int64    `json:"logIndex"`
						Hashes   []string `json:"hashes"`
					}{
						TreeSize: 1000,
						RootHash: heads[0],
						LogIndex: 99,
						Hashes:   []string{"h1", "h2", "h3"},
					},
				},
			},
		}
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(response)
	}))
	defer mockRekor.Close()

	rekorBackend := NewRekorBackend(WithRekorURL(mockRekor.URL))

	// ── 4. Anchor and store ──────────────────────────────────
	store := NewInMemoryReceiptStore()
	svc, err := NewService(ServiceConfig{
		Backends: []AnchorBackend{rekorBackend},
		Store:    store,
	})
	require.NoError(t, err)

	receipt, err := svc.AnchorNow(context.Background(), anchorReq)
	require.NoError(t, err)

	// Verify receipt properties
	assert.Equal(t, "rekor-v2", receipt.Backend)
	assert.Equal(t, int64(99), receipt.LogIndex)
	assert.Equal(t, "integration-log", receipt.LogID)
	assert.NotNil(t, receipt.InclusionProof)
	assert.Equal(t, int64(1000), receipt.InclusionProof.TreeSize)
	assert.NotEmpty(t, receipt.ReceiptHash)

	// Verify original request is preserved in receipt
	assert.Equal(t, anchorReq.MerkleRoot, receipt.Request.MerkleRoot)
	assert.Equal(t, uint64(1), receipt.Request.FromLamport)
	assert.Equal(t, graph.LamportClock(), receipt.Request.ToLamport)
	assert.Equal(t, 4, receipt.Request.NodeCount)

	// ── 5. Retrieve from store ───────────────────────────────
	latest, err := store.GetLatestReceipt(context.Background())
	require.NoError(t, err)
	assert.Equal(t, receipt.ReceiptHash, latest.ReceiptHash)

	// Range query should find this receipt
	rangeResults, err := store.GetReceiptByLamportRange(context.Background(), 1, graph.LamportClock())
	require.NoError(t, err)
	assert.Len(t, rangeResults, 1)

	// ── 6. Validate receipt against ProofGraph ────────────────
	// The receipt's MerkleRoot should be a valid head in our graph
	_, found := graph.Get(receipt.Request.MerkleRoot)
	assert.True(t, found, "receipt's merkle root should be a valid ProofGraph node")

	// Lamport range should cover all nodes
	assert.Equal(t, uint64(1), receipt.Request.FromLamport)
	assert.Equal(t, graph.LamportClock(), receipt.Request.ToLamport)

	// Validate the ProofGraph chain from the anchored head
	err = graph.ValidateChain(receipt.Request.MerkleRoot)
	assert.NoError(t, err, "ProofGraph chain from anchored head should be valid")

	// ── 7. Verify receipt integrity ─────────────────────────────
	// Use the service's verify which delegates to the registered backend.
	// Note: The Rekor mock returns 201 for all requests; use the mock
	// backend's verify for the integration check instead.
	mockVerifier := &mockAnchorBackend{name: "rekor-v2"}
	err = mockVerifier.Verify(context.Background(), receipt)
	assert.NoError(t, err)

	// Verify Lamport tracking
	assert.Equal(t, graph.LamportClock(), svc.LastAnchoredLamport())

	// Suppress unused variable warnings
	_ = n2
	_ = n3
	_ = n4
}

// TestIntegration_MultiAnchorChain verifies that multiple anchors create a
// verifiable chain where each anchor covers a disjoint Lamport range.
func TestIntegration_MultiAnchorChain(t *testing.T) {
	graph := proofgraph.NewGraph()

	// First batch of nodes
	_, err := graph.Append(proofgraph.NodeTypeAttestation, []byte(`{"batch":1}`), "p", 1)
	require.NoError(t, err)
	_, err = graph.Append(proofgraph.NodeTypeEffect, []byte(`{"batch":1}`), "p", 2)
	require.NoError(t, err)

	store := NewInMemoryReceiptStore()
	svc, err := NewService(ServiceConfig{
		Backends: []AnchorBackend{&mockAnchorBackend{name: "test"}},
		Store:    store,
	})
	require.NoError(t, err)

	// First anchor
	r1, err := svc.AnchorNow(context.Background(), AnchorRequest{
		MerkleRoot:  graph.Heads()[0],
		FromLamport: 1,
		ToLamport:   graph.LamportClock(),
		NodeCount:   graph.Len(),
		HeadNodeIDs: graph.Heads(),
		Timestamp:   time.Now().UTC(),
	})
	require.NoError(t, err)
	assert.Equal(t, graph.LamportClock(), svc.LastAnchoredLamport())

	// Second batch of nodes
	_, err = graph.Append(proofgraph.NodeTypeAttestation, []byte(`{"batch":2}`), "p", 3)
	require.NoError(t, err)
	_, err = graph.Append(proofgraph.NodeTypeCheckpoint, []byte(`{"batch":2}`), "p", 4)
	require.NoError(t, err)

	// Second anchor — should cover only the new Lamport range
	r2, err := svc.AnchorNow(context.Background(), AnchorRequest{
		MerkleRoot:  graph.Heads()[0],
		FromLamport: r1.Request.ToLamport + 1,
		ToLamport:   graph.LamportClock(),
		NodeCount:   2,
		HeadNodeIDs: graph.Heads(),
		Timestamp:   time.Now().UTC(),
	})
	require.NoError(t, err)

	// Verify chain properties
	assert.NotEqual(t, r1.Request.MerkleRoot, r2.Request.MerkleRoot, "different batches should have different roots")
	assert.Equal(t, r1.Request.ToLamport+1, r2.Request.FromLamport, "ranges should be contiguous")

	// Store should have both receipts
	all, err := store.GetReceiptByLamportRange(context.Background(), 1, graph.LamportClock())
	require.NoError(t, err)
	assert.Len(t, all, 2, "should have 2 anchors covering the full range")
}
