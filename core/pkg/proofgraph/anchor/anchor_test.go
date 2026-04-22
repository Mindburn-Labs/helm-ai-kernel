package anchor

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAnchorRequest_ComputeDigest(t *testing.T) {
	req := AnchorRequest{
		MerkleRoot:  "abc123def456",
		FromLamport: 1,
		ToLamport:   100,
		NodeCount:   50,
		HeadNodeIDs: []string{"head1", "head2"},
		Timestamp:   time.Date(2026, 2, 25, 12, 0, 0, 0, time.UTC),
	}

	d1, err := req.ComputeDigest()
	require.NoError(t, err)
	assert.Len(t, d1, 32, "SHA-256 digest should be 32 bytes")

	// Same request should produce same digest (deterministic).
	d2, err := req.ComputeDigest()
	require.NoError(t, err)
	assert.Equal(t, d1, d2, "digest should be deterministic")

	// Different request should produce different digest.
	req.MerkleRoot = "different"
	d3, err := req.ComputeDigest()
	require.NoError(t, err)
	assert.NotEqual(t, d1, d3, "different input should produce different digest")
}

func TestAnchorReceipt_ComputeReceiptHash(t *testing.T) {
	receipt := &AnchorReceipt{
		Backend: "test",
		Request: AnchorRequest{
			MerkleRoot: "abc123",
		},
		LogID:          "test-log",
		LogIndex:       42,
		IntegratedTime: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
	}

	hash := receipt.ComputeReceiptHash()
	assert.NotEmpty(t, hash)
	assert.Len(t, hash, 64, "SHA-256 hex should be 64 chars")

	// Deterministic.
	assert.Equal(t, hash, receipt.ComputeReceiptHash())
}

// mockAnchorBackend implements AnchorBackend for testing.
type mockAnchorBackend struct {
	name      string
	shouldErr bool
}

func (m *mockAnchorBackend) Name() string { return m.name }

func (m *mockAnchorBackend) Anchor(_ context.Context, req AnchorRequest) (*AnchorReceipt, error) {
	if m.shouldErr {
		return nil, fmt.Errorf("mock error")
	}
	receipt := &AnchorReceipt{
		Backend:        m.name,
		Request:        req,
		LogID:          "mock-log-id",
		LogIndex:       1,
		IntegratedTime: time.Now().UTC(),
		Signature:      "mock-sig",
	}
	receipt.ReceiptHash = receipt.ComputeReceiptHash()
	return receipt, nil
}

func (m *mockAnchorBackend) Verify(_ context.Context, receipt *AnchorReceipt) error {
	if receipt.Backend != m.name {
		return fmt.Errorf("backend mismatch")
	}
	return nil
}

func TestService_AnchorNow(t *testing.T) {
	store := NewInMemoryReceiptStore()

	svc, err := NewService(ServiceConfig{
		Backends: []AnchorBackend{
			&mockAnchorBackend{name: "primary"},
		},
		Store: store,
	})
	require.NoError(t, err)

	req := AnchorRequest{
		MerkleRoot:  "deadbeef",
		FromLamport: 1,
		ToLamport:   50,
		NodeCount:   25,
		Timestamp:   time.Now().UTC(),
	}

	receipt, err := svc.AnchorNow(context.Background(), req)
	require.NoError(t, err)
	assert.Equal(t, "primary", receipt.Backend)
	assert.Equal(t, "deadbeef", receipt.Request.MerkleRoot)
	assert.Equal(t, int64(1), receipt.LogIndex)
	assert.Equal(t, uint64(50), svc.LastAnchoredLamport())

	// Verify receipt is persisted.
	latest, err := store.GetLatestReceipt(context.Background())
	require.NoError(t, err)
	assert.Equal(t, receipt.ReceiptHash, latest.ReceiptHash)
}

func TestService_Failover(t *testing.T) {
	store := NewInMemoryReceiptStore()

	svc, err := NewService(ServiceConfig{
		Backends: []AnchorBackend{
			&mockAnchorBackend{name: "primary", shouldErr: true},    // Fails
			&mockAnchorBackend{name: "secondary", shouldErr: false}, // Succeeds
		},
		Store: store,
	})
	require.NoError(t, err)

	req := AnchorRequest{
		MerkleRoot:  "cafebabe",
		FromLamport: 1,
		ToLamport:   10,
		NodeCount:   5,
		Timestamp:   time.Now().UTC(),
	}

	receipt, err := svc.AnchorNow(context.Background(), req)
	require.NoError(t, err)
	assert.Equal(t, "secondary", receipt.Backend, "should fail over to secondary")
}

func TestService_AllBackendsFail(t *testing.T) {
	store := NewInMemoryReceiptStore()

	svc, err := NewService(ServiceConfig{
		Backends: []AnchorBackend{
			&mockAnchorBackend{name: "a", shouldErr: true},
			&mockAnchorBackend{name: "b", shouldErr: true},
		},
		Store: store,
	})
	require.NoError(t, err)

	req := AnchorRequest{
		MerkleRoot:  "deadbeef",
		FromLamport: 1,
		ToLamport:   10,
		NodeCount:   5,
		Timestamp:   time.Now().UTC(),
	}

	_, err = svc.AnchorNow(context.Background(), req)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "all backends failed")
}

func TestService_EmptyMerkleRoot(t *testing.T) {
	store := NewInMemoryReceiptStore()

	svc, err := NewService(ServiceConfig{
		Backends: []AnchorBackend{&mockAnchorBackend{name: "test"}},
		Store:    store,
	})
	require.NoError(t, err)

	_, err = svc.AnchorNow(context.Background(), AnchorRequest{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "empty merkle root")
}

func TestService_VerifyReceipt(t *testing.T) {
	backend := &mockAnchorBackend{name: "test"}
	store := NewInMemoryReceiptStore()

	svc, err := NewService(ServiceConfig{
		Backends: []AnchorBackend{backend},
		Store:    store,
	})
	require.NoError(t, err)

	receipt := &AnchorReceipt{
		Backend: "test",
		LogID:   "test-log",
	}

	err = svc.VerifyReceipt(context.Background(), receipt)
	assert.NoError(t, err)

	// Unknown backend should fail.
	receipt.Backend = "unknown"
	err = svc.VerifyReceipt(context.Background(), receipt)
	assert.Error(t, err)
}

func TestNewService_Validation(t *testing.T) {
	_, err := NewService(ServiceConfig{})
	assert.Error(t, err, "should require backends")

	_, err = NewService(ServiceConfig{
		Backends: []AnchorBackend{&mockAnchorBackend{name: "test"}},
	})
	assert.Error(t, err, "should require store")
}

func TestInMemoryReceiptStore(t *testing.T) {
	store := NewInMemoryReceiptStore()
	ctx := context.Background()

	// Empty store.
	_, err := store.GetLatestReceipt(ctx)
	assert.Error(t, err)

	// Store some receipts.
	r1 := &AnchorReceipt{Backend: "test", Request: AnchorRequest{FromLamport: 1, ToLamport: 10}}
	r2 := &AnchorReceipt{Backend: "test", Request: AnchorRequest{FromLamport: 11, ToLamport: 20}}

	require.NoError(t, store.StoreReceipt(ctx, r1))
	require.NoError(t, store.StoreReceipt(ctx, r2))

	latest, err := store.GetLatestReceipt(ctx)
	require.NoError(t, err)
	assert.Equal(t, uint64(11), latest.Request.FromLamport)

	// Range query.
	results, err := store.GetReceiptByLamportRange(ctx, 1, 20)
	require.NoError(t, err)
	assert.Len(t, results, 2)
}

func TestRekorBackend_MockServer(t *testing.T) {
	// Create a mock Rekor server.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			response := map[string]rekorResponse{
				"test-uuid": {
					LogID:          "test-log-id",
					LogIndex:       42,
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
						SignedEntryTimestamp: "mock-set",
						InclusionProof: &struct {
							TreeSize int64    `json:"treeSize"`
							RootHash string   `json:"rootHash"`
							LogIndex int64    `json:"logIndex"`
							Hashes   []string `json:"hashes"`
						}{
							TreeSize: 100,
							RootHash: "abc123",
							LogIndex: 42,
							Hashes:   []string{"hash1", "hash2"},
						},
					},
				},
			}
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(response)
			return
		}

		// GET for verification
		response := map[string]rekorResponse{
			"test-uuid": {
				LogID:          "test-log-id",
				LogIndex:       42,
				IntegratedTime: time.Now().Unix(),
			},
		}
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	backend := NewRekorBackend(WithRekorURL(server.URL))
	assert.Equal(t, "rekor-v2", backend.Name())

	req := AnchorRequest{
		MerkleRoot:  "deadbeef01234567890abcdef",
		FromLamport: 1,
		ToLamport:   50,
		NodeCount:   25,
		Timestamp:   time.Now().UTC(),
	}

	receipt, err := backend.Anchor(context.Background(), req)
	require.NoError(t, err)
	assert.Equal(t, "rekor-v2", receipt.Backend)
	assert.Equal(t, int64(42), receipt.LogIndex)
	assert.Equal(t, "test-log-id", receipt.LogID)
	assert.NotNil(t, receipt.InclusionProof)
	assert.Equal(t, int64(100), receipt.InclusionProof.TreeSize)
	assert.NotEmpty(t, receipt.ReceiptHash)

	// Verify against mock.
	err = backend.Verify(context.Background(), receipt)
	assert.NoError(t, err)
}
