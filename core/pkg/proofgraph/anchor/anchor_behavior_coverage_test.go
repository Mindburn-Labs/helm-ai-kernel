package anchor

import (
	"context"
	"errors"
	"testing"
	"time"
)

// ── mock backend ────────────────────────────────────────────────

type comprehensiveMockBackend struct {
	name      string
	anchorErr error
	verifyErr error
}

func (m *comprehensiveMockBackend) Name() string { return m.name }
func (m *comprehensiveMockBackend) Anchor(_ context.Context, req AnchorRequest) (*AnchorReceipt, error) {
	if m.anchorErr != nil {
		return nil, m.anchorErr
	}
	r := &AnchorReceipt{
		Backend:        m.name,
		Request:        req,
		LogID:          "log-001",
		LogIndex:       1,
		IntegratedTime: time.Now(),
		Signature:      "sig-abc",
	}
	r.ReceiptHash = r.ComputeReceiptHash()
	return r, nil
}
func (m *comprehensiveMockBackend) Verify(_ context.Context, _ *AnchorReceipt) error {
	return m.verifyErr
}

// ── AnchorRequest ───────────────────────────────────────────────

func TestComprehensive_AnchorRequest_ComputeDigest(t *testing.T) {
	req := AnchorRequest{
		MerkleRoot:  "abc123",
		FromLamport: 1,
		ToLamport:   10,
		NodeCount:   5,
	}
	digest, err := req.ComputeDigest()
	if err != nil {
		t.Fatalf("ComputeDigest: %v", err)
	}
	if len(digest) != 32 {
		t.Errorf("expected 32-byte SHA-256 digest, got %d", len(digest))
	}
}

func TestComprehensive_AnchorRequest_DigestDeterministic(t *testing.T) {
	req := AnchorRequest{MerkleRoot: "root", FromLamport: 0, ToLamport: 5}
	d1, _ := req.ComputeDigest()
	d2, _ := req.ComputeDigest()
	if string(d1) != string(d2) {
		t.Error("digest should be deterministic")
	}
}

// ── AnchorReceipt ───────────────────────────────────────────────

func TestComprehensive_AnchorReceipt_ComputeReceiptHash(t *testing.T) {
	r := &AnchorReceipt{
		Backend:        "test",
		LogID:          "log-1",
		LogIndex:       1,
		IntegratedTime: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		Request:        AnchorRequest{MerkleRoot: "root-hash"},
	}
	hash := r.ComputeReceiptHash()
	if hash == "" {
		t.Error("receipt hash should not be empty")
	}
	if len(hash) != 64 {
		t.Errorf("expected 64 hex chars, got %d", len(hash))
	}
}

// ── Service ─────────────────────────────────────────────────────

func TestComprehensive_NewService_NoBackends(t *testing.T) {
	_, err := NewService(ServiceConfig{
		Store: NewInMemoryReceiptStore(),
	})
	if err == nil {
		t.Error("should require at least one backend")
	}
}

func TestComprehensive_NewService_NoStore(t *testing.T) {
	_, err := NewService(ServiceConfig{
		Backends: []AnchorBackend{&comprehensiveMockBackend{name: "mock"}},
	})
	if err == nil {
		t.Error("should require receipt store")
	}
}

func TestComprehensive_Service_AnchorNow_Success(t *testing.T) {
	store := NewInMemoryReceiptStore()
	svc, err := NewService(ServiceConfig{
		Backends: []AnchorBackend{&comprehensiveMockBackend{name: "mock"}},
		Store:    store,
	})
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	receipt, err := svc.AnchorNow(context.Background(), AnchorRequest{
		MerkleRoot:  "root-abc",
		FromLamport: 1,
		ToLamport:   10,
		NodeCount:   5,
	})
	if err != nil {
		t.Fatalf("AnchorNow: %v", err)
	}
	if receipt.Backend != "mock" {
		t.Errorf("expected backend mock, got %s", receipt.Backend)
	}
	if svc.LastAnchoredLamport() != 10 {
		t.Errorf("expected last anchored lamport 10, got %d", svc.LastAnchoredLamport())
	}
}

func TestComprehensive_Service_AnchorNow_EmptyRoot(t *testing.T) {
	svc, _ := NewService(ServiceConfig{
		Backends: []AnchorBackend{&comprehensiveMockBackend{name: "mock"}},
		Store:    NewInMemoryReceiptStore(),
	})
	_, err := svc.AnchorNow(context.Background(), AnchorRequest{})
	if err == nil {
		t.Error("should reject empty merkle root")
	}
}

func TestComprehensive_Service_AnchorNow_Failover(t *testing.T) {
	svc, _ := NewService(ServiceConfig{
		Backends: []AnchorBackend{
			&comprehensiveMockBackend{name: "fail", anchorErr: errors.New("down")},
			&comprehensiveMockBackend{name: "ok"},
		},
		Store: NewInMemoryReceiptStore(),
	})
	receipt, err := svc.AnchorNow(context.Background(), AnchorRequest{MerkleRoot: "root"})
	if err != nil {
		t.Fatalf("should failover to second backend: %v", err)
	}
	if receipt.Backend != "ok" {
		t.Errorf("expected backend ok, got %s", receipt.Backend)
	}
}

func TestComprehensive_Service_AnchorNow_AllFail(t *testing.T) {
	svc, _ := NewService(ServiceConfig{
		Backends: []AnchorBackend{
			&comprehensiveMockBackend{name: "fail1", anchorErr: errors.New("down")},
			&comprehensiveMockBackend{name: "fail2", anchorErr: errors.New("down")},
		},
		Store: NewInMemoryReceiptStore(),
	})
	_, err := svc.AnchorNow(context.Background(), AnchorRequest{MerkleRoot: "root"})
	if err == nil {
		t.Error("should fail when all backends fail")
	}
}

func TestComprehensive_Service_VerifyReceipt_UnknownBackend(t *testing.T) {
	svc, _ := NewService(ServiceConfig{
		Backends: []AnchorBackend{&comprehensiveMockBackend{name: "mock"}},
		Store:    NewInMemoryReceiptStore(),
	})
	err := svc.VerifyReceipt(context.Background(), &AnchorReceipt{Backend: "unknown"})
	if err == nil {
		t.Error("should error for unknown backend")
	}
}

// ── InMemoryReceiptStore ────────────────────────────────────────

func TestComprehensive_InMemoryReceiptStore_StoreAndGet(t *testing.T) {
	store := NewInMemoryReceiptStore()
	ctx := context.Background()
	receipt := &AnchorReceipt{Backend: "test", LogIndex: 1, Request: AnchorRequest{FromLamport: 0, ToLamport: 5}}
	_ = store.StoreReceipt(ctx, receipt)
	latest, err := store.GetLatestReceipt(ctx)
	if err != nil {
		t.Fatalf("GetLatestReceipt: %v", err)
	}
	if latest.LogIndex != 1 {
		t.Error("should return stored receipt")
	}
}

func TestComprehensive_InMemoryReceiptStore_EmptyGetLatest(t *testing.T) {
	store := NewInMemoryReceiptStore()
	_, err := store.GetLatestReceipt(context.Background())
	if err == nil {
		t.Error("should error on empty store")
	}
}

func TestComprehensive_InMemoryReceiptStore_GetByRange(t *testing.T) {
	store := NewInMemoryReceiptStore()
	ctx := context.Background()
	_ = store.StoreReceipt(ctx, &AnchorReceipt{Request: AnchorRequest{FromLamport: 0, ToLamport: 10}})
	_ = store.StoreReceipt(ctx, &AnchorReceipt{Request: AnchorRequest{FromLamport: 11, ToLamport: 20}})
	results, _ := store.GetReceiptByLamportRange(ctx, 0, 10)
	if len(results) != 1 {
		t.Errorf("expected 1 receipt in range, got %d", len(results))
	}
}

func TestComprehensive_Service_DefaultInterval(t *testing.T) {
	svc, err := NewService(ServiceConfig{
		Backends: []AnchorBackend{&comprehensiveMockBackend{name: "mock"}},
		Store:    NewInMemoryReceiptStore(),
	})
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	if svc.interval != 5*time.Minute {
		t.Errorf("expected default 5m interval, got %v", svc.interval)
	}
}

func TestComprehensive_Service_LastAnchoredLamport_InitialZero(t *testing.T) {
	svc, _ := NewService(ServiceConfig{
		Backends: []AnchorBackend{&comprehensiveMockBackend{name: "mock"}},
		Store:    NewInMemoryReceiptStore(),
	})
	if svc.LastAnchoredLamport() != 0 {
		t.Error("initial last anchored lamport should be 0")
	}
}
