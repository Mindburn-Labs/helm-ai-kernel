package main

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/contracts"
	helmcrypto "github.com/Mindburn-Labs/helm-oss/core/pkg/crypto"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/store"
)

type captureReceiptStore struct {
	last     *contracts.Receipt
	stored   *contracts.Receipt
	storeErr error
}

func (s *captureReceiptStore) Get(context.Context, string) (*contracts.Receipt, error) {
	return nil, errors.New("not implemented")
}

func (s *captureReceiptStore) GetByReceiptID(context.Context, string) (*contracts.Receipt, error) {
	return nil, errors.New("not implemented")
}

func (s *captureReceiptStore) List(context.Context, int) ([]*contracts.Receipt, error) {
	return nil, errors.New("not implemented")
}

func (s *captureReceiptStore) ListSince(context.Context, uint64, int) ([]*contracts.Receipt, error) {
	return nil, errors.New("not implemented")
}

func (s *captureReceiptStore) ListByAgent(context.Context, string, uint64, int) ([]*contracts.Receipt, error) {
	return nil, errors.New("not implemented")
}

func (s *captureReceiptStore) Store(_ context.Context, receipt *contracts.Receipt) error {
	if s.storeErr != nil {
		return s.storeErr
	}
	s.stored = receipt
	return nil
}

func (s *captureReceiptStore) AppendCausal(ctx context.Context, _ string, build store.CausalReceiptBuilder) error {
	lamport := uint64(1)
	prevHash := ""
	if s.last != nil {
		lamport = s.last.LamportClock + 1
		hash, err := contracts.ReceiptChainHash(s.last)
		if err != nil {
			return err
		}
		prevHash = hash
	}
	receipt, err := build(s.last, lamport, prevHash)
	if err != nil {
		return err
	}
	return s.Store(ctx, receipt)
}

func (s *captureReceiptStore) GetLastForSession(context.Context, string) (*contracts.Receipt, error) {
	return s.last, nil
}

func TestPersistDecisionReceiptSignsAndStoresReceipt(t *testing.T) {
	signer, err := helmcrypto.NewEd25519Signer("test")
	if err != nil {
		t.Fatal(err)
	}
	store := &captureReceiptStore{}
	svc := &Services{ReceiptStore: store, ReceiptSigner: signer}
	decision := &contracts.DecisionRecord{
		ID:                 "dec-1",
		Action:             "EXECUTE_TOOL",
		Verdict:            string(contracts.VerdictDeny),
		PolicyDecisionHash: "sha256:pdp",
		Timestamp:          time.Unix(1700000000, 0).UTC(),
	}

	err = persistDecisionReceipt(context.Background(), svc, decision, "agent.test", []byte("EXECUTE_TOOL:tool"), map[string]any{"source": "test"})
	if err != nil {
		t.Fatalf("persist receipt: %v", err)
	}
	if store.stored == nil {
		t.Fatal("receipt was not stored")
	}
	if store.stored.Signature == "" {
		t.Fatal("receipt signature was not set")
	}
	valid, err := signer.VerifyReceipt(store.stored)
	if err != nil || !valid {
		t.Fatalf("receipt signature invalid: valid=%v err=%v receipt=%+v", valid, err, store.stored)
	}
	if store.stored.Timestamp != decision.Timestamp {
		t.Fatalf("timestamp = %s, want %s", store.stored.Timestamp, decision.Timestamp)
	}
}

func TestPersistDecisionReceiptLinksToCanonicalPreviousReceiptHash(t *testing.T) {
	signer, err := helmcrypto.NewEd25519Signer("test")
	if err != nil {
		t.Fatal(err)
	}
	previous := &contracts.Receipt{
		ReceiptID:    "rcpt-prev",
		DecisionID:   "dec-prev",
		EffectID:     "EXECUTE_TOOL",
		Status:       string(contracts.VerdictAllow),
		Timestamp:    time.Unix(1699999999, 0).UTC(),
		ExecutorID:   "agent.test",
		Metadata:     map[string]any{"resource": "tool-a"},
		Signature:    "sig-prev",
		LamportClock: 7,
		ArgsHash:     "sha256:args-prev",
	}
	expectedPrevHash, err := contracts.ReceiptChainHash(previous)
	if err != nil {
		t.Fatal(err)
	}
	store := &captureReceiptStore{last: previous}
	svc := &Services{ReceiptStore: store, ReceiptSigner: signer}
	decision := &contracts.DecisionRecord{
		ID:                 "dec-next",
		Action:             "EXECUTE_TOOL",
		Verdict:            string(contracts.VerdictAllow),
		PolicyDecisionHash: "sha256:pdp",
		Timestamp:          time.Unix(1700000000, 0).UTC(),
	}

	err = persistDecisionReceipt(context.Background(), svc, decision, "agent.test", []byte("EXECUTE_TOOL:tool"), map[string]any{"source": "test"})
	if err != nil {
		t.Fatalf("persist receipt: %v", err)
	}
	if store.stored.PrevHash != expectedPrevHash {
		t.Fatalf("prev_hash = %q, want %q", store.stored.PrevHash, expectedPrevHash)
	}
	if store.stored.LamportClock != previous.LamportClock+1 {
		t.Fatalf("lamport = %d, want %d", store.stored.LamportClock, previous.LamportClock+1)
	}
}

func TestPersistDecisionReceiptReturnsStoreError(t *testing.T) {
	signer, err := helmcrypto.NewEd25519Signer("test")
	if err != nil {
		t.Fatal(err)
	}
	storeErr := errors.New("store down")
	svc := &Services{ReceiptStore: &captureReceiptStore{storeErr: storeErr}, ReceiptSigner: signer}
	decision := &contracts.DecisionRecord{ID: "dec-2", Verdict: string(contracts.VerdictDeny), Timestamp: time.Now().UTC()}

	err = persistDecisionReceipt(context.Background(), svc, decision, "agent.test", []byte("body"), nil)
	if !errors.Is(err, storeErr) {
		t.Fatalf("expected store error, got %v", err)
	}
}
