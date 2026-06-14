package store

import (
	"context"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

// TestSQLiteReceiptPersistsTransparencyAnchor proves the MIN-720 persistence
// gap is closed: LogID, LeafIndex, and the Transparency anchor survive a
// store/reload round-trip. Before the fix these fields were silently dropped.
func TestSQLiteReceiptPersistsTransparencyAnchor(t *testing.T) {
	store, cleanup := newTestSQLiteStore(t)
	defer cleanup()
	ctx := context.Background()

	r := &contracts.Receipt{
		ReceiptID:    "rcpt-anchored",
		DecisionID:   "dec-anchored",
		EffectID:     "e",
		Status:       "ALLOW",
		Timestamp:    time.Now().UTC(),
		ExecutorID:   "agent.exec",
		LamportClock: 1,
		LogID:        "logid-abc123",
		LeafIndex:    42,
		Transparency: &contracts.TransparencyAnchor{
			Backend: "translog",
			LogID:   "logid-abc123",
		},
	}
	if err := store.Store(ctx, r); err != nil {
		t.Fatalf("store: %v", err)
	}

	got, err := store.GetByReceiptID(ctx, "rcpt-anchored")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.LogID != "logid-abc123" {
		t.Fatalf("LogID not persisted: got %q", got.LogID)
	}
	if got.LeafIndex != 42 {
		t.Fatalf("LeafIndex not persisted: got %d", got.LeafIndex)
	}
	if got.Transparency == nil {
		t.Fatal("Transparency anchor not persisted (nil)")
	}
	if got.Transparency.Backend != "translog" || got.Transparency.LogID != "logid-abc123" {
		t.Fatalf("Transparency anchor mismatch: %+v", got.Transparency)
	}
	if got.Transparency.Deferred {
		t.Fatalf("anchored receipt should not be deferred: %+v", got.Transparency)
	}
}

// TestSQLiteReceiptPersistsDeferredAnchor proves the degrade-mode promise is
// backed: a receipt whose anchor is Deferred=true persists that marker so it
// can be backfilled later. Before the fix the "backfill later" deferral was
// dropped on write.
func TestSQLiteReceiptPersistsDeferredAnchor(t *testing.T) {
	store, cleanup := newTestSQLiteStore(t)
	defer cleanup()
	ctx := context.Background()

	deferredUntil := time.Now().Add(time.Hour).UTC().Truncate(time.Second)
	r := &contracts.Receipt{
		ReceiptID:    "rcpt-deferred",
		DecisionID:   "dec-deferred",
		EffectID:     "e",
		Status:       "ALLOW",
		Timestamp:    time.Now().UTC(),
		ExecutorID:   "agent.exec",
		LamportClock: 1,
		LogID:        "logid-degrade",
		Transparency: &contracts.TransparencyAnchor{
			Backend:       "translog",
			LogID:         "logid-degrade",
			Deferred:      true,
			DeferredUntil: deferredUntil,
		},
	}
	if err := store.Store(ctx, r); err != nil {
		t.Fatalf("store: %v", err)
	}

	got, err := store.GetByReceiptID(ctx, "rcpt-deferred")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Transparency == nil {
		t.Fatal("deferred Transparency anchor not persisted (nil)")
	}
	if !got.Transparency.Deferred {
		t.Fatalf("Deferred marker not persisted: %+v", got.Transparency)
	}
	if !got.Transparency.DeferredUntil.Equal(deferredUntil) {
		t.Fatalf("DeferredUntil not persisted: got %v want %v", got.Transparency.DeferredUntil, deferredUntil)
	}

	// A receipt with no anchor at all must still round-trip with a nil anchor.
	plain := &contracts.Receipt{
		ReceiptID:  "rcpt-plain",
		DecisionID: "dec-plain",
		Status:     "ALLOW",
		Timestamp:  time.Now().UTC(),
	}
	if err := store.Store(ctx, plain); err != nil {
		t.Fatalf("store plain: %v", err)
	}
	gotPlain, err := store.GetByReceiptID(ctx, "rcpt-plain")
	if err != nil {
		t.Fatalf("get plain: %v", err)
	}
	if gotPlain.Transparency != nil || gotPlain.LogID != "" || gotPlain.LeafIndex != 0 {
		t.Fatalf("unanchored receipt should round-trip empty, got %+v", gotPlain)
	}
}

// TestTransparencyAnchorFieldsDoNotEnterChainHash guards the canonicalization
// invariant from anchorReceiptTransparency: the transparency anchor is recorded
// AFTER ReceiptChainHash is computed, and the anchor fields must not alter the
// canonical chain hash. If they did, the leaf hash used to anchor the receipt
// would no longer match the persisted receipt's own chain hash and the
// prev_hash of the next causal receipt would shift, breaking verification.
func TestTransparencyAnchorFieldsDoNotEnterChainHash(t *testing.T) {
	base := &contracts.Receipt{
		ReceiptID:    "rcpt-hash",
		DecisionID:   "dec-hash",
		EffectID:     "e",
		Status:       "ALLOW",
		Timestamp:    time.Unix(1700000000, 0).UTC(),
		ExecutorID:   "agent.exec",
		LamportClock: 1,
		ArgsHash:     "args",
	}
	before, err := contracts.ReceiptChainHash(base)
	if err != nil {
		t.Fatalf("hash before: %v", err)
	}

	base.LogID = "logid-abc123"
	base.LeafIndex = 7
	base.Transparency = &contracts.TransparencyAnchor{Backend: "translog", LogID: "logid-abc123"}

	after, err := contracts.ReceiptChainHash(base)
	if err != nil {
		t.Fatalf("hash after: %v", err)
	}
	if before != after {
		t.Fatalf("transparency anchor fields changed chain hash: before=%s after=%s", before, after)
	}
}
