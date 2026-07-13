package store

import (
	"context"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
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

// TestSQLiteReceiptV2EnvelopeSurvivesAnchorAndCausalReload proves the v2
// persistence contract: a receipt is signed, receives transparency metadata,
// survives a full SQLite reload, verifies against its exact KeyID, and remains
// the byte-stable parent of the next causal receipt. Historic column-only
// persistence lost the signed V2 fields and broke each of those properties.
func TestSQLiteReceiptV2EnvelopeSurvivesAnchorAndCausalReload(t *testing.T) {
	store, cleanup := newTestSQLiteStore(t)
	defer cleanup()
	ctx := context.Background()

	signer, err := crypto.NewEd25519Signer("receipt-v2-store")
	if err != nil {
		t.Fatal(err)
	}
	ring := crypto.NewKeyRing()
	ring.AddKey(signer)

	issuedAt := time.Date(2026, 7, 13, 12, 0, 0, 0, time.UTC)
	receipt := &contracts.Receipt{
		ReceiptID:                    "rcpt-v2-store",
		DecisionID:                   "dec-v2-store",
		EffectID:                     "eff-v2-store",
		ExternalReferenceID:          "external-v2",
		Status:                       "SUCCESS",
		BlobHash:                     "sha256:blob",
		OutputHash:                   "sha256:output",
		Timestamp:                    issuedAt,
		ExecutorID:                   "agent.exec",
		PrevHash:                     "GENESIS",
		LamportClock:                 1,
		ArgsHash:                     "sha256:args",
		EffectType:                   "EXECUTE_TOOL",
		ToolFingerprint:              "sha256:tool",
		IdempotencyKey:               "idem-v2",
		ToolName:                     "local.echo",
		ReasonCode:                   "ALLOW",
		PolicyHash:                   "sha256:policy",
		SessionID:                    "session-v2",
		ScopeHash:                    "sha256:scope",
		IssuedAt:                     issuedAt,
		EmergencyActivationID:        "activation-v2",
		EmergencyDelegationSessionID: "delegation-v2",
		EmergencyScopeHash:           "sha256:emergency",
		SafeDepState:                 "NORMAL",
		SafeDepReasonCode:            "NONE",
		NetworkLogRef:                "cas://network",
		SecretEventsRef:              "cas://secret-events",
		PortExposures: []contracts.PortExposureEvent{{
			Port:         443,
			Protocol:     "tcp",
			Direction:    "outbound",
			StartedAt:    issuedAt,
			ClosedAt:     issuedAt.Add(time.Second),
			AllowedPeers: []string{"api.example.test"},
		}},
		SandboxLeaseID:    "lease-v2",
		EffectGraphNodeID: "node-v2",
		BundledArtifacts: []contracts.ParsedArtifact{{
			ArtifactID: "artifact-v2",
			Type:       "tool-output",
			Hash:       "sha256:artifact",
		}},
	}
	if err := signer.SignReceipt(receipt); err != nil {
		t.Fatalf("sign receipt: %v", err)
	}
	chainHash, err := contracts.ReceiptChainHash(receipt)
	if err != nil {
		t.Fatalf("chain hash before anchor: %v", err)
	}

	// Transparency assignment happens after signing because the log allocates
	// its leaf position from the signed receipt hash. It is verified externally
	// against ReceiptChainHash and deliberately does not mutate the v2 preimage.
	receipt.LogID = "translog-v2"
	receipt.LeafIndex = 42
	receipt.Transparency = &contracts.TransparencyAnchor{Backend: "translog", LogID: "translog-v2"}
	if valid, err := ring.VerifyReceipt(receipt); err != nil || !valid {
		t.Fatalf("anchored receipt must retain its v2 signature: valid=%v err=%v", valid, err)
	}
	if got, err := contracts.ReceiptChainHash(receipt); err != nil || got != chainHash {
		t.Fatalf("anchor mutated chain hash: got=%q err=%v want=%q", got, err, chainHash)
	}
	if err := store.Store(ctx, receipt); err != nil {
		t.Fatalf("store: %v", err)
	}

	reloaded, err := store.GetByReceiptID(ctx, receipt.ReceiptID)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if valid, err := ring.VerifyReceipt(reloaded); err != nil || !valid {
		t.Fatalf("reloaded receipt must verify by its exact KeyID: valid=%v err=%v", valid, err)
	}
	if reloaded.SafeDepState != receipt.SafeDepState || reloaded.EmergencyScopeHash != receipt.EmergencyScopeHash || reloaded.NetworkLogRef != receipt.NetworkLogRef || len(reloaded.PortExposures) != 1 || len(reloaded.BundledArtifacts) != 1 {
		t.Fatalf("v2 evidence fields were not preserved: %+v", reloaded)
	}
	if got, err := contracts.ReceiptChainHash(reloaded); err != nil || got != chainHash {
		t.Fatalf("reloaded chain hash: got=%q err=%v want=%q", got, err, chainHash)
	}

	var assignedPrev *contracts.Receipt
	if err := store.AppendCausal(ctx, "session-v2", func(previous *contracts.Receipt, lamport uint64, prevHash string) (*contracts.Receipt, error) {
		assignedPrev = previous
		if prevHash != chainHash || lamport != 2 {
			t.Fatalf("causal reload binding: previous=%+v lamport=%d prev_hash=%q", previous, lamport, prevHash)
		}
		next := &contracts.Receipt{
			ReceiptID:    "rcpt-v2-next",
			DecisionID:   "dec-v2-next",
			EffectID:     "eff-v2-next",
			Status:       "SUCCESS",
			Timestamp:    issuedAt.Add(time.Minute),
			ExecutorID:   "agent.exec",
			SessionID:    "session-v2",
			PrevHash:     prevHash,
			LamportClock: lamport,
		}
		return next, signer.SignReceipt(next)
	}); err != nil {
		t.Fatalf("append causal: %v", err)
	}
	if assignedPrev == nil || assignedPrev.SignatureSchema != crypto.ReceiptSignatureSchemaV2 {
		t.Fatalf("causal builder did not receive full v2 parent: %+v", assignedPrev)
	}
}
