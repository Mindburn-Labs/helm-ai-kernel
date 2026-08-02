package store

import (
	"context"
	"database/sql"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
)

// A signed receipt must still verify after a store round-trip.
//
// This is the failure the V5 preimage invited: it binds verdict, reason_code,
// policy_hash and session_id, so any of those dropped on the way to the database
// and back comes home empty and the receipt reads as tampered. The stores keep
// the receipt document itself in an `envelope` column for exactly this reason —
// every signed field survives whether or not it has a column of its own.
func TestSQLiteReceiptStore_SignedReceiptSurvivesRoundTrip(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	defer db.Close()

	store, err := NewSQLiteReceiptStore(db)
	if err != nil {
		t.Fatalf("new store: %v", err)
	}

	signer, err := crypto.NewEd25519Signer("roundtrip-key")
	if err != nil {
		t.Fatalf("signer: %v", err)
	}

	receipt := &contracts.Receipt{
		ReceiptID:    "rcpt-roundtrip",
		DecisionID:   "dec-roundtrip",
		EffectID:     "eff-roundtrip",
		Status:       "SUCCESS",
		OutputHash:   "sha256:out",
		PrevHash:     "GENESIS",
		LamportClock: 1,
		ArgsHash:     "sha256:args",
		Verdict:      "ALLOW",
		ReasonCode:   "",
		PolicyHash:   "sha256:policy-v7",
		SessionID:    "sess-roundtrip",
	}
	if err := signer.SignReceipt(receipt); err != nil {
		t.Fatalf("sign: %v", err)
	}
	if receipt.SignatureVersion != contracts.ReceiptSignatureV5 {
		t.Fatalf("signer must stamp V5, got %q", receipt.SignatureVersion)
	}

	ctx := context.Background()
	if err := store.Store(ctx, receipt); err != nil {
		t.Fatalf("store: %v", err)
	}

	loaded, err := store.GetByReceiptID(ctx, receipt.ReceiptID)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if loaded == nil {
		t.Fatal("receipt not found after storing it")
	}

	for _, field := range []struct{ name, got, want string }{
		{"signature_version", loaded.SignatureVersion, receipt.SignatureVersion},
		{"verdict", loaded.Verdict, receipt.Verdict},
		{"policy_hash", loaded.PolicyHash, receipt.PolicyHash},
		{"session_id", loaded.SessionID, receipt.SessionID},
		{"signature", loaded.Signature, receipt.Signature},
	} {
		if field.got != field.want {
			t.Errorf("%s did not survive the round-trip: got %q, want %q", field.name, field.got, field.want)
		}
	}

	ok, err := signer.VerifyReceipt(loaded)
	if err != nil {
		t.Fatalf("verify reloaded receipt: %v", err)
	}
	if !ok {
		t.Fatal("a receipt signed, stored and reloaded no longer verifies — a signed field was lost in persistence")
	}
}
