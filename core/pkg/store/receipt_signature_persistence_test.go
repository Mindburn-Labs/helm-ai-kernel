package store

import (
	"context"
	"database/sql"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
)

func TestSQLiteReceiptStorePreservesV2SafeDepSignature(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()

	store, err := NewSQLiteReceiptStore(db)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := crypto.NewEd25519Signer("sqlite-receipt-v2")
	if err != nil {
		t.Fatal(err)
	}
	receipt := &contracts.Receipt{
		ReceiptID:                    "rcpt-sqlite-safe-dep",
		DecisionID:                   "dec-sqlite-safe-dep",
		EffectID:                     "eff-sqlite-safe-dep",
		Status:                       "SUCCESS",
		OutputHash:                   "sha256:output",
		PrevHash:                     "sha256:previous",
		LamportClock:                 3,
		ArgsHash:                     "sha256:args",
		EmergencyActivationID:        "activation-sqlite",
		EmergencyDelegationSessionID: "delegation-sqlite",
		EmergencyScopeHash:           "sha256:scope-sqlite",
		SafeDepState:                 string(contracts.SafeDepDegradedNarrowing),
		SafeDepReasonCode:            string(contracts.ReasonSafeDepDegradedNarrowing),
	}
	if err := signer.SignReceipt(receipt); err != nil {
		t.Fatal(err)
	}
	if err := store.Store(context.Background(), receipt); err != nil {
		t.Fatal(err)
	}

	stored, err := store.GetByReceiptID(context.Background(), receipt.ReceiptID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.SignatureVersion != contracts.ReceiptSignatureVersionV2 ||
		stored.EmergencyActivationID != receipt.EmergencyActivationID ||
		stored.EmergencyDelegationSessionID != receipt.EmergencyDelegationSessionID ||
		stored.EmergencyScopeHash != receipt.EmergencyScopeHash ||
		stored.SafeDepState != receipt.SafeDepState ||
		stored.SafeDepReasonCode != receipt.SafeDepReasonCode {
		t.Fatalf("persisted receipt lost v2 SafeDep evidence: %+v", stored)
	}
	if valid, err := signer.VerifyReceipt(stored); err != nil || !valid {
		t.Fatalf("persisted v2 receipt did not verify: valid=%v err=%v", valid, err)
	}
}
