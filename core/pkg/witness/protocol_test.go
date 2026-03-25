package witness

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"testing"
	"time"
)

func generateTestKeyPair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func TestWitnessNode_Attest_ValidSignature(t *testing.T) {
	// Generate node keypair
	nodePub, nodePriv := generateTestKeyPair(t)
	// Generate witness keypair
	_, witnessPriv := generateTestKeyPair(t)

	node, err := NewWitnessNode(WitnessNodeConfig{
		ID:         "witness-001",
		PrivateKey: witnessPriv,
		TrustedKeys: map[string]ed25519.PublicKey{
			"node-001": nodePub,
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	// Create a receipt hash and sign it with node key
	receiptData := []byte(`{"receipt_id":"rcpt-001","status":"ALLOW"}`)
	receiptHash := sha256.Sum256(receiptData)
	receiptHashHex := hex.EncodeToString(receiptHash[:])
	nodeSignature := ed25519.Sign(nodePriv, receiptHash[:])

	att, err := node.Attest(context.Background(), WitnessRequest{
		ReceiptID:    "rcpt-001",
		ReceiptHash:  receiptHashHex,
		Signature:    hex.EncodeToString(nodeSignature),
		PublicKey:    hex.EncodeToString(nodePub),
		LamportClock: 42,
		SessionID:    "session-001",
		Timestamp:    time.Now(),
	})
	if err != nil {
		t.Fatal(err)
	}

	if att.Verdict != "VALID" {
		t.Errorf("expected verdict VALID, got %q (reason: %s)", att.Verdict, att.Reason)
	}
	if att.WitnessID != "witness-001" {
		t.Errorf("expected witness ID 'witness-001', got %q", att.WitnessID)
	}
	if att.ReceiptHash != receiptHashHex {
		t.Error("receipt hash mismatch")
	}
	if att.Signature == "" {
		t.Error("witness signature should not be empty")
	}
}

func TestWitnessNode_Attest_InvalidSignature(t *testing.T) {
	_, witnessPriv := generateTestKeyPair(t)
	nodePub, _ := generateTestKeyPair(t)

	node, _ := NewWitnessNode(WitnessNodeConfig{
		ID:          "witness-001",
		PrivateKey:  witnessPriv,
		TrustedKeys: map[string]ed25519.PublicKey{"node-001": nodePub},
	})

	receiptHash := sha256.Sum256([]byte("test"))
	fakeSignature := make([]byte, ed25519.SignatureSize) // zero sig

	att, err := node.Attest(context.Background(), WitnessRequest{
		ReceiptID:   "rcpt-001",
		ReceiptHash: hex.EncodeToString(receiptHash[:]),
		Signature:   hex.EncodeToString(fakeSignature),
		PublicKey:   hex.EncodeToString(nodePub),
	})
	if err != nil {
		t.Fatal(err)
	}
	if att.Verdict != "INVALID" {
		t.Error("expected INVALID for bad signature")
	}
}

func TestWitnessNode_Attest_UntrustedKey(t *testing.T) {
	_, witnessPriv := generateTestKeyPair(t)
	trustedPub, _ := generateTestKeyPair(t)
	untrustedPub, untrustedPriv := generateTestKeyPair(t)

	node, _ := NewWitnessNode(WitnessNodeConfig{
		ID:          "witness-001",
		PrivateKey:  witnessPriv,
		TrustedKeys: map[string]ed25519.PublicKey{"trusted": trustedPub},
	})

	receiptHash := sha256.Sum256([]byte("test"))
	sig := ed25519.Sign(untrustedPriv, receiptHash[:])

	att, err := node.Attest(context.Background(), WitnessRequest{
		ReceiptID:   "rcpt-001",
		ReceiptHash: hex.EncodeToString(receiptHash[:]),
		Signature:   hex.EncodeToString(sig),
		PublicKey:   hex.EncodeToString(untrustedPub),
	})
	if err != nil {
		t.Fatal(err)
	}
	if att.Verdict != "INVALID" {
		t.Errorf("expected INVALID for untrusted key, got %q", att.Verdict)
	}
	if att.Reason != "public key not in trusted set" {
		t.Errorf("unexpected reason: %q", att.Reason)
	}
}

func TestVerifyAttestation(t *testing.T) {
	_, witnessPriv := generateTestKeyPair(t)
	witnessPub := witnessPriv.Public().(ed25519.PublicKey)

	receiptHash := sha256.Sum256([]byte("test"))
	sig := ed25519.Sign(witnessPriv, receiptHash[:])

	att := WitnessAttestation{
		WitnessID:   "witness-001",
		ReceiptHash: hex.EncodeToString(receiptHash[:]),
		Signature:   hex.EncodeToString(sig),
		PublicKey:   hex.EncodeToString(witnessPub),
	}

	err := VerifyAttestation(att)
	if err != nil {
		t.Errorf("expected valid attestation, got error: %v", err)
	}
}

func TestVerifyAttestation_Invalid(t *testing.T) {
	_, witnessPriv := generateTestKeyPair(t)
	witnessPub := witnessPriv.Public().(ed25519.PublicKey)

	// Sign one hash, attest another
	receiptHash1 := sha256.Sum256([]byte("original"))
	sig := ed25519.Sign(witnessPriv, receiptHash1[:])

	receiptHash2 := sha256.Sum256([]byte("tampered"))
	att := WitnessAttestation{
		WitnessID:   "witness-001",
		ReceiptHash: hex.EncodeToString(receiptHash2[:]), // different hash
		Signature:   hex.EncodeToString(sig),
		PublicKey:   hex.EncodeToString(witnessPub),
	}

	err := VerifyAttestation(att)
	if err == nil {
		t.Error("expected error for tampered receipt hash")
	}
}

func TestHashReceipt(t *testing.T) {
	hash1 := HashReceipt([]byte(`{"id":"a"}`))
	hash2 := HashReceipt([]byte(`{"id":"a"}`))
	hash3 := HashReceipt([]byte(`{"id":"b"}`))

	if hash1 != hash2 {
		t.Error("hash should be deterministic")
	}
	if hash1 == hash3 {
		t.Error("hash should differ for different content")
	}
}

func TestNewWitnessNode_Validation(t *testing.T) {
	_, priv := generateTestKeyPair(t)

	_, err := NewWitnessNode(WitnessNodeConfig{ID: "", PrivateKey: priv})
	if err == nil {
		t.Error("expected error for empty ID")
	}

	_, err = NewWitnessNode(WitnessNodeConfig{ID: "test", PrivateKey: nil})
	if err == nil {
		t.Error("expected error for nil private key")
	}
}

func TestWitnessClient_CollectAttestations(t *testing.T) {
	_, witnessPriv := generateTestKeyPair(t)
	nodePub, nodePriv := generateTestKeyPair(t)

	node, _ := NewWitnessNode(WitnessNodeConfig{
		ID:         "w1",
		PrivateKey: witnessPriv,
		TrustedKeys: map[string]ed25519.PublicKey{"n1": nodePub},
	})

	client := NewWitnessClient(
		WitnessPolicy{MinWitnesses: 1, TotalWitnesses: 1, TimeoutPerNode: 5 * time.Second},
		[]WitnessEndpoint{{ID: "w1", Address: "localhost:50051"}},
	)

	receiptHash := sha256.Sum256([]byte("test"))
	sig := ed25519.Sign(nodePriv, receiptHash[:])

	req := WitnessRequest{
		ReceiptID:   "rcpt-001",
		ReceiptHash: hex.EncodeToString(receiptHash[:]),
		Signature:   hex.EncodeToString(sig),
		PublicKey:   hex.EncodeToString(nodePub),
	}

	attestations, err := client.CollectAttestations(context.Background(), req, func(r WitnessRequest) (*WitnessAttestation, error) {
		return node.Attest(context.Background(), r)
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(attestations) < 1 {
		t.Error("expected at least 1 attestation")
	}
	if attestations[0].Verdict != "VALID" {
		t.Errorf("expected VALID verdict, got %q", attestations[0].Verdict)
	}
}
