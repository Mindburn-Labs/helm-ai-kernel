package witness

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"net/http/httptest"
	"testing"
	"time"
)

func TestHTTPTransport_RoundTrip(t *testing.T) {
	// Generate keys
	nodePub, nodePriv, _ := ed25519.GenerateKey(rand.Reader)
	_, witnessPriv, _ := ed25519.GenerateKey(rand.Reader)

	// Create witness node
	node, err := NewWitnessNode(WitnessNodeConfig{
		ID:         "w1",
		PrivateKey: witnessPriv,
		TrustedKeys: map[string]ed25519.PublicKey{
			"n1": nodePub,
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	// Start HTTP server for witness
	handler := HTTPWitnessHandler(node)
	server := httptest.NewServer(handler)
	defer server.Close()

	// Create HTTP transport and make request
	transport := NewHTTPTransport(5 * time.Second)
	receiptHash := sha256.Sum256([]byte("test-receipt"))
	sig := ed25519.Sign(nodePriv, receiptHash[:])

	att, err := transport.RequestAttestation(context.Background(), server.URL, WitnessRequest{
		ReceiptID:    "rcpt-001",
		ReceiptHash:  hex.EncodeToString(receiptHash[:]),
		Signature:    hex.EncodeToString(sig),
		PublicKey:    hex.EncodeToString(nodePub),
		LamportClock: 1,
		SessionID:    "session-001",
		Timestamp:    time.Now(),
	})
	if err != nil {
		t.Fatal(err)
	}

	if att.Verdict != "VALID" {
		t.Errorf("expected VALID, got %q (reason: %s)", att.Verdict, att.Reason)
	}
	if att.WitnessID != "w1" {
		t.Errorf("expected witness ID 'w1', got %q", att.WitnessID)
	}
	if att.Signature == "" {
		t.Error("should have witness signature")
	}
}

func TestHTTPTransport_InvalidSignature(t *testing.T) {
	_, witnessPriv, _ := ed25519.GenerateKey(rand.Reader)
	nodePub, _, _ := ed25519.GenerateKey(rand.Reader)

	node, _ := NewWitnessNode(WitnessNodeConfig{
		ID:          "w1",
		PrivateKey:  witnessPriv,
		TrustedKeys: map[string]ed25519.PublicKey{"n1": nodePub},
	})

	server := httptest.NewServer(HTTPWitnessHandler(node))
	defer server.Close()

	transport := NewHTTPTransport(5 * time.Second)
	receiptHash := sha256.Sum256([]byte("test"))
	fakeSig := make([]byte, ed25519.SignatureSize)

	att, err := transport.RequestAttestation(context.Background(), server.URL, WitnessRequest{
		ReceiptID:   "rcpt-001",
		ReceiptHash: hex.EncodeToString(receiptHash[:]),
		Signature:   hex.EncodeToString(fakeSig),
		PublicKey:   hex.EncodeToString(nodePub),
	})
	if err != nil {
		t.Fatal(err)
	}
	if att.Verdict != "INVALID" {
		t.Errorf("expected INVALID for bad signature, got %q", att.Verdict)
	}
}

func TestHTTPTransport_Timeout(t *testing.T) {
	transport := NewHTTPTransport(10 * time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()

	_, err := transport.RequestAttestation(ctx, "http://192.0.2.1:12345", WitnessRequest{})
	if err == nil {
		t.Error("expected error on timeout")
	}
}
