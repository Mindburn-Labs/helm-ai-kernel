package witness

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func testKeys(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func signedRequest(t *testing.T, pub ed25519.PublicKey, priv ed25519.PrivateKey, data []byte) WitnessRequest {
	t.Helper()
	h := sha256.Sum256(data)
	sig := ed25519.Sign(priv, h[:])
	return WitnessRequest{
		ReceiptID:    "rcpt-test",
		ReceiptHash:  hex.EncodeToString(h[:]),
		Signature:    hex.EncodeToString(sig),
		PublicKey:    hex.EncodeToString(pub),
		LamportClock: 1,
		SessionID:    "sess-test",
		Timestamp:    time.Now(),
	}
}

func TestHashReceipt_Deterministic(t *testing.T) {
	data := []byte(`{"id":"x","val":42}`)
	h1 := HashReceipt(data)
	h2 := HashReceipt(data)
	if h1 != h2 {
		t.Fatalf("HashReceipt not deterministic: %s vs %s", h1, h2)
	}
}

func TestHashReceipt_DifferentInputs(t *testing.T) {
	h1 := HashReceipt([]byte("alpha"))
	h2 := HashReceipt([]byte("beta"))
	if h1 == h2 {
		t.Fatal("different inputs should produce different hashes")
	}
}

func TestSerializeAttestations_Empty(t *testing.T) {
	data, err := SerializeAttestations(nil)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "null" {
		t.Fatalf("expected null JSON for nil slice, got %s", data)
	}
}

func TestSerializeAttestations_Roundtrip(t *testing.T) {
	atts := []WitnessAttestation{{WitnessID: "w1", Verdict: "VALID"}, {WitnessID: "w2", Verdict: "INVALID"}}
	data, err := SerializeAttestations(atts)
	if err != nil {
		t.Fatal(err)
	}
	var decoded []WitnessAttestation
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	if len(decoded) != 2 || decoded[0].WitnessID != "w1" {
		t.Fatalf("roundtrip failed: %+v", decoded)
	}
}

func TestVerifyAttestation_BadPublicKey(t *testing.T) {
	err := VerifyAttestation(WitnessAttestation{PublicKey: "not-hex", Signature: "aa", ReceiptHash: "bb"})
	if err == nil {
		t.Fatal("expected error for bad public key")
	}
}

func TestVerifyAttestation_BadSignatureEncoding(t *testing.T) {
	pub, _ := testKeys(t)
	err := VerifyAttestation(WitnessAttestation{
		PublicKey:   hex.EncodeToString(pub),
		Signature:   "zzz-not-hex",
		ReceiptHash: hex.EncodeToString(make([]byte, 32)),
	})
	if err == nil {
		t.Fatal("expected error for bad signature encoding")
	}
}

func TestVerifyAttestation_BadReceiptHashEncoding(t *testing.T) {
	pub, _ := testKeys(t)
	err := VerifyAttestation(WitnessAttestation{
		PublicKey:   hex.EncodeToString(pub),
		Signature:   hex.EncodeToString(make([]byte, 64)),
		ReceiptHash: "not-hex!!!",
	})
	if err == nil {
		t.Fatal("expected error for bad receipt hash encoding")
	}
}

func TestWitnessNode_AttestNoTrustedKeys(t *testing.T) {
	nodePub, nodePriv := testKeys(t)
	_, witPriv := testKeys(t)
	node, _ := NewWitnessNode(WitnessNodeConfig{ID: "w-open", PrivateKey: witPriv, TrustedKeys: nil})
	att, err := node.Attest(context.Background(), signedRequest(t, nodePub, nodePriv, []byte("data")))
	if err != nil {
		t.Fatal(err)
	}
	if att.Verdict != "VALID" {
		t.Fatalf("expected VALID when no trusted keys configured, got %s", att.Verdict)
	}
}

func TestWitnessNode_AttestBadPublicKeyHex(t *testing.T) {
	_, witPriv := testKeys(t)
	node, _ := NewWitnessNode(WitnessNodeConfig{ID: "w1", PrivateKey: witPriv})
	att, _ := node.Attest(context.Background(), WitnessRequest{PublicKey: "zzzz", Signature: "aa", ReceiptHash: "bb"})
	if att.Verdict != "INVALID" {
		t.Fatalf("expected INVALID for bad public key hex, got %s", att.Verdict)
	}
}

func TestWitnessClient_InsufficientAttestations(t *testing.T) {
	client := NewWitnessClient(
		WitnessPolicy{MinWitnesses: 3, TotalWitnesses: 2, TimeoutPerNode: 100 * time.Millisecond},
		[]WitnessEndpoint{{ID: "w1"}, {ID: "w2"}},
	)
	_, err := client.CollectAttestations(context.Background(), WitnessRequest{}, func(r WitnessRequest) (*WitnessAttestation, error) {
		return &WitnessAttestation{Verdict: "VALID"}, nil
	})
	if err == nil {
		t.Fatal("expected error when insufficient attestations")
	}
	if !strings.Contains(err.Error(), "2/2") {
		t.Fatalf("error should mention counts: %v", err)
	}
}

func TestHTTPTransport_DefaultTimeout(t *testing.T) {
	tr := NewHTTPTransport(0)
	if tr.client.Timeout != 5*time.Second {
		t.Fatalf("expected default 5s timeout, got %v", tr.client.Timeout)
	}
}

func TestHTTPWitnessHandler_MethodNotAllowed(t *testing.T) {
	_, priv := testKeys(t)
	node, _ := NewWitnessNode(WitnessNodeConfig{ID: "w1", PrivateKey: priv})
	handler := HTTPWitnessHandler(node)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/attest", nil)
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", rr.Code)
	}
}

func TestHTTPWitnessHandler_BadJSON(t *testing.T) {
	_, priv := testKeys(t)
	node, _ := NewWitnessNode(WitnessNodeConfig{ID: "w1", PrivateKey: priv})
	handler := HTTPWitnessHandler(node)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/attest", strings.NewReader("not-json"))
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rr.Code)
	}
}

func TestWitnessPolicy_Fields(t *testing.T) {
	p := WitnessPolicy{MinWitnesses: 2, TotalWitnesses: 5, TimeoutPerNode: 3 * time.Second, RequireUnanimous: true}
	if p.MinWitnesses != 2 || p.TotalWitnesses != 5 || !p.RequireUnanimous {
		t.Fatal("WitnessPolicy fields not set correctly")
	}
}

func TestWitnessEndpoint_Fields(t *testing.T) {
	ep := WitnessEndpoint{ID: "w1", Address: "localhost:8080", PublicKey: "aabb"}
	if ep.ID != "w1" || ep.Address != "localhost:8080" || ep.PublicKey != "aabb" {
		t.Fatal("WitnessEndpoint fields not set correctly")
	}
}
