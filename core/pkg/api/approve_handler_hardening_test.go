package api

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/contracts"
)

// TestApproveHandler_UnregisteredKey_Rejected verifies DRIFT-3:
// Approval requests with public keys not in the AllowedApproverKeys set
// must be rejected with 403, even if the signature is cryptographically valid.
func TestApproveHandler_UnregisteredKey_Rejected(t *testing.T) {
	// Generate a valid Ed25519 keypair
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("key generation failed: %v", err)
	}
	pubHex := hex.EncodeToString(pub)

	// Create handler with an EMPTY allow-list — no keys authorized
	handler := NewApproveHandler(nil)

	// Register a pending intent
	intentHash := "sha256:deadbeef"
	handler.pendingApprovals[intentHash] = &contracts.ApprovalRequest{
		IntentHash: intentHash,
		RiskLevel:  "LOW",
		Status:     contracts.ApprovalPending,
		CreatedAt:  time.Now(),
		ExpiresAt:  time.Now().Add(5 * time.Minute),
	}

	// Sign the intent with a valid key (but not in allow-list)
	sig := ed25519.Sign(priv, []byte(intentHash))
	sigHex := hex.EncodeToString(sig)

	body := `{"intent_hash":"` + intentHash + `","public_key":"` + pubHex + `","signature":"` + sigHex + `"}`

	req := httptest.NewRequest(http.MethodPost, "/api/v1/kernel/approve", strings.NewReader(body))
	req = req.WithContext(context.Background())
	w := httptest.NewRecorder()

	handler.HandleApprove(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("DRIFT-3 VIOLATION: expected 403 for unregistered key, got %d (body: %s)", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "authorized approver registry") {
		t.Errorf("expected rejection message about approver registry, got: %s", w.Body.String())
	}
}

// TestApproveHandler_RegisteredKey_Accepted verifies that registered keys pass the gate.
func TestApproveHandler_RegisteredKey_Accepted(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("key generation failed: %v", err)
	}
	pubHex := hex.EncodeToString(pub)

	// Create handler with this key authorized
	handler := NewApproveHandler([]string{pubHex})

	intentHash := "sha256:cafebabe"
	handler.pendingApprovals[intentHash] = &contracts.ApprovalRequest{
		IntentHash: intentHash,
		RiskLevel:  "LOW",
		Status:     contracts.ApprovalPending,
		CreatedAt:  time.Now(),
		ExpiresAt:  time.Now().Add(5 * time.Minute),
	}

	// Sign the domain-separated message matching handler's verification
	planHash := "sha256:plan123"
	policyHash := "sha256:policy456"
	nonce := "test-nonce-1"
	message := fmt.Sprintf("HELM/Approval/v1:%s:%s:%s:%s", planHash, policyHash, intentHash, nonce)
	sig := ed25519.Sign(priv, []byte(message))
	sigHex := hex.EncodeToString(sig)

	body := `{"intent_hash":"` + intentHash + `","public_key":"` + pubHex +
		`","signature":"` + sigHex +
		`","plan_hash":"` + planHash +
		`","policy_hash":"` + policyHash +
		`","nonce":"` + nonce + `"}`

	req := httptest.NewRequest(http.MethodPost, "/api/v1/kernel/approve", strings.NewReader(body))
	w := httptest.NewRecorder()

	handler.HandleApprove(w, req)

	// Should succeed (200 OK) since key is authorized
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 for registered key, got %d (body: %s)", w.Code, w.Body.String())
	}
}
