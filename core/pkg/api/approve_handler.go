package api

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/contracts"
)

// ApproveHandler handles POST /api/v1/kernel/approve
// This is the backend half of the HITL bridge. The frontend uses WebCrypto API
// to sign the intent hash, and this handler verifies the signature cryptographically.
type ApproveHandler struct {
	mu sync.RWMutex
	// pendingApprovals maps intent_hash → ApprovalRequest
	pendingApprovals map[string]*contracts.ApprovalRequest
	// allowedKeys is the set of authorized Ed25519 public keys (hex-encoded)
	allowedKeys map[string]struct{}
	// clock provides the current time (injected for deterministic testing)
	clock func() time.Time
}

// NewApproveHandler creates a new approval handler with an authorized key list.
// Uses time.Now as the default clock; override with WithClock for testing.
func NewApproveHandler(allowedKeys []string) *ApproveHandler {
	allowed := make(map[string]struct{})
	for _, k := range allowedKeys {
		allowed[k] = struct{}{}
	}
	return &ApproveHandler{
		pendingApprovals: make(map[string]*contracts.ApprovalRequest),
		allowedKeys:      allowed,
		clock:            time.Now,
	}
}

// WithClock overrides the time source for deterministic testing.
func (h *ApproveHandler) WithClock(clock func() time.Time) *ApproveHandler {
	h.clock = clock
	return h
}

// RegisterPendingApproval adds an intent to the pending approval queue.
func (h *ApproveHandler) RegisterPendingApproval(req *contracts.ApprovalRequest) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.pendingApprovals[req.IntentHash] = req
}

// HandleApprove processes a cryptographic approval from the operator UI.
//
// Flow:
//  1. Parse ApprovalReceipt from request body
//  2. Verify the intent exists in pending queue
//  3. Decode the approver's Ed25519 public key
//  4. Verify the signature over IntentHash
//  5. Mark the approval as APPROVED with the receipt
//  6. Return 200 with the signed receipt
func (h *ApproveHandler) HandleApprove(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		WriteMethodNotAllowed(w)
		return
	}

	var receipt contracts.ApprovalReceipt
	if err := json.NewDecoder(r.Body).Decode(&receipt); err != nil {
		WriteBadRequest(w, fmt.Sprintf("invalid request body: %v", err))
		return
	}

	// Validate required fields
	if receipt.IntentHash == "" || receipt.PublicKey == "" || receipt.Signature == "" {
		WriteBadRequest(w, "missing required fields: intent_hash, public_key, signature")
		return
	}

	// Check if the intent exists in pending queue
	h.mu.Lock()
	pending, ok := h.pendingApprovals[receipt.IntentHash]
	if !ok {
		h.mu.Unlock()
		WriteNotFound(w, "intent not found or already processed")
		return
	}

	if pending.Status != contracts.ApprovalPending {
		h.mu.Unlock()
		WriteConflict(w, fmt.Sprintf("intent already %s", pending.Status))
		return
	}

	// Check expiry
	if h.clock().After(pending.ExpiresAt) {
		pending.Status = contracts.ApprovalExpired
		h.mu.Unlock()
		WriteError(w, http.StatusGone, "Gone", "approval request has expired")
		return
	}
	h.mu.Unlock()

	// Decode public key
	pubKeyBytes, err := hex.DecodeString(receipt.PublicKey)
	if err != nil || len(pubKeyBytes) != ed25519.PublicKeySize {
		WriteBadRequest(w, "invalid public key")
		return
	}

	// Decode signature
	sigBytes, err := hex.DecodeString(receipt.Signature)
	if err != nil {
		WriteBadRequest(w, "invalid signature encoding")
		return
	}

	// Ensure the public key is authorized (KID check)
	if len(h.allowedKeys) > 0 {
		if _, authorized := h.allowedKeys[receipt.PublicKey]; !authorized {
			WriteForbidden(w, "public key not found in authorized approver registry")
			return
		}
	} else {
		WriteForbidden(w, "no authorized approver registry configured")
		return
	}

	// Verify Ed25519 signature over the bound context:
	// plan_hash + policy_hash + intent_hash + nonce
	pubKey := ed25519.PublicKey(pubKeyBytes)

	// Create the canonical domain-separated message
	message := fmt.Sprintf("HELM/Approval/v1:%s:%s:%s:%s",
		receipt.PlanHash,
		receipt.PolicyHash,
		receipt.IntentHash,
		receipt.Nonce)

	if !ed25519.Verify(pubKey, []byte(message), sigBytes) {
		WriteForbidden(w, "signature verification failed — approval rejected")
		return
	}

	// Signature valid — approve the intent
	receipt.Timestamp = h.clock()
	h.mu.Lock()
	pending.Status = contracts.ApprovalApproved
	pending.Receipt = &receipt
	h.mu.Unlock()

	// Respond with the signed approval
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"status":      "APPROVED",
		"intent_hash": receipt.IntentHash,
		"approver_id": receipt.ApproverID,
		"timestamp":   receipt.Timestamp,
	})
}

// GetPendingApprovals returns all pending approval requests.
func (h *ApproveHandler) GetPendingApprovals() []*contracts.ApprovalRequest {
	h.mu.RLock()
	defer h.mu.RUnlock()
	var pending []*contracts.ApprovalRequest
	for _, req := range h.pendingApprovals {
		if req.Status == contracts.ApprovalPending {
			pending = append(pending, req)
		}
	}
	return pending
}
