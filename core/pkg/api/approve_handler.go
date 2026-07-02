package api

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	helmcrypto "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
)

const (
	approvalSignatureAlgorithmEd25519 = "ed25519-sha256"
	approvalSignatureAlgorithmHybrid  = "hybrid-ed25519-mldsa65-sha256"
	approvalPolicyClassicalRequired   = "classical-ed25519-required"
	approvalPolicyHybridRequired      = "hybrid-required"
	approvalPolicyPQCRequired         = "pqc-required"
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
//  3. Verify the approver public key is authorized
//  4. Verify the profile-aware signature over the approval context
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

	if err := validateApprovalReceiptEncoding(receipt); err != nil {
		WriteBadRequest(w, err.Error())
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

	// Create the canonical domain-separated message
	message := fmt.Sprintf("HELM/Approval/v1:%s:%s:%s:%s",
		receipt.PlanHash,
		receipt.PolicyHash,
		receipt.IntentHash,
		receipt.Nonce)

	if err := verifyApprovalReceiptSignature(receipt, []byte(message)); err != nil {
		WriteForbidden(w, fmt.Sprintf("signature verification failed — approval rejected: %v", err))
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

func validateApprovalReceiptEncoding(receipt contracts.ApprovalReceipt) error {
	switch approvalSignatureProfile(receipt) {
	case helmcrypto.ReceiptProfileClassical:
		pubKeyBytes, err := hex.DecodeString(receipt.PublicKey)
		if err != nil || len(pubKeyBytes) != ed25519.PublicKeySize {
			return fmt.Errorf("invalid public key")
		}
		if _, err := hex.DecodeString(receipt.Signature); err != nil {
			return fmt.Errorf("invalid signature encoding")
		}
	case helmcrypto.ReceiptProfileHybrid:
		edPub, mldsaPub, err := approvalHybridPublicKeys(receipt)
		if err != nil {
			return fmt.Errorf("invalid public key")
		}
		edPubBytes, err := hex.DecodeString(edPub)
		if err != nil {
			return fmt.Errorf("invalid public key")
		}
		mldsaPubBytes, err := hex.DecodeString(mldsaPub)
		if err != nil {
			return fmt.Errorf("invalid public key")
		}
		if _, err := helmcrypto.NewHybridVerifier(edPubBytes, mldsaPubBytes); err != nil {
			return fmt.Errorf("invalid public key")
		}
		edSig, mldsaSig, err := approvalHybridSignatureParts(receipt.Signature)
		if err != nil {
			return fmt.Errorf("invalid signature encoding")
		}
		if _, err := hex.DecodeString(edSig); err != nil {
			return fmt.Errorf("invalid signature encoding")
		}
		if _, err := hex.DecodeString(mldsaSig); err != nil {
			return fmt.Errorf("invalid signature encoding")
		}
	default:
		return fmt.Errorf("unsupported signature profile")
	}
	return nil
}

func verifyApprovalReceiptSignature(receipt contracts.ApprovalReceipt, message []byte) error {
	profile := approvalSignatureProfile(receipt)
	algorithm := approvalSignatureAlgorithm(receipt, profile)
	if err := enforceApprovalVerificationPolicy(receipt, profile, algorithm); err != nil {
		return err
	}

	switch profile {
	case helmcrypto.ReceiptProfileClassical:
		pubKeyBytes, err := hex.DecodeString(receipt.PublicKey)
		if err != nil || len(pubKeyBytes) != ed25519.PublicKeySize {
			return fmt.Errorf("invalid public key")
		}
		sigBytes, err := hex.DecodeString(receipt.Signature)
		if err != nil {
			return fmt.Errorf("invalid signature encoding")
		}
		if !ed25519.Verify(ed25519.PublicKey(pubKeyBytes), message, sigBytes) {
			return fmt.Errorf("ed25519 signature verification failed")
		}
		return nil
	case helmcrypto.ReceiptProfileHybrid:
		edPub, mldsaPub, err := approvalHybridPublicKeys(receipt)
		if err != nil {
			return err
		}
		edSig, mldsaSig, err := approvalHybridSignatureParts(receipt.Signature)
		if err != nil {
			return err
		}
		ok, err := helmcrypto.Verify(edPub, edSig, message)
		if err != nil || !ok {
			return fmt.Errorf("hybrid ed25519 verification failed")
		}
		ok, err = helmcrypto.VerifyMLDSA65(mldsaPub, mldsaSig, message)
		if err != nil || !ok {
			return fmt.Errorf("hybrid ml-dsa-65 verification failed")
		}
		return nil
	default:
		return fmt.Errorf("unsupported signature profile %q", profile)
	}
}

func approvalSignatureProfile(receipt contracts.ApprovalReceipt) string {
	if profile := strings.ToLower(strings.TrimSpace(receipt.SignatureProfile)); profile != "" {
		return profile
	}
	if strings.HasPrefix(receipt.Signature, "hybrid:") {
		return helmcrypto.ReceiptProfileHybrid
	}
	return helmcrypto.ReceiptProfileClassical
}

func approvalSignatureAlgorithm(receipt contracts.ApprovalReceipt, profile string) string {
	if algorithm := strings.ToLower(strings.TrimSpace(receipt.SignatureAlgorithm)); algorithm != "" {
		return algorithm
	}
	if profile == helmcrypto.ReceiptProfileHybrid {
		return approvalSignatureAlgorithmHybrid
	}
	return approvalSignatureAlgorithmEd25519
}

func enforceApprovalVerificationPolicy(receipt contracts.ApprovalReceipt, profile, algorithm string) error {
	switch strings.ToLower(strings.TrimSpace(receipt.VerificationPolicy)) {
	case "", approvalPolicyClassicalRequired:
		if profile != helmcrypto.ReceiptProfileClassical {
			return fmt.Errorf("approval signature profile %q does not satisfy classical policy", profile)
		}
	case approvalPolicyHybridRequired:
		if profile != helmcrypto.ReceiptProfileHybrid {
			return fmt.Errorf("approval signature profile %q does not satisfy hybrid policy", profile)
		}
		if !receipt.DowngradeRejected {
			return fmt.Errorf("hybrid approval must declare downgrade rejection")
		}
	case approvalPolicyPQCRequired:
		return fmt.Errorf("approval handler does not support PQ-only approvals")
	default:
		return fmt.Errorf("unsupported approval verification policy %q", receipt.VerificationPolicy)
	}
	if len(receipt.AcceptedAlgorithms) == 0 {
		return nil
	}
	for _, accepted := range receipt.AcceptedAlgorithms {
		if normalizeApprovalAlgorithm(accepted) == normalizeApprovalAlgorithm(algorithm) {
			return nil
		}
	}
	return fmt.Errorf("approval signature algorithm %q not accepted", algorithm)
}

func approvalHybridPublicKeys(receipt contracts.ApprovalReceipt) (edPub, mldsaPub string, err error) {
	if receipt.PublicKeySet != nil {
		edPub = firstNonEmpty(receipt.PublicKeySet[receipt.KeyID+":ed25519"], receipt.PublicKeySet["ed25519"])
		mldsaPub = firstNonEmpty(receipt.PublicKeySet[receipt.KeyID+":ml-dsa-65"], receipt.PublicKeySet["ml-dsa-65"])
	}
	if edPub == "" || mldsaPub == "" {
		edPub, mldsaPub, err = approvalHybridEnvelopeParts(receipt.PublicKey)
		if err != nil {
			return "", "", err
		}
	}
	return edPub, mldsaPub, nil
}

func approvalHybridSignatureParts(signature string) (edSig, mldsaSig string, err error) {
	return approvalHybridEnvelopeParts(signature)
}

func approvalHybridEnvelopeParts(envelope string) (edPart, mldsaPart string, err error) {
	const prefix = "hybrid:"
	if !strings.HasPrefix(envelope, prefix) {
		return "", "", fmt.Errorf("hybrid envelope missing prefix")
	}
	parts := strings.SplitN(strings.TrimPrefix(envelope, prefix), ":", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", fmt.Errorf("invalid hybrid envelope")
	}
	return parts[0], parts[1], nil
}

func normalizeApprovalAlgorithm(algorithm string) string {
	switch strings.ToLower(strings.TrimSpace(algorithm)) {
	case "ed25519", approvalSignatureAlgorithmEd25519:
		return approvalSignatureAlgorithmEd25519
	case "hybrid", "hybrid-ed25519-mldsa65", approvalSignatureAlgorithmHybrid:
		return approvalSignatureAlgorithmHybrid
	default:
		return strings.ToLower(strings.TrimSpace(algorithm))
	}
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}
