package api

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"net/http"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/trust/registry"
)

// TrustKeyHandler provides HTTP handlers for trust key management.
type TrustKeyHandler struct {
	Registry *registry.TrustRegistry
}

// AddKeyRequest is the wire format for adding a trusted key.
type AddKeyRequest struct {
	TenantID  string `json:"tenant_id"`
	KeyID     string `json:"key_id"`
	PublicKey string `json:"public_key"` // hex-encoded Ed25519 public key
}

// RevokeKeyRequest is the wire format for revoking a trusted key.
type RevokeKeyRequest struct {
	TenantID string `json:"tenant_id"`
	KeyID    string `json:"key_id"`
}

// HandleAddKey handles POST /api/v1/trust/keys/add.
func (h *TrustKeyHandler) HandleAddKey(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		WriteMethodNotAllowed(w)
		return
	}

	var req AddKeyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteBadRequest(w, "invalid request body")
		return
	}

	if req.TenantID == "" || req.KeyID == "" || req.PublicKey == "" {
		WriteBadRequest(w, "tenant_id, key_id, and public_key are required")
		return
	}

	pubBytes, err := hex.DecodeString(req.PublicKey)
	if err != nil || len(pubBytes) != ed25519.PublicKeySize {
		WriteBadRequest(w, "public_key must be 64-char hex-encoded Ed25519 public key")
		return
	}

	event := registry.LegacyTrustEvent{
		EventType: "KEY_ADDED",
		TenantID:  req.TenantID,
		KeyID:     req.KeyID,
		PublicKey: ed25519.PublicKey(pubBytes),
	}

	if err := h.Registry.Apply(event); err != nil {
		WriteInternal(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"status":    "key_added",
		"tenant_id": req.TenantID,
		"key_id":    req.KeyID,
	})
}

// HandleRevokeKey handles POST /api/v1/trust/keys/revoke.
func (h *TrustKeyHandler) HandleRevokeKey(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		WriteMethodNotAllowed(w)
		return
	}

	var req RevokeKeyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteBadRequest(w, "invalid request body")
		return
	}

	if req.TenantID == "" || req.KeyID == "" {
		WriteBadRequest(w, "tenant_id and key_id are required")
		return
	}

	event := registry.LegacyTrustEvent{
		EventType: "KEY_REVOKED",
		TenantID:  req.TenantID,
		KeyID:     req.KeyID,
	}

	if err := h.Registry.Apply(event); err != nil {
		WriteInternal(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"status":    "key_revoked",
		"tenant_id": req.TenantID,
		"key_id":    req.KeyID,
	})
}
