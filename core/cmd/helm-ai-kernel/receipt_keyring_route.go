package main

// quantum_posture: this route publishes the public half of whichever receipt
// signer the Kernel runs: classical Ed25519, hybrid Ed25519 + ML-DSA-65, or
// ML-DSA-65 alone. It signs nothing and claims no profile the signer lacks.

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/api"
	helmcrypto "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
)

const (
	receiptKeyringPath    = "/api/v1/receipt-keyring"
	receiptKeyringVersion = "kernel-evaluate-receipt-keyring.v1"
)

// receiptKeyring is the document the Control Plane pins as
// HELM_KERNEL_RECEIPT_KEYRING. Its shape is fixed by the Control Plane's strict
// decoder (unknown fields refused), so it must not grow fields here.
type receiptKeyring struct {
	KeyringVersion string                    `json:"keyring_version"`
	Keys           []receiptKeyringAuthority `json:"keys"`
}

type receiptKeyringAuthority struct {
	KeyID               string `json:"key_id"`
	Profile             string `json:"profile"`
	Ed25519PublicKeyHex string `json:"ed25519_public_key_hex,omitempty"`
	MLDSA65PublicKeyHex string `json:"ml_dsa_65_public_key_hex,omitempty"`
}

// receiptKeyringFor describes the identity signer stamps on every receipt: the
// same key id, profile and public keys that SignReceipt writes into KeyID,
// SignatureProfile and PublicKeySet.
func receiptKeyringFor(signer helmcrypto.Signer) (receiptKeyring, error) {
	var authority receiptKeyringAuthority
	switch s := signer.(type) {
	case *helmcrypto.Ed25519Signer:
		authority = receiptKeyringAuthority{KeyID: s.GetKeyID(), Profile: helmcrypto.ReceiptProfileClassical, Ed25519PublicKeyHex: s.PublicKey()}
	case *helmcrypto.HybridSigner:
		authority = receiptKeyringAuthority{KeyID: s.GetKeyID(), Profile: helmcrypto.ReceiptProfileHybrid, Ed25519PublicKeyHex: s.Ed25519Signer().PublicKey(), MLDSA65PublicKeyHex: s.MLDSASigner().PublicKey()}
	case *helmcrypto.MLDSASigner:
		authority = receiptKeyringAuthority{KeyID: s.GetKeyID(), Profile: helmcrypto.ReceiptProfilePQC, MLDSA65PublicKeyHex: s.PublicKey()}
	default:
		return receiptKeyring{}, errors.New("receipt signer profile is not publishable")
	}
	if authority.KeyID == "" {
		return receiptKeyring{}, errors.New("receipt signer has no key id")
	}
	return receiptKeyring{KeyringVersion: receiptKeyringVersion, Keys: []receiptKeyringAuthority{authority}}, nil
}

// registerReceiptKeyringRoute serves the receipt keyring. The body is built
// once from the running signer; without a publishable signer the route answers
// 503 and never an empty keyring, which the Control Plane reads as "not
// configured".
func registerReceiptKeyringRoute(mux routeMux, svc *Services) {
	var body []byte
	if svc != nil && svc.ReceiptSigner != nil {
		if keyring, err := receiptKeyringFor(svc.ReceiptSigner); err == nil {
			body, _ = json.Marshal(keyring)
		}
	}
	mux.HandleFunc(http.MethodGet+" "+receiptKeyringPath, protectRuntimeHandler(RouteAuthPublic, func(w http.ResponseWriter, _ *http.Request) {
		if body == nil {
			api.WriteError(w, http.StatusServiceUnavailable, "Receipt keyring unavailable", "kernel receipt signer is not initialized")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write(body)
	}))
}
