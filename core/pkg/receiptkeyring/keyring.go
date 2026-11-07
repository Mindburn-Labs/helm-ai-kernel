// Package receiptkeyring is the one receipt keyring document shape HELM
// publishes at GET /api/v1/receipt-keyring: the Kernel for its evaluate
// receipts, and helm-gateway for its decision receipts, each on its own
// listener, for its own signer and under its own keyring_version label, so
// one service's keyring is never read as the other's.
package receiptkeyring

// quantum_posture: describes the public half of a receipt signer, classical
// Ed25519, hybrid Ed25519 + ML-DSA-65 or ML-DSA-65 alone; it signs nothing and
// claims no profile the signer lacks.

import (
	"encoding/json"
	"errors"
	"net/http"

	helmcrypto "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
)

const (
	// Path is where a HELM service publishes its receipt keyring.
	Path = "/api/v1/receipt-keyring"
	// KernelVersion labels the Kernel's keyring. The Control Plane pins it as
	// HELM_KERNEL_RECEIPT_KEYRING with a strict decoder (unknown fields
	// refused), so the shape must not grow fields under this label.
	KernelVersion = "kernel-evaluate-receipt-keyring.v1"
	// GatewayVersion labels helm-gateway's keyring: the same shape, for the
	// key that signs the gateway's decision receipts.
	GatewayVersion = "gateway-receipt-keyring.v1"
)

// Keyring is the published document.
type Keyring struct {
	KeyringVersion string      `json:"keyring_version"`
	Keys           []Authority `json:"keys"`
}

// Authority is one signing identity: the key id receipts carry as key_id, the
// signature profile they declare and the public keys that verify them.
type Authority struct {
	KeyID               string `json:"key_id"`
	Profile             string `json:"profile"`
	Ed25519PublicKeyHex string `json:"ed25519_public_key_hex,omitempty"`
	MLDSA65PublicKeyHex string `json:"ml_dsa_65_public_key_hex,omitempty"`
}

// For describes, under the publishing service's label, the identity signer
// stamps on every receipt: the same key id, profile and public keys that
// SignReceipt writes into KeyID, SignatureProfile and PublicKeySet.
func For(version string, signer helmcrypto.Signer) (Keyring, error) {
	if version != KernelVersion && version != GatewayVersion {
		return Keyring{}, errors.New("receipt keyring version must be the Kernel's or the gateway's")
	}
	var authority Authority
	switch s := signer.(type) {
	case *helmcrypto.Ed25519Signer:
		authority = Authority{KeyID: s.GetKeyID(), Profile: helmcrypto.ReceiptProfileClassical, Ed25519PublicKeyHex: s.PublicKey()}
	case *helmcrypto.HybridSigner:
		authority = Authority{KeyID: s.GetKeyID(), Profile: helmcrypto.ReceiptProfileHybrid, Ed25519PublicKeyHex: s.Ed25519Signer().PublicKey(), MLDSA65PublicKeyHex: s.MLDSASigner().PublicKey()}
	case *helmcrypto.MLDSASigner:
		authority = Authority{KeyID: s.GetKeyID(), Profile: helmcrypto.ReceiptProfilePQC, MLDSA65PublicKeyHex: s.PublicKey()}
	default:
		return Keyring{}, errors.New("receipt signer profile is not publishable")
	}
	if authority.KeyID == "" {
		return Keyring{}, errors.New("receipt signer has no key id")
	}
	return Keyring{KeyringVersion: version, Keys: []Authority{authority}}, nil
}

// Encode returns the exact response body for signer's keyring.
func Encode(version string, signer helmcrypto.Signer) ([]byte, error) {
	keyring, err := For(version, signer)
	if err != nil {
		return nil, err
	}
	return json.Marshal(keyring)
}

// Write serves an encoded keyring: JSON, never cached, so a rotated key is
// read the next time it is asked for.
func Write(w http.ResponseWriter, body []byte) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(body)
}
