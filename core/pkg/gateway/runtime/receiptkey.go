package runtime

// quantum_posture: loads a classical Ed25519 receipt signing seed through
// core/pkg/crypto's Ed25519 constructor and prints its public half; no hybrid
// or post-quantum key is loaded and no post-quantum claim is made.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/admission"
)

const (
	// envReceiptSigningKeyFile names the file holding the 32-byte Ed25519
	// seed the gateway signs its decision receipts with, hex or standard
	// base64. The chart mounts it into the gateway Pod only (R8).
	envReceiptSigningKeyFile = "HELM_GATEWAY_RECEIPT_SIGNING_KEY_FILE"
	// envReceiptKeyID is the public label every receipt carries as key_id and
	// a verifier names the key by: receipt_verify --key "<key_id>=<hex>".
	envReceiptKeyID = "HELM_GATEWAY_RECEIPT_KEY_ID"
	// envReceiptKeyIDPrefix, set instead of envReceiptKeyID, derives the key
	// id from the key: "<prefix>:<first 16 hex of SHA-256(public key)>", so a
	// new seed is never published under the old key's id. The chart's
	// default key id uses it.
	envReceiptKeyIDPrefix = "HELM_GATEWAY_RECEIPT_KEY_ID_PREFIX"
	// maxReceiptKeyFile bounds the read: a seed is at most 64 hex characters
	// and a line ending.
	maxReceiptKeyFile = 1024
)

// receiptSignerFromEnv loads the receipt signing key. It refuses to go on
// without one, and refuses anything but a 32-byte seed: a passphrase hashed
// to a seed has the passphrase's entropy, not a key's.
func receiptSignerFromEnv(getenv func(string) string) (*crypto.Ed25519Signer, error) {
	path := strings.TrimSpace(getenv(envReceiptSigningKeyFile))
	keyID := strings.TrimSpace(getenv(envReceiptKeyID))
	prefix := strings.TrimSpace(getenv(envReceiptKeyIDPrefix))
	if path == "" || (keyID == "") == (prefix == "") {
		return nil, fmt.Errorf("%s and exactly one of %s or %s are required: every gateway decision is recorded with a signed receipt",
			envReceiptSigningKeyFile, envReceiptKeyID, envReceiptKeyIDPrefix)
	}
	f, err := os.Open(path) // #nosec G304 -- operator-supplied Secret mount path
	if err != nil {
		return nil, fmt.Errorf("%s: %w", envReceiptSigningKeyFile, err)
	}
	defer func() { _ = f.Close() }()
	raw, err := io.ReadAll(io.LimitReader(f, maxReceiptKeyFile+1))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", envReceiptSigningKeyFile, err)
	}
	if len(raw) > maxReceiptKeyFile {
		return nil, fmt.Errorf("%s holds more than a 32-byte Ed25519 seed", envReceiptSigningKeyFile)
	}
	seed := decodeReceiptSeed(string(bytes.TrimSpace(raw)))
	if seed == nil {
		return nil, fmt.Errorf("%s must hold a 32-byte Ed25519 seed, hex or standard base64; a passphrase or a private key in another form is refused",
			envReceiptSigningKeyFile)
	}
	if bytes.Equal(seed, make([]byte, ed25519.SeedSize)) {
		return nil, fmt.Errorf("%s holds an all-zero seed, which is not a secret", envReceiptSigningKeyFile)
	}
	if prefix != "" {
		public := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
		fingerprint := sha256.Sum256(public)
		keyID = prefix + ":" + hex.EncodeToString(fingerprint[:8])
	}
	signer, err := crypto.NewEd25519SignerFromSeed(seed, keyID)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", envReceiptSigningKeyFile, err)
	}
	if err := admission.CheckReceiptSigner(signer); err != nil {
		return nil, fmt.Errorf("receipt key id: %w", err)
	}
	return signer, nil
}

// decodeReceiptSeed returns the 32 bytes a hex or standard base64 seed
// encodes, or nil for anything else.
func decodeReceiptSeed(text string) []byte {
	if seed, err := hex.DecodeString(text); err == nil && len(seed) == ed25519.SeedSize {
		return seed
	}
	if seed, err := base64.StdEncoding.DecodeString(text); err == nil && len(seed) == ed25519.SeedSize {
		return seed
	}
	return nil
}

// runReceiptKey serves `helm-gateway receipt-key`: it prints the public half
// of the configured receipt key as "<key_id>=<public key hex>", the form
// receipt_verify --key takes. The seed is never printed.
func runReceiptKey(args []string, getenv func(string) string, stdout io.Writer) error {
	if len(args) != 0 {
		return fmt.Errorf("usage: helm-gateway receipt-key (reads %s and %s or %s)", envReceiptSigningKeyFile, envReceiptKeyID, envReceiptKeyIDPrefix)
	}
	signer, err := receiptSignerFromEnv(getenv)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(stdout, "%s=%s\n", signer.GetKeyID(), signer.PublicKey())
	return err
}
