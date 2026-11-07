package server

// quantum_posture: a fixed-seed classical Ed25519 signer for the receipts of
// decisions under test; no post-quantum claim.

import (
	"bytes"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
)

// testReceiptSigner signs every decision these tests record. The seed is
// fixed, so a stored receipt verifies under testReceiptSigner.PublicKey().
var testReceiptSigner = func() *crypto.Ed25519Signer {
	signer, err := crypto.NewEd25519SignerFromSeed(bytes.Repeat([]byte{0x5a}, 32), "helm-gateway-test")
	if err != nil {
		panic(err)
	}
	return signer
}()
