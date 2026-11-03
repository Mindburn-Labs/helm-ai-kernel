package a2a

import (
	"encoding/hex"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
)

// fakeVerifier returns a verifier function that uses Ed25519 verification.
func fakeVerifier() func(pubKey, data, sig string) bool {
	return func(pubKey, data, sig string) bool {
		dataBytes, err := hex.DecodeString(data)
		if err != nil {
			return false
		}
		ok, err := crypto.Verify(pubKey, sig, dataBytes)
		if err != nil {
			return false
		}
		return ok
	}
}
