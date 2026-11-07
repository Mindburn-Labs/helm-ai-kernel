package executor

import (
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
)

func mustSigner(t *testing.T) crypto.Signer {
	t.Helper()
	s, err := crypto.NewEd25519Signer("test-key")
	if err != nil {
		t.Fatalf("failed to create signer: %v", err)
	}
	return s
}
