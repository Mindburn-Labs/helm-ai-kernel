package executor

import (
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

func createTestPack() *contracts.EvidencePack {
	return &contracts.EvidencePack{
		PackID:    "test-pack-1",
		CreatedAt: time.Now(),
		Attestation: contracts.EvidencePackAttestation{
			Signature: "test-signature",
		},
	}
}
