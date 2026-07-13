package crypto

import (
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

func executableIntentFixture(id, decisionID, effectDigestHash, allowedTool string) *contracts.AuthorizedExecutionIntent {
	issuedAt := time.Date(2026, time.July, 13, 12, 0, 0, 0, time.UTC)
	return &contracts.AuthorizedExecutionIntent{
		ID:               id,
		DecisionID:       decisionID,
		EffectDigestHash: effectDigestHash,
		IssuedAt:         issuedAt,
		ExpiresAt:        issuedAt.Add(5 * time.Minute),
		Signer:           "test-kernel",
		AllowedTool:      allowedTool,
	}
}
