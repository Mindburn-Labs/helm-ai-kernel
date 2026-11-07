package governance

import (
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
)

type PolicyInductor struct {
	ProducerID string
	signer     crypto.Signer
}
