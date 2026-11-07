package governance

import (
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
)

type StateEstimator struct {
	ProducerID string
	signer     crypto.Signer
}
