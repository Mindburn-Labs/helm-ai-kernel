package governance

import (
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
)

type SignalController struct {
	ProducerID string
	signer     crypto.Signer
}

type signalAdvicePayload struct {
	Signal  string         `json:"signal"`
	Health  float64        `json:"health"`
	Check   string         `json:"check"`
	Intent  string         `json:"intent"`
	Metrics map[string]any `json:"metrics"`
	Reasons []string       `json:"reasons,omitempty"`
}
