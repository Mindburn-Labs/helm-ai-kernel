package contracts

import (
	"time"
)

// EffectReceipt is the outcome of executing an effect.
// Originally 'Result' in gateway.
type EffectReceipt struct {
	Success   bool           `json:"success"`
	Output    map[string]any `json:"output,omitempty"`
	Error     string         `json:"error,omitempty"`
	Duration  time.Duration  `json:"duration"`
	Timestamp time.Time      `json:"timestamp"`
}
