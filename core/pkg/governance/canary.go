package governance

// CanaryConfig defines how to roll out a change.
type CanaryConfig struct {
	StepDurationSec int `json:"step_duration_sec"`
	Steps           int `json:"steps"` // e.g. 10%, 50%, 100%
}

// DefaultCanary is the safe default.
var DefaultCanary = CanaryConfig{
	StepDurationSec: 300,
	Steps:           3,
}

// FastCanary for urgent fixes.
var FastCanary = CanaryConfig{
	StepDurationSec: 30,
	Steps:           1,
}
