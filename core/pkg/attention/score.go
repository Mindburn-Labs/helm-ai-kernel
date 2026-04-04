package attention

// sensitivityWeights maps sensitivity labels to multiplier weights.
// Higher-sensitivity signals produce higher attention scores.
var sensitivityWeights = map[string]float64{
	"PUBLIC":       0.2,
	"INTERNAL":     0.4,
	"CONFIDENTIAL": 0.7,
	"RESTRICTED":   1.0,
}

// ScoreComputer computes attention scores for signal-watch pairs.
type ScoreComputer struct{}

// NewScoreComputer creates a new ScoreComputer.
func NewScoreComputer() *ScoreComputer {
	return &ScoreComputer{}
}

// Compute calculates an attention score for a signal matched against a watch.
// The formula is: sensitivityWeight * (priority / 100).
// Returns a value clamped to [0.0, 1.0].
func (sc *ScoreComputer) Compute(signalClass, sensitivity string, watch *Watch) float64 {
	_ = signalClass // reserved for future class-based weighting

	weight, ok := sensitivityWeights[sensitivity]
	if !ok {
		weight = 0.2 // default to PUBLIC weight for unknown sensitivity
	}

	priority := float64(watch.Priority) / 100.0
	if priority < 0 {
		priority = 0
	}
	if priority > 1 {
		priority = 1
	}

	score := weight * priority
	if score < 0 {
		return 0
	}
	if score > 1 {
		return 1
	}
	return score
}
