package a2a

import (
	"sync"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/trust"
)

func newTestScorer(clock trust.BehavioralClock) *trust.BehavioralTrustScorer {
	return trust.NewBehavioralTrustScorer(
		trust.WithBehavioralClock(clock),
		trust.WithScorerConfig(trust.ScorerConfig{
			InitialScore:     500,
			MaxHistorySize:   100,
			PositiveHalfLife: 24 * time.Hour,
			NegativeHalfLife: 72 * time.Hour,
		}),
	)
}

type fixedClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fixedClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fixedClock) Set(t time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = t
}
