package attention

import (
	"context"
	"fmt"
)

// AttentionRouter routes inbound signals to matching watches and produces attention scores.
type AttentionRouter interface {
	// Route evaluates a signal against all watches and returns attention scores.
	// Only watches whose entity type and ID match the subject are considered.
	Route(ctx context.Context, signalID string, class string, sensitivity string, subjectEntityID string, subjectEntityType string) ([]AttentionScore, error)

	// AddWatch registers a new watch for routing.
	AddWatch(ctx context.Context, watch *Watch) error

	// RemoveWatch unregisters a watch.
	RemoveWatch(ctx context.Context, watchID string) error
}

// DefaultRouter implements AttentionRouter using a WatchlistStore and ScoreComputer.
type DefaultRouter struct {
	store  WatchlistStore
	scorer *ScoreComputer
}

// NewDefaultRouter creates a new DefaultRouter backed by the given store.
func NewDefaultRouter(store WatchlistStore) *DefaultRouter {
	return &DefaultRouter{
		store:  store,
		scorer: NewScoreComputer(),
	}
}

// Route evaluates a signal against all matching watches and returns attention scores.
// A watch matches when its entity type and entity ID correspond to the signal's subject.
// Signals with a score > 0 are marked for routing; scores above the escalation threshold
// receive an EscalationHint.
func (r *DefaultRouter) Route(ctx context.Context, signalID string, class string, sensitivity string, subjectEntityID string, subjectEntityType string) ([]AttentionScore, error) {
	watches, err := r.store.ByEntity(ctx, subjectEntityType, subjectEntityID)
	if err != nil {
		return nil, fmt.Errorf("attention: failed to query watches: %w", err)
	}

	var scores []AttentionScore
	for _, w := range watches {
		score := r.scorer.Compute(class, sensitivity, w)
		as := AttentionScore{
			SignalID:       signalID,
			WatchID:        w.WatchID,
			Score:          score,
			Reason:         fmt.Sprintf("matched watch %q (type=%s, priority=%d)", w.WatchID, w.Type, w.Priority),
			ShouldRoute:    score > 0,
			EscalationHint: ShouldEscalate(score),
		}
		scores = append(scores, as)
	}

	return scores, nil
}

// AddWatch registers a new watch in the underlying store.
func (r *DefaultRouter) AddWatch(ctx context.Context, watch *Watch) error {
	return r.store.Add(ctx, watch)
}

// RemoveWatch removes a watch from the underlying store.
func (r *DefaultRouter) RemoveWatch(ctx context.Context, watchID string) error {
	return r.store.Remove(ctx, watchID)
}
