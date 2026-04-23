package connectors

import (
	"context"
	"fmt"
)

// validTransitions defines the allowed state machine edges for connector releases.
// Fail-closed: any transition not listed here is rejected.
var validTransitions = map[ConnectorReleaseState]map[ConnectorReleaseState]bool{
	ConnectorCandidate: {
		ConnectorCertified: true,
		ConnectorRevoked:   true,
	},
	ConnectorCertified: {
		ConnectorRevoked: true,
	},
	// Revoked is a terminal state — no outbound transitions.
}

// Transition moves a connector release from its current state to the target state.
// Fail-closed: the transition must be in the valid set, and the connector must exist.
func Transition(ctx context.Context, store ConnectorStore, id string, to ConnectorReleaseState) error {
	if store == nil {
		return fmt.Errorf("connector store is nil (fail-closed)")
	}

	release, err := store.Get(ctx, id)
	if err != nil {
		return fmt.Errorf("connector %q: cannot transition: %w", id, err)
	}

	from := release.State

	targets, ok := validTransitions[from]
	if !ok || !targets[to] {
		return fmt.Errorf("connector %q: invalid transition from %q to %q (fail-closed)", id, from, to)
	}

	release.State = to

	if err := store.Put(ctx, *release); err != nil {
		return fmt.Errorf("connector %q: failed to persist transition to %q: %w", id, to, err)
	}

	return nil
}
