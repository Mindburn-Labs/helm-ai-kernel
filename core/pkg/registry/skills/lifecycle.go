package skills

import (
	"context"
	"fmt"
)

// validTransitions defines the allowed state machine edges for skill bundles.
// Fail-closed: any transition not listed here is rejected.
var validTransitions = map[SkillBundleState]map[SkillBundleState]bool{
	SkillBundleStateCandidate: {
		SkillBundleStateCertified: true,
		SkillBundleStateRevoked:   true,
	},
	SkillBundleStateCertified: {
		SkillBundleStateDeprecated: true,
		SkillBundleStateRevoked:    true,
	},
	SkillBundleStateDeprecated: {
		SkillBundleStateRevoked: true,
	},
	// Revoked is a terminal state — no outbound transitions.
}

// Transition moves a skill bundle from its current state to the target state.
// Fail-closed: the transition must be in the valid set, and the skill must exist.
func Transition(ctx context.Context, store SkillStore, id string, to SkillBundleState) error {
	if store == nil {
		return fmt.Errorf("skill store is nil (fail-closed)")
	}

	manifest, err := store.Get(ctx, id)
	if err != nil {
		return fmt.Errorf("skill %q: cannot transition: %w", id, err)
	}

	from := manifest.State

	targets, ok := validTransitions[from]
	if !ok || !targets[to] {
		return fmt.Errorf("skill %q: invalid transition from %q to %q (fail-closed)", id, from, to)
	}

	manifest.State = to

	if err := store.Put(ctx, *manifest); err != nil {
		return fmt.Errorf("skill %q: failed to persist transition to %q: %w", id, to, err)
	}

	return nil
}
