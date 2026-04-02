package replay

import (
	"context"
	"fmt"
	"time"
)

// ReplayMode defines how a replay should be executed.
type ReplayMode string

const (
	// ReplayModeDry verifies receipt hashes without re-execution.
	ReplayModeDry ReplayMode = "dry"

	// ReplayModeBounded re-executes but skips network effects.
	ReplayModeBounded ReplayMode = "bounded"

	// ReplayModeFull recreates the full sandbox environment and re-executes.
	ReplayModeFull ReplayMode = "full"
)

// ReplayManifest contains everything needed to replay a prior run.
type ReplayManifest struct {
	// ManifestID is the unique identifier.
	ManifestID string `json:"manifest_id"`

	// RunID identifies the original run.
	RunID string `json:"run_id"`

	// Backend is the sandbox backend used in the original run.
	Backend string `json:"backend"`

	// TemplateRef identifies the sandbox template.
	TemplateRef string `json:"template_ref,omitempty"`

	// WorkspaceSnapshotRef is a content-addressed reference to the workspace state.
	WorkspaceSnapshotRef string `json:"workspace_snapshot_ref,omitempty"`

	// PolicyPackRefs lists the policy packs that were active during the run.
	PolicyPackRefs []string `json:"policy_pack_refs,omitempty"`

	// OrderedEffectIDs lists the effects in execution order.
	OrderedEffectIDs []string `json:"ordered_effect_ids"`

	// ExpectedReceiptHashes lists the expected receipt hashes in order.
	ExpectedReceiptHashes []string `json:"expected_receipt_hashes,omitempty"`

	// Mode specifies the replay execution mode.
	Mode ReplayMode `json:"mode"`

	// CreatedAt is when the manifest was generated.
	CreatedAt time.Time `json:"created_at"`
}

// StartReplayWithManifest begins a mode-aware replay using a manifest.
// - "dry" mode: verifies receipt hashes without re-execution
// - "bounded" mode: re-executes but skips network-classified effects
// - "full" mode: full sandbox recreation and re-execution
func (e *Engine) StartReplayWithManifest(ctx context.Context, manifest *ReplayManifest) (*Session, error) {
	if manifest == nil {
		return nil, fmt.Errorf("manifest is nil")
	}

	switch manifest.Mode {
	case ReplayModeDry:
		return e.replayDry(ctx, manifest)
	case ReplayModeBounded, ReplayModeFull:
		return e.replayExecute(ctx, manifest)
	default:
		return nil, fmt.Errorf("unknown replay mode: %s", manifest.Mode)
	}
}

// replayDry verifies receipt hashes against expected values without re-execution.
func (e *Engine) replayDry(ctx context.Context, manifest *ReplayManifest) (*Session, error) {
	events, err := e.source.GetRunEvents(ctx, manifest.RunID)
	if err != nil {
		return nil, fmt.Errorf("fetch events: %w", err)
	}

	session := &Session{
		SessionID:  fmt.Sprintf("replay-dry-%s-%d", manifest.RunID, e.clock().UnixNano()),
		RunID:      manifest.RunID,
		Status:     SessionStatusRunning,
		TotalSteps: len(events),
		StartedAt:  e.clock(),
		Steps:      make([]Step, 0, len(events)),
	}

	e.mu.Lock()
	e.sessions[session.SessionID] = session
	e.mu.Unlock()

	// Verify each event's output hash against expected.
	for i, event := range events {
		step := Step{
			SequenceNumber: event.SequenceNumber,
			EventID:        event.EventID,
			EventType:      event.EventType,
			InputHash:      event.PayloadHash,
			OutputHash:     event.OutputHash,
		}
		session.Steps = append(session.Steps, step)
		session.ReplayedSteps = i + 1

		// Check against expected hashes if available.
		if i < len(manifest.ExpectedReceiptHashes) && manifest.ExpectedReceiptHashes[i] != "" {
			if event.OutputHash != manifest.ExpectedReceiptHashes[i] {
				session.Status = SessionStatusDiverged
				session.DivergencePoint = i
				session.DivergenceInfo = fmt.Sprintf(
					"dry replay: receipt hash mismatch at step %d: expected %s, got %s",
					i, manifest.ExpectedReceiptHashes[i], event.OutputHash,
				)
				session.CompletedAt = e.clock()
				return session, nil
			}
		}
	}

	// Compute hashes.
	originalHash, _ := computeRunHash(events)
	session.OriginalHash = originalHash
	session.ReplayHash = originalHash // In dry mode, replay hash equals original.
	session.Status = SessionStatusComplete
	session.CompletedAt = e.clock()
	return session, nil
}

// replayExecute re-executes events (bounded skips NETWORK types, full runs all).
func (e *Engine) replayExecute(ctx context.Context, manifest *ReplayManifest) (*Session, error) {
	events, err := e.source.GetRunEvents(ctx, manifest.RunID)
	if err != nil {
		return nil, fmt.Errorf("fetch events: %w", err)
	}

	originalHash, _ := computeRunHash(events)

	session := &Session{
		SessionID:    fmt.Sprintf("replay-%s-%s-%d", manifest.Mode, manifest.RunID, e.clock().UnixNano()),
		RunID:        manifest.RunID,
		Status:       SessionStatusRunning,
		TotalSteps:   len(events),
		OriginalHash: originalHash,
		StartedAt:    e.clock(),
		Steps:        make([]Step, 0, len(events)),
	}

	e.mu.Lock()
	e.sessions[session.SessionID] = session
	e.mu.Unlock()

	for i, event := range events {
		// In bounded mode, skip network effects.
		if manifest.Mode == ReplayModeBounded && event.EventType == "NETWORK" {
			step := Step{
				SequenceNumber: event.SequenceNumber,
				EventID:        event.EventID,
				EventType:      event.EventType,
				InputHash:      event.PayloadHash,
				OutputHash:     event.OutputHash, // Use original output.
			}
			session.Steps = append(session.Steps, step)
			session.ReplayedSteps = i + 1
			continue
		}

		start := e.clock()
		outputHash, err := e.executor.ReplayEvent(ctx, event)
		elapsed := e.clock().Sub(start)

		step := Step{
			SequenceNumber: event.SequenceNumber,
			EventID:        event.EventID,
			EventType:      event.EventType,
			InputHash:      event.PayloadHash,
			OutputHash:     outputHash,
			Duration:       elapsed,
		}
		session.Steps = append(session.Steps, step)
		session.ReplayedSteps = i + 1

		if err != nil {
			session.Status = SessionStatusFailed
			session.DivergencePoint = i
			session.DivergenceInfo = fmt.Sprintf("execution failed at step %d: %v", i, err)
			session.CompletedAt = e.clock()
			return session, nil
		}

		if event.OutputHash != "" && outputHash != event.OutputHash {
			session.Status = SessionStatusDiverged
			session.DivergencePoint = i
			session.DivergenceInfo = fmt.Sprintf(
				"output diverged at step %d: expected %s, got %s",
				i, event.OutputHash, outputHash,
			)
			session.CompletedAt = e.clock()
			return session, nil
		}
	}

	replayHash, _ := computeReplayHash(session.Steps)
	session.ReplayHash = replayHash
	session.Status = SessionStatusComplete
	session.CompletedAt = e.clock()
	return session, nil
}
