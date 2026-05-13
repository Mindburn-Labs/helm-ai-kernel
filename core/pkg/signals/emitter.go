package signals

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/interfaces"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/proofgraph"
)

// EventTypeSignalIngested is the event type constant for signal ingestion events.
const EventTypeSignalIngested = "SIGNAL_INGESTED"

// SignalEmitter writes normalized signals to the EventRepository and ProofGraph.
type SignalEmitter struct {
	events     interfaces.EventRepository
	graph      *proofgraph.Graph
	dedup      DedupStore
	normalizer Normalizer
	logger     *slog.Logger
}

// EmitterConfig configures the SignalEmitter.
type EmitterConfig struct {
	Events     interfaces.EventRepository
	Graph      *proofgraph.Graph
	Dedup      DedupStore
	Normalizer Normalizer
	Logger     *slog.Logger
}

// NewSignalEmitter creates a new signal emitter.
func NewSignalEmitter(cfg EmitterConfig) (*SignalEmitter, error) {
	if cfg.Events == nil {
		return nil, fmt.Errorf("signals: EventRepository is required")
	}
	if cfg.Graph == nil {
		return nil, fmt.Errorf("signals: ProofGraph is required")
	}

	dedup := cfg.Dedup
	if dedup == nil {
		dedup = NewInMemoryDedupStore()
	}

	normalizer := cfg.Normalizer
	if normalizer == nil {
		normalizer = NewDefaultNormalizer()
	}

	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}

	return &SignalEmitter{
		events:     cfg.Events,
		graph:      cfg.Graph,
		dedup:      dedup,
		normalizer: normalizer,
		logger:     logger,
	}, nil
}

// EmitResult is the result of emitting a signal.
type EmitResult struct {
	// SignalID is the ID of the emitted signal.
	SignalID string

	// Duplicate is true if the signal was a duplicate and was skipped.
	Duplicate bool

	// ProofNodeHash is the hash of the ProofGraph node created for this signal.
	ProofNodeHash string
}

// Emit normalizes and emits a signal. Returns the result or an error.
//
// Fail-closed: normalization failure results in the signal being dropped (not silently accepted).
// Duplicate signals are detected via the DedupStore and skipped.
func (e *SignalEmitter) Emit(ctx context.Context, env *SignalEnvelope) (*EmitResult, error) {
	// Normalize
	if err := e.normalizer.Normalize(env); err != nil {
		e.logger.WarnContext(ctx, "signal normalization failed, dropping signal",
			"signal_id", env.SignalID,
			"class", env.Class,
			"error", err,
		)
		return nil, fmt.Errorf("signals: normalization failed: %w", err)
	}

	// Deduplicate
	if e.dedup.HasSeen(env.IdempotencyKey) {
		e.logger.DebugContext(ctx, "duplicate signal detected, skipping",
			"signal_id", env.SignalID,
			"idempotency_key", env.IdempotencyKey,
		)
		return &EmitResult{
			SignalID:  env.SignalID,
			Duplicate: true,
		}, nil
	}

	// Record in dedup store
	if err := e.dedup.Record(env.IdempotencyKey); err != nil {
		return nil, fmt.Errorf("signals: dedup record failed: %w", err)
	}

	// Write to EventRepository
	_, err := e.events.Append(ctx, EventTypeSignalIngested, env.Source.PrincipalID, env)
	if err != nil {
		return nil, fmt.Errorf("signals: event append failed: %w", err)
	}

	// Write to ProofGraph as INTENT node
	payload, err := json.Marshal(signalProofPayload{
		SignalID:    env.SignalID,
		Class:       string(env.Class),
		ContentHash: env.ContentHash,
		SourceID:    env.Source.SourceID,
		ConnectorID: env.Source.ConnectorID,
	})
	if err != nil {
		return nil, fmt.Errorf("signals: proof payload marshal failed: %w", err)
	}

	node, err := e.graph.Append(proofgraph.NodeTypeIntent, payload, env.Source.PrincipalID, 0)
	if err != nil {
		return nil, fmt.Errorf("signals: proofgraph append failed: %w", err)
	}

	e.logger.InfoContext(ctx, "signal emitted",
		"signal_id", env.SignalID,
		"class", env.Class,
		"source_id", env.Source.SourceID,
		"content_hash", env.ContentHash,
		"proof_node", node.NodeHash,
	)

	return &EmitResult{
		SignalID:      env.SignalID,
		Duplicate:     false,
		ProofNodeHash: node.NodeHash,
	}, nil
}

// signalProofPayload is the structured payload stored in the ProofGraph node.
type signalProofPayload struct {
	SignalID    string `json:"signal_id"`
	Class       string `json:"class"`
	ContentHash string `json:"content_hash"`
	SourceID    string `json:"source_id"`
	ConnectorID string `json:"connector_id"`
}
