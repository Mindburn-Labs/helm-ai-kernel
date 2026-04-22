// Package kernel provides low-level primitives for the HELM kernel.
// Per Section 1.3 - Authoritative Event Log
package kernel

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/canonicalize"
)

// EventEnvelope represents a kernel event with normative time semantics.
// Per Section 2.3 - Time Semantics
type EventEnvelope struct {
	EventID        string                 `json:"event_id"`
	EventType      string                 `json:"event_type"`
	SequenceNumber uint64                 `json:"sequence_number"`
	ObservedAt     time.Time              `json:"observed_at"`
	ReceivedAt     time.Time              `json:"received_at"`
	CommittedAt    time.Time              `json:"committed_at,omitempty"`
	PayloadHash    string                 `json:"payload_hash"`
	Payload        map[string]interface{} `json:"payload,omitempty"`
	Causation      *CausationContext      `json:"causation,omitempty"`
	Entropy        *EntropyContext        `json:"entropy,omitempty"`
}

// CausationContext tracks event causality chain.
type CausationContext struct {
	ParentEventID  string   `json:"parent_event_id,omitempty"`
	CorrelationID  string   `json:"correlation_id,omitempty"`
	CausationChain []string `json:"causation_chain,omitempty"`
}

// EntropyContext tracks PRNG seed per Section 2.4.
type EntropyContext struct {
	Seed          string `json:"seed,omitempty"`
	PRNGAlgorithm string `json:"prng_algorithm,omitempty"`
	LoopID        string `json:"loop_id,omitempty"`
}

// EventLog defines the authoritative event log interface.
// Per Section 1.3 - Authoritative Event Log
type EventLog interface {
	// Append adds an event to the log. Returns committed sequence number.
	Append(ctx context.Context, event *EventEnvelope) (uint64, error)

	// Get retrieves an event by sequence number.
	Get(ctx context.Context, seq uint64) (*EventEnvelope, error)

	// Range returns events in [start, end] sequence range.
	Range(ctx context.Context, start, end uint64) ([]*EventEnvelope, error)

	// LastSequence returns the highest committed sequence number.
	LastSequence() uint64

	// Hash returns the cumulative hash of all committed events.
	Hash() string
}

// InMemoryEventLog is a reference implementation for testing.
type InMemoryEventLog struct {
	mu             sync.RWMutex
	events         []*EventEnvelope
	sequenceNumber uint64
	cumulativeHash string
}

// NewInMemoryEventLog creates a new in-memory event log.
func NewInMemoryEventLog() *InMemoryEventLog {
	return &InMemoryEventLog{
		events:         make([]*EventEnvelope, 0),
		sequenceNumber: 0,
		cumulativeHash: "",
	}
}

// Append adds an event with canonical encoding.
func (l *InMemoryEventLog) Append(ctx context.Context, event *EventEnvelope) (uint64, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	// Assign sequence number
	l.sequenceNumber++
	event.SequenceNumber = l.sequenceNumber

	// Set committed timestamp
	event.CommittedAt = time.Now().UTC()

	// Compute payload hash using canonical encoding (JCS - sorted keys)
	payloadHash, err := canonicalize.CanonicalHash(event.Payload)
	if err != nil {
		return 0, fmt.Errorf("failed to compute payload hash: %w", err)
	}
	event.PayloadHash = payloadHash

	// Update cumulative hash
	eventHash, err := canonicalize.CanonicalHash(map[string]interface{}{
		"event_id":        event.EventID,
		"sequence_number": event.SequenceNumber,
		"payload_hash":    event.PayloadHash,
		"previous_hash":   l.cumulativeHash,
	})
	if err != nil {
		return 0, fmt.Errorf("failed to compute event hash: %w", err)
	}
	l.cumulativeHash = eventHash

	l.events = append(l.events, event)

	return event.SequenceNumber, nil
}

// Get retrieves an event by sequence number.
func (l *InMemoryEventLog) Get(ctx context.Context, seq uint64) (*EventEnvelope, error) {
	l.mu.RLock()
	defer l.mu.RUnlock()

	if seq == 0 || seq > uint64(len(l.events)) {
		return nil, fmt.Errorf("event not found: sequence %d", seq)
	}
	return l.events[seq-1], nil
}

// Range returns events in sequence range [start, end].
func (l *InMemoryEventLog) Range(ctx context.Context, start, end uint64) ([]*EventEnvelope, error) {
	l.mu.RLock()
	defer l.mu.RUnlock()

	if start == 0 || start > end {
		return nil, fmt.Errorf("invalid range: [%d, %d]", start, end)
	}

	maxSeq := uint64(len(l.events))
	if start > maxSeq {
		return []*EventEnvelope{}, nil
	}
	if end > maxSeq {
		end = maxSeq
	}

	return l.events[start-1 : end], nil
}

// LastSequence returns the highest committed sequence number.
func (l *InMemoryEventLog) LastSequence() uint64 {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.sequenceNumber
}

// Hash returns the cumulative hash of all committed events.
func (l *InMemoryEventLog) Hash() string {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.cumulativeHash
}
