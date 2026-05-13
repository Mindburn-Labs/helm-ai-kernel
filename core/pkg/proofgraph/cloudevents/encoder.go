// Package cloudevents implements CloudEvents v1.0 encoding for ProofGraph nodes.
// This enables integration with enterprise SIEM systems (Splunk, Datadog, Elastic).
//
// CloudEvents spec: https://github.com/cloudevents/spec/blob/v1.0.2/cloudevents/spec.md
//
// Design invariants:
//   - Deterministic: same node + same clock => same CloudEvent output
//   - Offline: no network calls
//   - Spec-compliant: all required CloudEvents v1.0 attributes present
//   - Content-typed: data is application/json
//   - Batch-safe: supports both single and batch encoding
package cloudevents

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/proofgraph"
)

// ── Errors ───────────────────────────────────────────────────────────

var (
	// ErrNilNode is returned when a nil node is passed to the encoder.
	ErrNilNode = errors.New("cloudevents: nil node")

	// ErrMarshal is returned when JSON marshaling fails.
	ErrMarshal = errors.New("cloudevents: marshal failed")
)

// ── Constants ────────────────────────────────────────────────────────

const (
	// specVersion is the CloudEvents specification version.
	specVersion = "1.0"

	// defaultSource is the default CloudEvents source URI.
	defaultSource = "helm://proofgraph"

	// typePrefix is the prefix for CloudEvents type attribute.
	typePrefix = "helm.proofgraph."

	// dataContentType is the content type for CloudEvents data.
	dataContentType = "application/json"
)

// ── CloudEvent ───────────────────────────────────────────────────────

// CloudEvent represents a CloudEvents v1.0 structured-mode JSON event.
// All required attributes per CloudEvents v1.0 section 2 are present.
// HELM-specific extension attributes carry ProofGraph metadata for
// downstream correlation and verification.
type CloudEvent struct {
	// Required attributes (CloudEvents v1.0 section 2)
	SpecVersion string `json:"specversion"`
	ID          string `json:"id"`
	Source      string `json:"source"`
	Type        string `json:"type"`

	// Optional attributes
	Time            string `json:"time,omitempty"`
	DataContentType string `json:"datacontenttype,omitempty"`
	Subject         string `json:"subject,omitempty"`

	// Extension attributes (HELM-specific, prefixed with "helm")
	HelmNodeHash     string `json:"helmnode_hash,omitempty"`
	HelmLamport      uint64 `json:"helmlamport,omitempty"`
	HelmPrincipalSeq uint64 `json:"helmprincipal_seq,omitempty"`
	HelmSignature    string `json:"helmsignature,omitempty"`
	HelmParents      string `json:"helmparents,omitempty"`

	// Data payload
	Data json.RawMessage `json:"data"`
}

// ── Option ───────────────────────────────────────────────────────────

// Option configures the Encoder via the functional options pattern.
type Option func(*Encoder)

// WithSource sets the CloudEvents source URI.
// The source identifies the context in which the event happened (RFC 3986 URI).
func WithSource(source string) Option {
	return func(e *Encoder) {
		e.source = source
	}
}

// WithClock injects a clock function for deterministic time generation.
// When set, the clock is used as a fallback when a node has no timestamp.
func WithClock(clock func() time.Time) Option {
	return func(e *Encoder) {
		e.clock = clock
	}
}

// ── Encoder ──────────────────────────────────────────────────────────

// Encoder converts ProofGraph nodes to CloudEvents v1.0 events.
// It is safe for concurrent use.
type Encoder struct {
	source string
	clock  func() time.Time
}

// New creates a new CloudEvents encoder with the given options.
func New(opts ...Option) *Encoder {
	e := &Encoder{
		source: defaultSource,
		clock:  time.Now,
	}
	for _, opt := range opts {
		opt(e)
	}
	return e
}

// Encode converts a single ProofGraph node to a CloudEvent.
// Returns ErrNilNode if node is nil.
func (e *Encoder) Encode(node *proofgraph.Node) (*CloudEvent, error) {
	if node == nil {
		return nil, ErrNilNode
	}

	// Determine time: prefer node timestamp, fall back to encoder clock.
	var eventTime time.Time
	if node.Timestamp > 0 {
		eventTime = time.UnixMilli(node.Timestamp).UTC()
	} else {
		eventTime = e.clock().UTC()
	}

	// Build CloudEvents type: helm.proofgraph.<lowercase kind>
	eventType := typePrefix + strings.ToLower(string(node.Kind))

	// Build comma-separated parents list.
	parents := strings.Join(node.Parents, ",")

	// Data is the node's payload; use empty JSON object if nil/empty.
	data := node.Payload
	if len(data) == 0 {
		data = json.RawMessage(`{}`)
	}

	ce := &CloudEvent{
		SpecVersion:      specVersion,
		ID:               node.NodeHash,
		Source:           e.source,
		Type:             eventType,
		Time:             eventTime.Format(time.RFC3339Nano),
		DataContentType:  dataContentType,
		Subject:          node.Principal,
		HelmNodeHash:     node.NodeHash,
		HelmLamport:      node.Lamport,
		HelmPrincipalSeq: node.PrincipalSeq,
		HelmSignature:    node.Sig,
		HelmParents:      parents,
		Data:             data,
	}

	return ce, nil
}

// EncodeBatch converts a slice of ProofGraph nodes to CloudEvents.
// Returns an error wrapping the first node that fails encoding.
// A nil slice produces an empty (non-nil) result slice.
func (e *Encoder) EncodeBatch(nodes []*proofgraph.Node) ([]*CloudEvent, error) {
	events := make([]*CloudEvent, 0, len(nodes))
	for i, node := range nodes {
		ce, err := e.Encode(node)
		if err != nil {
			return nil, fmt.Errorf("cloudevents: batch index %d: %w", i, err)
		}
		events = append(events, ce)
	}
	return events, nil
}

// EncodeJSON converts a single ProofGraph node directly to JSON bytes.
// This is a convenience method combining Encode + json.Marshal.
func (e *Encoder) EncodeJSON(node *proofgraph.Node) ([]byte, error) {
	ce, err := e.Encode(node)
	if err != nil {
		return nil, err
	}
	data, err := json.Marshal(ce)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMarshal, err)
	}
	return data, nil
}

// EncodeBatchJSON converts a slice of ProofGraph nodes to a JSON array.
// Each element is a CloudEvent v1.0 structured-mode JSON object.
func (e *Encoder) EncodeBatchJSON(nodes []*proofgraph.Node) ([]byte, error) {
	events, err := e.EncodeBatch(nodes)
	if err != nil {
		return nil, err
	}
	data, err := json.Marshal(events)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMarshal, err)
	}
	return data, nil
}
