package signals

import (
	"encoding/json"
	"time"
)

// SignalEnvelope is the canonical typed envelope for an inbound business event.
// It carries normalized metadata and a raw payload that is connector-agnostic.
//
// The ContentHash is computed via JCS canonicalization (RFC 8785) + SHA-256,
// consistent with ProofGraph node hashing.
type SignalEnvelope struct {
	// SignalID is the unique identifier for this signal.
	SignalID string `json:"signal_id"`

	// Class categorizes the business event type.
	Class SignalClass `json:"class"`

	// Source identifies where this signal came from.
	Source SignalSource `json:"source"`

	// Subject optionally identifies the primary entity this signal is about.
	Subject *SignalSubject `json:"subject,omitempty"`

	// ThreadRef optionally links this signal to a conversation thread.
	ThreadRef *SignalThreadRef `json:"thread_ref,omitempty"`

	// Artifacts lists any attachments or referenced artifacts.
	Artifacts []SignalArtifactRef `json:"artifacts,omitempty"`

	// Provenance tracks ingestion and normalization metadata.
	Provenance SignalProvenance `json:"provenance"`

	// Sensitivity classifies the content sensitivity for access control.
	Sensitivity SensitivityTag `json:"sensitivity"`

	// ContentHash is the SHA-256 of the JCS-canonical RawPayload.
	ContentHash string `json:"content_hash"`

	// RawPayload is the original event payload preserved as-is.
	// The signal layer does not interpret this — typed interpretation
	// happens in connector-specific adapters.
	RawPayload json.RawMessage `json:"raw_payload"`

	// IdempotencyKey is the dedupe key (source_id + external_id + content_hash).
	IdempotencyKey string `json:"idempotency_key"`

	// ExternalID is the source system's native identifier for this event.
	ExternalID string `json:"external_id,omitempty"`

	// ReceivedAt is when the signal was received by HELM.
	ReceivedAt time.Time `json:"received_at"`
}

// SignalSource identifies the origin of a signal.
type SignalSource struct {
	// SourceID is a stable identifier for the source instance (e.g., "gmail-workspace-acme").
	SourceID string `json:"source_id"`

	// SourceType is the connector type (e.g., "gmail", "slack", "jira").
	SourceType string `json:"source_type"`

	// PrincipalID references the identity.Principal.ID() that owns this source.
	PrincipalID string `json:"principal_id"`

	// ConnectorID is the HELM connector that produced this signal.
	ConnectorID string `json:"connector_id"`

	// TrustLevel is the connector's trust classification.
	// Reuses connector.TrustLevel values: FULL, VERIFIED, RESTRICTED, UNTRUSTED.
	TrustLevel string `json:"trust_level"`
}

// SignalSubject identifies the primary entity a signal is about.
type SignalSubject struct {
	// EntityType categorizes the entity (e.g., "person", "account", "project", "incident").
	EntityType string `json:"entity_type"`

	// EntityID is the stable identifier for the entity.
	EntityID string `json:"entity_id"`

	// EntityName is a human-readable name for display.
	EntityName string `json:"entity_name,omitempty"`
}

// SignalThreadRef links a signal to a conversation thread.
type SignalThreadRef struct {
	// ThreadID is the conversation thread identifier.
	ThreadID string `json:"thread_id"`

	// ParentID is the parent message in the thread, if any.
	ParentID string `json:"parent_id,omitempty"`

	// SequenceNo is the position in the thread.
	SequenceNo int `json:"sequence_no,omitempty"`
}

// SignalArtifactRef references an attachment or artifact associated with a signal.
type SignalArtifactRef struct {
	// ArtifactID is the unique identifier for this artifact.
	ArtifactID string `json:"artifact_id"`

	// MimeType is the content type.
	MimeType string `json:"mime_type"`

	// Hash is the SHA-256 content hash.
	Hash string `json:"hash"`

	// SizeBytes is the artifact size.
	SizeBytes int64 `json:"size_bytes"`

	// URI is an optional retrieval URI.
	URI string `json:"uri,omitempty"`
}

// SignalProvenance tracks the ingestion and normalization chain for a signal.
type SignalProvenance struct {
	// IngestedAt is when the signal entered HELM.
	IngestedAt time.Time `json:"ingested_at"`

	// IngestedBy is the connector or adapter that ingested the signal.
	IngestedBy string `json:"ingested_by"`

	// SourceTimestamp is the event's timestamp in the source system.
	SourceTimestamp *time.Time `json:"source_timestamp,omitempty"`

	// ChainHash links this signal to the previous signal from the same source
	// for tamper detection.
	ChainHash string `json:"chain_hash,omitempty"`

	// NormalizedAt is when normalization completed.
	NormalizedAt time.Time `json:"normalized_at"`
}
