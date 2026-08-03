// Package events provides the canonical event type catalog for the HELM runtime.
package events

// Runtime extension event types.
const (
	// Skill lifecycle
	SkillBundleInstalled    = "helm.skill.bundle.installed.v1"
	SkillBundleRevoked      = "helm.skill.bundle.revoked.v1"
	SkillCandidateGenerated = "helm.skill.candidate.generated.v1"
	SkillPromotionRequested = "helm.skill.promotion.requested.v1"
	SkillPromotionDecided   = "helm.skill.promotion.decided.v1"

	// Scheduling
	ScheduleRegistered = "helm.schedule.registered.v1"
	ScheduleTriggered  = "helm.schedule.triggered.v1"

	// Channels
	ChannelMessageReceived    = "helm.channel.message.received.v1"
	ChannelMessageSent        = "helm.channel.message.sent.v1"
	ChannelMessageQuarantined = "helm.channel.message.quarantined.v1"

	// Artifacts
	ArtifactCreated = "helm.artifact.created.v1"
	ArtifactDerived = "helm.artifact.derived.v1"

	// Knowledge
	KnowledgeClaimWritten            = "helm.knowledge.claim.written.v1"
	KnowledgeClaimPromotionRequested = "helm.knowledge.claim.promotion.requested.v1"
	KnowledgeClaimPromoted           = "helm.knowledge.claim.promoted.v1"

	// Connectors
	ConnectorReleaseCertified = "helm.connector.release.certified.v1"
	ConnectorReleaseRevoked   = "helm.connector.release.revoked.v1"
)

// EventSchemaVersion is the current envelope version (§4). v2 added the
// identity and data-class fields below; every field it introduced is optional,
// so a v1 producer keeps emitting valid events.
const EventSchemaVersion = 2

// Data classes for EventMeta.Env (§7). Retention and placement are cut by this
// value rather than by which stand produced the event, so a pilot event
// carries its class wherever it is copied.
const (
	EnvSynthetic      = "synthetic"
	EnvPilot          = "pilot"
	EnvCustomerHosted = "customer-hosted"
)

// EventMeta is common metadata for all events.
//
// v2 fields are additive and omitempty: they carry the identity that turns a
// pile of events into one request's story (§2, §3). correlation_id is the join
// key and survives sampling; trace_id/span_id link the story to its trace and
// may not.
type EventMeta struct {
	EventID     string `json:"event_id"`
	EventType   string `json:"event_type"`
	TenantID    string `json:"tenant_id"`
	TimestampMs int64  `json:"timestamp_ms"`
	SourceRef   string `json:"source_ref,omitempty"`

	// --- v2 ---

	// CorrelationID is the product request identity (§2). It is the stable
	// join key across events, receipts and evidence.
	CorrelationID string `json:"correlation_id,omitempty"`
	// RunID identifies a multi-request run when one exists.
	RunID string `json:"run_id,omitempty"`
	// TraceID and SpanID are copied from the active span for trace
	// correlation (§3). Deliberately distinct from CorrelationID: sampling
	// may drop the trace while the product identity survives.
	TraceID string `json:"trace_id,omitempty"`
	SpanID  string `json:"span_id,omitempty"`
	// Env is the data class (§7), one of the Env* constants above.
	Env string `json:"env,omitempty"`
	// SchemaVersion is the envelope version; absent means v1.
	SchemaVersion int `json:"schema_version,omitempty"`
}
