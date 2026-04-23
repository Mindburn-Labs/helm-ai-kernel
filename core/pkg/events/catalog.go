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

// EventMeta is common metadata for all events.
type EventMeta struct {
	EventID     string `json:"event_id"`
	EventType   string `json:"event_type"`
	TenantID    string `json:"tenant_id"`
	TimestampMs int64  `json:"timestamp_ms"`
	SourceRef   string `json:"source_ref,omitempty"`
}
