package researchruntime

import "time"

type MissionMode string

const (
	MissionModeContinuousWatch MissionMode = "continuous_watch"
	MissionModeEditorial       MissionMode = "editorial_calendar"
	MissionModeOnDemand        MissionMode = "on_demand"
)

type MissionClass string

const (
	MissionClassDailyBrief      MissionClass = "daily_brief"
	MissionClassWeeklyPaper     MissionClass = "weekly_paper"
	MissionClassBenchmarkMemo   MissionClass = "benchmark_memo"
	MissionClassThreatWatch     MissionClass = "threat_watch_note"
	MissionClassStrategicMemo   MissionClass = "strategic_memo"
	MissionClassResearchPaper   MissionClass = "research_paper"
	MissionClassRevisionNotice  MissionClass = "revision_notice"
)

type MissionTriggerType string

const (
	MissionTriggerSchedule MissionTriggerType = "schedule"
	MissionTriggerWatch    MissionTriggerType = "watch"
	MissionTriggerManual   MissionTriggerType = "manual"
	MissionTriggerRevision MissionTriggerType = "revision"
	MissionTriggerPolicy   MissionTriggerType = "policy"
)

type WorkerRole string

const (
	WorkerPlanner         WorkerRole = "planner"
	WorkerWebScout        WorkerRole = "web-scout"
	WorkerSourceHarvester WorkerRole = "source-harvester"
	WorkerPaperScout      WorkerRole = "paper-scout"
	WorkerCoderAnalyst    WorkerRole = "coder-analyst"
	WorkerFactVerifier    WorkerRole = "fact-verifier"
	WorkerSynthesizer     WorkerRole = "synthesizer"
	WorkerCitationBuilder WorkerRole = "citation-builder"
	WorkerEditor          WorkerRole = "editor"
	WorkerPublisher       WorkerRole = "publisher"
)

type PublicationClass string

const (
	PublicationClassInternalNote  PublicationClass = "internal_note"
	PublicationClassInternalBrief PublicationClass = "internal_brief"
	PublicationClassExternalPost  PublicationClass = "external_post"
	PublicationClassExternalMemo  PublicationClass = "external_memo"
	PublicationClassExternalPaper PublicationClass = "external_paper"
	PublicationClassRevision      PublicationClass = "revision_notice"
)

type PublicationState string

const (
	PublicationStateDraft      PublicationState = "DRAFT"
	PublicationStateScored     PublicationState = "SCORED"
	PublicationStateHeld       PublicationState = "HELD"
	PublicationStateEligible   PublicationState = "ELIGIBLE"
	PublicationStatePromoted   PublicationState = "PROMOTED"
	PublicationStatePublished  PublicationState = "PUBLISHED"
	PublicationStateSuperseded PublicationState = "SUPERSEDED"
)

type ProvenanceStatus string

const (
	ProvenanceDiscovered ProvenanceStatus = "discovered"
	ProvenanceCaptured   ProvenanceStatus = "captured"
	ProvenanceVerified   ProvenanceStatus = "verified"
	ProvenanceDisputed   ProvenanceStatus = "disputed"
	ProvenanceDrifted    ProvenanceStatus = "drifted"
)

type MissionTrigger struct {
	Type          MissionTriggerType `json:"type"`
	Label         string             `json:"label,omitempty"`
	Schedule      string             `json:"schedule,omitempty"`
	SourceRef     string             `json:"source_ref,omitempty"`
	Reason        string             `json:"reason,omitempty"`
	TriggeredBy   string             `json:"triggered_by,omitempty"`
	TriggeredAt   time.Time          `json:"triggered_at"`
}

type MissionSpec struct {
	MissionID         string           `json:"mission_id"`
	Title             string           `json:"title"`
	Thesis            string           `json:"thesis"`
	Mode              MissionMode      `json:"mode"`
	Class             MissionClass     `json:"class"`
	PublicationClass  PublicationClass `json:"publication_class"`
	Topics            []string         `json:"topics,omitempty"`
	QuerySeeds        []string         `json:"query_seeds,omitempty"`
	NamedDomains      []string         `json:"named_domains,omitempty"`
	Keywords          []string         `json:"keywords,omitempty"`
	PrimaryModel      string           `json:"primary_model,omitempty"`
	VerificationModel string           `json:"verification_model,omitempty"`
	EditorModel       string           `json:"editor_model,omitempty"`
	MaxBudgetTokens   int              `json:"max_budget_tokens,omitempty"`
	MaxBudgetCents    int              `json:"max_budget_cents,omitempty"`
	Trigger           MissionTrigger   `json:"trigger"`
	CreatedAt         time.Time        `json:"created_at"`
}

type WorkNode struct {
	ID            string     `json:"id"`
	Role          WorkerRole `json:"role"`
	Title         string     `json:"title"`
	Purpose       string     `json:"purpose"`
	DependsOn     []string   `json:"depends_on,omitempty"`
	DeadlineSec   int        `json:"deadline_sec,omitempty"`
	RetryClass    string     `json:"retry_class,omitempty"`
	Required      bool       `json:"required"`
	PublishImpact string     `json:"publish_impact,omitempty"`
}

type WorkEdge struct {
	From string `json:"from"`
	To   string `json:"to"`
	Kind string `json:"kind"`
}

type WorkGraph struct {
	MissionID string     `json:"mission_id"`
	Version   string     `json:"version"`
	Nodes     []WorkNode `json:"nodes"`
	Edges     []WorkEdge `json:"edges"`
}

type TaskLease struct {
	LeaseID      string     `json:"lease_id"`
	MissionID    string     `json:"mission_id"`
	NodeID       string     `json:"node_id"`
	Role         WorkerRole `json:"role"`
	Assignee     string     `json:"assignee"`
	LeaseClass   string     `json:"lease_class,omitempty"`
	DeadlineAt   time.Time  `json:"deadline_at"`
	RetryCount   int        `json:"retry_count"`
	EscalationAt *time.Time `json:"escalation_at,omitempty"`
}

type CitationSpan struct {
	ClaimID      string `json:"claim_id"`
	SourceID     string `json:"source_id"`
	StartOffset  int    `json:"start_offset"`
	EndOffset    int    `json:"end_offset"`
	QuotedText   string `json:"quoted_text,omitempty"`
	SectionLabel string `json:"section_label,omitempty"`
}

type SourceSnapshot struct {
	SourceID         string           `json:"source_id"`
	MissionID        string           `json:"mission_id"`
	URL              string           `json:"url"`
	CanonicalURL     string           `json:"canonical_url,omitempty"`
	Title            string           `json:"title,omitempty"`
	ContentHash      string           `json:"content_hash"`
	SnapshotHash     string           `json:"snapshot_hash,omitempty"`
	DOMManifestHash  string           `json:"dom_manifest_hash,omitempty"`
	PDFManifestHash  string           `json:"pdf_manifest_hash,omitempty"`
	CapturedAt       time.Time        `json:"captured_at"`
	PublishedAt      *time.Time       `json:"published_at,omitempty"`
	Language         string           `json:"language,omitempty"`
	Provider         string           `json:"provider,omitempty"`
	FreshnessScore   float64          `json:"freshness_score,omitempty"`
	Primary          bool             `json:"primary"`
	Metadata         map[string]any   `json:"metadata,omitempty"`
	ProvenanceStatus ProvenanceStatus `json:"provenance_status"`
}

type ClaimBinding struct {
	ClaimID         string         `json:"claim_id"`
	MissionID       string         `json:"mission_id"`
	ClaimText       string         `json:"claim_text"`
	Spans           []CitationSpan `json:"spans"`
	Confidence      float64        `json:"confidence"`
	ContradictedBy  []string       `json:"contradicted_by,omitempty"`
	VerifierVerdict string         `json:"verifier_verdict,omitempty"`
}

type ContradictionSet struct {
	SetID          string   `json:"set_id"`
	MissionID      string   `json:"mission_id"`
	ClaimIDs       []string `json:"claim_ids"`
	SourceIDs      []string `json:"source_ids"`
	Summary        string   `json:"summary"`
	Resolution     string   `json:"resolution,omitempty"`
	Severity       string   `json:"severity,omitempty"`
	Unresolved     bool     `json:"unresolved"`
	DetectedAtUnix int64    `json:"detected_at_unix"`
}

type ModelManifest struct {
	Stage             string         `json:"stage"`
	RequestedProvider string         `json:"requested_provider,omitempty"`
	RequestedModel    string         `json:"requested_model"`
	ActualProvider    string         `json:"actual_provider,omitempty"`
	ActualModel       string         `json:"actual_model"`
	FallbackUsed      bool           `json:"fallback_used"`
	FallbackReason    string         `json:"fallback_reason,omitempty"`
	PolicyOutcome     string         `json:"policy_outcome,omitempty"`
	Parameters        map[string]any `json:"parameters,omitempty"`
	InvokedAt         time.Time      `json:"invoked_at"`
}

type ToolInvocationManifest struct {
	InvocationID string         `json:"invocation_id"`
	Stage        string         `json:"stage"`
	ToolName     string         `json:"tool_name"`
	Provider     string         `json:"provider,omitempty"`
	InputHash    string         `json:"input_hash"`
	OutputHash   string         `json:"output_hash"`
	Outcome      string         `json:"outcome"`
	Metadata     map[string]any `json:"metadata,omitempty"`
	InvokedAt    time.Time      `json:"invoked_at"`
}

type DraftManifest struct {
	DraftID        string         `json:"draft_id"`
	MissionID      string         `json:"mission_id"`
	Title          string         `json:"title"`
	Version        int            `json:"version"`
	SectionCount   int            `json:"section_count"`
	ClaimCount     int            `json:"claim_count"`
	CitationCount  int            `json:"citation_count"`
	WordCount      int            `json:"word_count"`
	ArtifactHashes map[string]any `json:"artifact_hashes,omitempty"`
	CreatedAt      time.Time      `json:"created_at"`
}

type ScoreRecord struct {
	Stage      string         `json:"stage"`
	Score      float64        `json:"score"`
	Threshold  float64        `json:"threshold"`
	Passed     bool           `json:"passed"`
	Notes      []string       `json:"notes,omitempty"`
	Breakdown  map[string]any `json:"breakdown,omitempty"`
	RecordedAt time.Time      `json:"recorded_at"`
}

type TracePack struct {
	Mission    MissionSpec                `json:"mission"`
	WorkGraph  WorkGraph                  `json:"work_graph"`
	Sources    []SourceSnapshot           `json:"sources,omitempty"`
	Claims     []ClaimBinding             `json:"claims,omitempty"`
	ModelRuns  []ModelManifest            `json:"model_runs,omitempty"`
	ToolRuns   []ToolInvocationManifest   `json:"tool_runs,omitempty"`
	Drafts     []DraftManifest            `json:"drafts,omitempty"`
	Scores     []ScoreRecord              `json:"scores,omitempty"`
	Conflicts  []ContradictionSet         `json:"conflicts,omitempty"`
	Metadata   map[string]any             `json:"metadata,omitempty"`
}

type ResearchEvidencePack struct {
	PackID           string         `json:"pack_id"`
	MissionID        string         `json:"mission_id"`
	TraceHash        string         `json:"trace_hash"`
	SourceManifest   []SourceSnapshot `json:"source_manifest,omitempty"`
	ModelManifest    []ModelManifest  `json:"model_manifest,omitempty"`
	ToolManifest     []ToolInvocationManifest `json:"tool_manifest,omitempty"`
	DraftManifest    []DraftManifest `json:"draft_manifest,omitempty"`
	ScoreManifest    []ScoreRecord   `json:"score_manifest,omitempty"`
	Contradictions   []ContradictionSet `json:"contradictions,omitempty"`
	ArtifactManifest map[string]any  `json:"artifact_manifest,omitempty"`
	SealedAt         time.Time       `json:"sealed_at"`
}

type PromotionReceipt struct {
	ReceiptID         string           `json:"receipt_id"`
	MissionID         string           `json:"mission_id"`
	PublicationID     string           `json:"publication_id"`
	PublicationState  PublicationState `json:"publication_state"`
	EvidencePackHash  string           `json:"evidence_pack_hash"`
	RequestedModel    string           `json:"requested_model,omitempty"`
	ActualModel       string           `json:"actual_model,omitempty"`
	FallbackUsed      bool             `json:"fallback_used"`
	PolicyDecision    string           `json:"policy_decision"`
	ReasonCodes       []string         `json:"reason_codes,omitempty"`
	Signer            string           `json:"signer,omitempty"`
	ManifestHash      string           `json:"manifest_hash"`
	CreatedAt         time.Time        `json:"created_at"`
}

type PublicationRecord struct {
	PublicationID    string           `json:"publication_id"`
	MissionID        string           `json:"mission_id"`
	Class            PublicationClass `json:"class"`
	State            PublicationState `json:"state"`
	Title            string           `json:"title"`
	Slug             string           `json:"slug,omitempty"`
	Thesis           string           `json:"thesis,omitempty"`
	Abstract         string           `json:"abstract,omitempty"`
	BodyHash         string           `json:"body_hash,omitempty"`
	EvidencePackHash string           `json:"evidence_pack_hash,omitempty"`
	PromotionReceipt string           `json:"promotion_receipt,omitempty"`
	Version          int              `json:"version"`
	Supersedes       string           `json:"supersedes,omitempty"`
	SupersededBy     string           `json:"superseded_by,omitempty"`
	PublishedAt      *time.Time       `json:"published_at,omitempty"`
	Metadata         map[string]any   `json:"metadata,omitempty"`
}
