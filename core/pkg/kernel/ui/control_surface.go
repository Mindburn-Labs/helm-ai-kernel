// Package ui — Control surface primitives for OSS.
//
// Per HELM 2030 Spec §5.9 / §6.1.15:
//
//	HELM OSS MUST include operator-console primitives that render
//	from canonical truth and issue signed intents, not bypasses.
//	All 13 control surfaces are specified; this package provides
//	the type contracts for their data models.
//
// Resolves: GAP-A21.
package ui

import "time"

// ── Control Surface Registry ─────────────────────────────────────

// SurfaceType enumerates all spec-required control surfaces.
type SurfaceType string

const (
	SurfaceOrgCanvas         SurfaceType = "ORG_CANVAS"
	SurfaceLiveOrgGraph      SurfaceType = "LIVE_ORG_GRAPH"
	SurfaceExecutionTimeline SurfaceType = "EXECUTION_TIMELINE"
	SurfaceDecisionLineage   SurfaceType = "DECISION_LINEAGE"
	SurfacePolicyStudio      SurfaceType = "POLICY_STUDIO"
	SurfaceDelegationStudio  SurfaceType = "DELEGATION_STUDIO"
	SurfaceEvidenceBrowser   SurfaceType = "EVIDENCE_BROWSER"
	SurfaceReplayConsole     SurfaceType = "REPLAY_CONSOLE"
	SurfaceBrowserReview     SurfaceType = "BROWSER_REVIEW"
	SurfaceTreasuryConsole   SurfaceType = "TREASURY_CONSOLE"
	SurfaceSimCockpit        SurfaceType = "SIMULATION_COCKPIT"
	SurfaceIntervention      SurfaceType = "INTERVENTION_CONSOLE"
	SurfaceFacilityMap       SurfaceType = "FACILITY_MAP"
)

// SurfaceSpec describes a control surface and its data contract.
type SurfaceSpec struct {
	Surface      SurfaceType `json:"surface"`
	DisplayName  string      `json:"display_name"`
	Description  string      `json:"description"`
	DataSources  []string    `json:"data_sources"`  // canonical data paths
	RequiredAPIs []string    `json:"required_apis"`  // backend endpoints needed
	Intents      []string    `json:"intents"`        // governance intents this surface can issue
	OSS          bool        `json:"oss"`            // available in OSS
	Commercial   bool        `json:"commercial"`     // available in commercial
}

// AllSurfaces returns the full spec-required surface registry.
func AllSurfaces() []SurfaceSpec {
	return []SurfaceSpec{
		{SurfaceOrgCanvas, "Org Canvas", "Visual representation of organizational structure and authority graph", []string{"orggenome", "authority_graph"}, []string{"/api/org/graph"}, []string{"MODIFY_ORG"}, false, true},
		{SurfaceLiveOrgGraph, "Live Org Graph", "Real-time view of organizational state and active agents", []string{"orgphenotype", "agent_registry"}, []string{"/api/org/live"}, []string{}, true, true},
		{SurfaceExecutionTimeline, "Execution Timeline", "Chronological view of all governed execution events", []string{"proofgraph", "receipts"}, []string{"/api/timeline"}, []string{}, true, true},
		{SurfaceDecisionLineage, "Decision Lineage", "Causal chain from intent to outcome", []string{"proofgraph", "receipts"}, []string{"/api/lineage"}, []string{"REPLAY"}, true, true},
		{SurfacePolicyStudio, "Policy Studio", "Editor and simulator for governance policies", []string{"policies", "cel_rules"}, []string{"/api/policies"}, []string{"UPDATE_POLICY"}, false, true},
		{SurfaceDelegationStudio, "Delegation Studio", "Design and inspect delegation chains", []string{"delegation_graph", "envelopes"}, []string{"/api/delegations"}, []string{"DELEGATE"}, false, true},
		{SurfaceEvidenceBrowser, "Evidence Browser", "Browse and export EvidencePacks and receipts", []string{"evidencepack", "receipts"}, []string{"/api/evidence"}, []string{"EXPORT"}, true, true},
		{SurfaceReplayConsole, "Replay Console", "Replay disputed or audited execution sequences", []string{"replay_engine", "receipts"}, []string{"/api/replay"}, []string{"REPLAY"}, true, true},
		{SurfaceBrowserReview, "Browser Review", "Review browser execution transcripts and DOM receipts", []string{"browser_transcripts", "dom_receipts"}, []string{"/api/browser/review"}, []string{}, false, true},
		{SurfaceTreasuryConsole, "Treasury Console", "View and manage treasury, budgets, and spend authority", []string{"treasury", "budgets"}, []string{"/api/treasury"}, []string{"APPROVE_SPEND"}, false, true},
		{SurfaceSimCockpit, "Simulation Cockpit", "Design, run, and review simulations", []string{"org_twin", "scenarios"}, []string{"/api/simulation"}, []string{"RUN_SIM"}, true, true},
		{SurfaceIntervention, "Intervention Console", "Emergency controls and override panel", []string{"live_state", "alerts"}, []string{"/api/intervention"}, []string{"EMERGENCY_STOP", "OVERRIDE"}, false, true},
		{SurfaceFacilityMap, "Facility Map", "Physical facility and robot fleet visualization", []string{"facilities", "robots"}, []string{"/api/facilities"}, []string{"FACILITY_CONTROL"}, false, true},
	}
}

// ── Data Contracts for OSS Surfaces ──────────────────────────────

// LiveOrgGraphData is the data contract for the Live Org Graph surface.
type LiveOrgGraphData struct {
	OrgID       string           `json:"org_id"`
	Snapshot    time.Time        `json:"snapshot_at"`
	Nodes       []OrgGraphNode   `json:"nodes"`
	Edges       []OrgGraphEdge   `json:"edges"`
	ActiveAgents int             `json:"active_agents"`
	ActiveHumans int             `json:"active_humans"`
}

// OrgGraphNode is a node in the live org graph.
type OrgGraphNode struct {
	NodeID    string `json:"node_id"`
	Label     string `json:"label"`
	Type      string `json:"type"` // "TEAM", "ROLE", "AGENT", "HUMAN", "DEVICE"
	Status    string `json:"status"`
	ParentID  string `json:"parent_id,omitempty"`
}

// OrgGraphEdge is an edge in the live org graph.
type OrgGraphEdge struct {
	FromID   string `json:"from_id"`
	ToID     string `json:"to_id"`
	Relation string `json:"relation"` // "REPORTS_TO", "DELEGATES_TO", "OVERSEES"
}

// ExecutionTimelineData is the data contract for the Execution Timeline surface.
type ExecutionTimelineData struct {
	StartTime time.Time             `json:"start_time"`
	EndTime   time.Time             `json:"end_time"`
	Events    []ExecutionTimeEvent  `json:"events"`
	Total     int                   `json:"total"`
}

// ExecutionTimeEvent is a single event in the execution timeline.
type ExecutionTimeEvent struct {
	EventID    string    `json:"event_id"`
	Timestamp  time.Time `json:"timestamp"`
	Actor      string    `json:"actor"`
	Action     string    `json:"action"`
	Target     string    `json:"target,omitempty"`
	Verdict    string    `json:"verdict"` // "ALLOW", "DENY"
	ReceiptRef string    `json:"receipt_ref,omitempty"`
}

// EvidenceBrowserData is the data contract for the Evidence Browser surface.
type EvidenceBrowserData struct {
	Packs     []EvidencePackSummary `json:"packs"`
	Total     int                   `json:"total"`
}

// EvidencePackSummary is a summary of an evidence pack.
type EvidencePackSummary struct {
	PackID      string    `json:"pack_id"`
	CreatedAt   time.Time `json:"created_at"`
	ReceiptCount int      `json:"receipt_count"`
	ContentHash string    `json:"content_hash"`
	ExportReady bool      `json:"export_ready"`
}

// SimCockpitData is the data contract for the Simulation Cockpit surface.
type SimCockpitData struct {
	ActiveSims  []SimSummary `json:"active_simulations"`
	Scenarios   int          `json:"available_scenarios"`
	LastRunAt   *time.Time   `json:"last_run_at,omitempty"`
}

// SimSummary is a summary of a simulation run.
type SimSummary struct {
	SimID     string    `json:"sim_id"`
	Name      string    `json:"name"`
	Status    string    `json:"status"` // "RUNNING", "COMPLETED", "FAILED"
	StartedAt time.Time `json:"started_at"`
}
