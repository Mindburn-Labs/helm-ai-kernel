package boundary

// quantum_posture: classical Ed25519/SHA-256 only; no post-quantum assurance
// is claimed or provided by this file.

import (
	"context"
	"database/sql"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	mcppkg "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/mcp"
)

// SurfaceRegistry is the OSS-local durable-surface model used by CLI/API/Console
// wiring. Production runtimes can hydrate it from SQLite; tests and local dev
// can use the in-memory instance without creating a second policy authority.
type SurfaceRegistry struct {
	mu sync.RWMutex

	now  func() time.Time
	path string
	db   *sql.DB
	ctx  context.Context

	// assertionVerifier is nil until runtime wiring registers a credential
	// verifier; while nil, AssertApprovalChallenge fails closed with
	// ErrApprovalVerificationUnavailable.
	assertionVerifier ApprovalAssertionVerifier

	records            map[string]contracts.ExecutionBoundaryRecord
	checkpoints        map[string]contracts.BoundaryCheckpoint
	approvals          map[string]contracts.ApprovalCeremony
	challenges         map[string]contracts.ApprovalWebAuthnChallenge
	authProfiles       map[string]contracts.MCPAuthorizationProfile
	mcpServers         map[string]mcppkg.ServerQuarantineRecord
	sandboxGrants      map[string]contracts.SandboxGrant
	authzSnapshots     map[string]contracts.AuthzSnapshot
	envelopes          map[string]contracts.EvidenceEnvelopeManifest
	envelopePayloads   map[string]contracts.EvidenceEnvelopePayload
	verificationScopes map[string]contracts.VerificationScope
	harnessTraces      map[string]contracts.HarnessTrace
	planTransactions   map[string]contracts.PlanTransaction
	harnessChanges     map[string]contracts.HarnessChangeContract
	groundedActions    map[string]contracts.GroundedActionRef
	guiReceipts        map[string]contracts.GUIActionReceipt
	budgets            map[string]contracts.BudgetCeiling
	agents             map[string]contracts.AgentIdentityProfile
	reports            map[string]map[string]any
}

func NewSurfaceRegistry(now func() time.Time) *SurfaceRegistry {
	r := newSurfaceRegistry(now)
	r.seed()
	return r
}

func newSurfaceRegistry(now func() time.Time) *SurfaceRegistry {
	if now == nil {
		now = time.Now
	}
	return &SurfaceRegistry{
		now:                now,
		records:            map[string]contracts.ExecutionBoundaryRecord{},
		checkpoints:        map[string]contracts.BoundaryCheckpoint{},
		approvals:          map[string]contracts.ApprovalCeremony{},
		challenges:         map[string]contracts.ApprovalWebAuthnChallenge{},
		authProfiles:       map[string]contracts.MCPAuthorizationProfile{},
		mcpServers:         map[string]mcppkg.ServerQuarantineRecord{},
		sandboxGrants:      map[string]contracts.SandboxGrant{},
		authzSnapshots:     map[string]contracts.AuthzSnapshot{},
		envelopes:          map[string]contracts.EvidenceEnvelopeManifest{},
		envelopePayloads:   map[string]contracts.EvidenceEnvelopePayload{},
		verificationScopes: map[string]contracts.VerificationScope{},
		harnessTraces:      map[string]contracts.HarnessTrace{},
		planTransactions:   map[string]contracts.PlanTransaction{},
		harnessChanges:     map[string]contracts.HarnessChangeContract{},
		groundedActions:    map[string]contracts.GroundedActionRef{},
		guiReceipts:        map[string]contracts.GUIActionReceipt{},
		budgets:            map[string]contracts.BudgetCeiling{},
		agents:             map[string]contracts.AgentIdentityProfile{},
		reports:            map[string]map[string]any{},
	}
}

func (r *SurfaceRegistry) Status(version string, receiptStoreReady bool, signerReady bool, quarantined int) contracts.BoundaryStatus {
	r.mu.RLock()
	defer r.mu.RUnlock()
	status := "ready"
	receiptStore := "ready"
	receiptSigner := "ready"
	if !receiptStoreReady {
		status = "degraded"
		receiptStore = "unavailable"
	}
	if !signerReady {
		status = "degraded"
		receiptSigner = "unavailable"
	}
	lastCheckpoint := ""
	if checkpoints := r.sortedCheckpointsLocked(); len(checkpoints) > 0 {
		lastCheckpoint = checkpoints[len(checkpoints)-1].CheckpointHash
	}
	return contracts.BoundaryStatus{
		Status:              status,
		Mode:                "oss-local",
		Version:             version,
		ReceiptSigner:       receiptSigner,
		ReceiptStore:        receiptStore,
		PDP:                 "fail-closed",
		MCPFirewall:         "enabled",
		Sandbox:             "deny-default",
		Authz:               "rebac-snapshot",
		EvidenceVerifier:    "offline",
		CheckpointLog:       "tamper-evident",
		LastCheckpointHash:  lastCheckpoint,
		OpenApprovalCount:   r.countOpenApprovalsLocked(),
		QuarantinedMCPCount: quarantined,
		UpdatedAt:           r.now().UTC(),
		Components: map[string]string{
			"mcp":         "quarantine+oauth+schema-pin",
			"sandbox":     "preflight+grant-hash",
			"evidence":    "native-authority",
			"telemetry":   "non-authoritative",
			"coexistence": "export-only",
		},
	}
}

func (r *SurfaceRegistry) Capabilities() []contracts.BoundaryCapabilitySummary {
	return []contracts.BoundaryCapabilitySummary{
		{CapabilityID: "boundary-records", Category: "execution-boundary", Status: "implemented", Authority: "native-receipt", PublicRoutes: []string{"/api/v1/boundary/records", "/api/v1/boundary/checkpoints"}, CLICommands: []string{"helm-ai-kernel boundary records", "helm-ai-kernel boundary checkpoint"}, ReceiptBindings: []string{"record_hash", "receipt_id"}, ConformanceLevel: "L1"},
		{CapabilityID: "mcp-firewall", Category: "mcp", Status: "implemented", Authority: "pre-dispatch-pep", PublicRoutes: []string{"/api/v1/mcp/registry", "/api/v1/mcp/authorize-call", "/.well-known/oauth-protected-resource/mcp"}, CLICommands: []string{"helm-ai-kernel mcp scan", "helm-ai-kernel mcp authorize-call"}, ReceiptBindings: []string{"mcp_server_id", "oauth_scopes", "record_hash"}, ConformanceLevel: "L2"},
		{CapabilityID: "sandbox-grants", Category: "sandbox", Status: "implemented", Authority: "native-grant", PublicRoutes: []string{"/api/v1/sandbox/grants", "/api/v1/sandbox/preflight"}, CLICommands: []string{"helm-ai-kernel sandbox grant", "helm-ai-kernel sandbox preflight"}, ReceiptBindings: []string{"sandbox_grant_hash"}, ConformanceLevel: "L3"},
		{CapabilityID: "authz-snapshots", Category: "identity-authz", Status: "implemented", Authority: "pdp-snapshot", PublicRoutes: []string{"/api/v1/authz/check", "/api/v1/authz/snapshots"}, CLICommands: []string{"helm-ai-kernel authz check", "helm-ai-kernel authz snapshots"}, ReceiptBindings: []string{"authz_snapshot_hash"}, ConformanceLevel: "L3"},
		{CapabilityID: "evidence-envelopes", Category: "evidence", Status: "implemented", Authority: "native-evidencepack", PublicRoutes: []string{"/api/v1/evidence/envelopes"}, CLICommands: []string{"helm-ai-kernel evidence envelope"}, ReceiptBindings: []string{"evidence_manifest_hash"}, ConformanceLevel: "L4"},
		{CapabilityID: "telemetry-coexistence", Category: "telemetry", Status: "non-authoritative", Authority: "export-only", PublicRoutes: []string{"/api/v1/telemetry/otel/config", "/api/v1/coexistence/capabilities"}, CLICommands: []string{"helm-ai-kernel telemetry otel-config", "helm-ai-kernel coexistence manifest"}, ReceiptBindings: []string{"receipt_id", "record_hash"}, ConformanceLevel: "L4"},
	}
}

func (r *SurfaceRegistry) PutRecord(record contracts.ExecutionBoundaryRecord) (contracts.ExecutionBoundaryRecord, error) {
	sealed, err := record.Seal()
	if err != nil {
		return contracts.ExecutionBoundaryRecord{}, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.records[sealed.RecordID] = sealed
	if err := r.persistRecordIndexLocked(sealed); err != nil {
		return contracts.ExecutionBoundaryRecord{}, err
	}
	if err := r.appendEventLocked("record", sealed.RecordID, sealed); err != nil {
		return contracts.ExecutionBoundaryRecord{}, err
	}
	if err := r.persistLocked(); err != nil {
		return contracts.ExecutionBoundaryRecord{}, err
	}
	return sealed, nil
}

func (r *SurfaceRegistry) ListRecords(query contracts.BoundarySearchRequest) []contracts.ExecutionBoundaryRecord {
	r.mu.RLock()
	defer r.mu.RUnlock()
	records := make([]contracts.ExecutionBoundaryRecord, 0, len(r.records))
	for _, record := range r.records {
		if !matchesRecord(query, record) {
			continue
		}
		records = append(records, record)
	}
	sort.Slice(records, func(i, j int) bool {
		return records[i].CreatedAt.Before(records[j].CreatedAt)
	})
	limit := contracts.NormalizeSurfaceLimit(query.Limit)
	if len(records) > limit {
		records = records[:limit]
	}
	return records
}

func (r *SurfaceRegistry) GetRecord(id string) (contracts.ExecutionBoundaryRecord, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	record, ok := r.records[id]
	return record, ok
}

func (r *SurfaceRegistry) VerifyRecord(id string) contracts.BoundaryRecordVerification {
	r.mu.RLock()
	record, ok := r.records[id]
	lastCheckpoint := ""
	inclusionProof := []string{}
	if checkpoints := r.sortedCheckpointsLocked(); len(checkpoints) > 0 {
		last := checkpoints[len(checkpoints)-1]
		lastCheckpoint = last.CheckpointHash
		if containsString(last.RecordHashes, record.RecordHash) {
			inclusionProof = append([]string(nil), last.RecordHashes...)
		}
	}
	r.mu.RUnlock()
	now := r.now().UTC()
	if !ok {
		return contracts.BoundaryRecordVerification{
			RecordID:   id,
			Verdict:    "FAIL",
			Verified:   false,
			Offline:    true,
			Checks:     map[string]string{"record": "FAIL"},
			Errors:     []string{"boundary record not found"},
			VerifiedAt: now,
		}
	}
	expected := record.RecordHash
	record.RecordHash = ""
	hash, err := canonicalize.CanonicalHash(record)
	checks := map[string]string{"jcs": "PASS", "record_hash": "PASS", "receipt_binding": "PASS"}
	var errs []string
	if err != nil || "sha256:"+hash != expected {
		checks["record_hash"] = "FAIL"
		errs = append(errs, "record hash mismatch")
	}
	if strings.TrimSpace(record.ReceiptID) == "" {
		checks["receipt_binding"] = "WARN"
	}
	return contracts.BoundaryRecordVerification{
		RecordID:       id,
		Verdict:        passFail(len(errs) == 0),
		RecordHash:     expected,
		ReceiptID:      record.ReceiptID,
		Verified:       len(errs) == 0,
		Offline:        true,
		Checks:         checks,
		Errors:         errs,
		VerifiedAt:     now,
		CheckpointHash: lastCheckpoint,
		InclusionProof: inclusionProof,
	}
}

func (r *SurfaceRegistry) CreateCheckpoint(receiptCount int) (contracts.BoundaryCheckpoint, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	records := make([]contracts.ExecutionBoundaryRecord, 0, len(r.records))
	for _, record := range r.records {
		records = append(records, record)
	}
	sort.Slice(records, func(i, j int) bool {
		if records[i].CreatedAt.Equal(records[j].CreatedAt) {
			return records[i].RecordID < records[j].RecordID
		}
		return records[i].CreatedAt.Before(records[j].CreatedAt)
	})
	recordHashes := make([]string, 0, len(records))
	for _, record := range records {
		recordHashes = append(recordHashes, record.RecordHash)
	}
	recordRoot, err := canonicalize.CanonicalHash(recordHashes)
	if err != nil {
		return contracts.BoundaryCheckpoint{}, err
	}
	receiptRoot, err := canonicalize.CanonicalHash(struct {
		ReceiptCount int      `json:"receipt_count"`
		RecordHashes []string `json:"record_hashes"`
	}{ReceiptCount: receiptCount, RecordHashes: recordHashes})
	if err != nil {
		return contracts.BoundaryCheckpoint{}, err
	}
	previousHash := ""
	if checkpoints := r.sortedCheckpointsLocked(); len(checkpoints) > 0 {
		previousHash = checkpoints[len(checkpoints)-1].CheckpointHash
	}
	sequence := int64(len(r.checkpoints) + 1)
	checkpoint := contracts.BoundaryCheckpoint{
		CheckpointID:    fmt.Sprintf("boundary-checkpoint-%06d", sequence),
		Sequence:        sequence,
		RecordCount:     len(r.records),
		ReceiptCount:    receiptCount,
		RecordRootHash:  "sha256:" + recordRoot,
		ReceiptRootHash: "sha256:" + receiptRoot,
		PreviousHash:    previousHash,
		RecordHashes:    recordHashes,
		CreatedAt:       r.now().UTC(),
	}
	sealed, err := checkpoint.Seal()
	if err != nil {
		return contracts.BoundaryCheckpoint{}, err
	}
	r.checkpoints[sealed.CheckpointID] = sealed
	if err := r.appendEventLocked("checkpoint", sealed.CheckpointID, sealed); err != nil {
		return contracts.BoundaryCheckpoint{}, err
	}
	if err := r.persistLocked(); err != nil {
		return contracts.BoundaryCheckpoint{}, err
	}
	return sealed, nil
}

func (r *SurfaceRegistry) ListCheckpoints() []contracts.BoundaryCheckpoint {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.sortedCheckpointsLocked()
}

func (r *SurfaceRegistry) PutAuthProfile(profile contracts.MCPAuthorizationProfile) (contracts.MCPAuthorizationProfile, error) {
	sealed, err := profile.Seal()
	if err != nil {
		return contracts.MCPAuthorizationProfile{}, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.authProfiles[sealed.ProfileID] = sealed
	if err := r.appendEventLocked("mcp_auth_profile", sealed.ProfileID, sealed); err != nil {
		return contracts.MCPAuthorizationProfile{}, err
	}
	if err := r.persistLocked(); err != nil {
		return contracts.MCPAuthorizationProfile{}, err
	}
	return sealed, nil
}

func (r *SurfaceRegistry) ListAuthProfiles() []contracts.MCPAuthorizationProfile {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]contracts.MCPAuthorizationProfile, 0, len(r.authProfiles))
	for _, profile := range r.authProfiles {
		out = append(out, profile)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ProfileID < out[j].ProfileID })
	return out
}

func (r *SurfaceRegistry) PutMCPServer(record mcppkg.ServerQuarantineRecord) (mcppkg.ServerQuarantineRecord, error) {
	if strings.TrimSpace(record.ServerID) == "" {
		return mcppkg.ServerQuarantineRecord{}, fmt.Errorf("mcp server id is required")
	}
	record = mcppkg.FailClosedUnverifiedApproval(record)
	r.mu.Lock()
	defer r.mu.Unlock()
	r.mcpServers[record.ServerID] = record
	if err := r.appendEventLocked("mcp_server", record.ServerID, record); err != nil {
		return mcppkg.ServerQuarantineRecord{}, err
	}
	if err := r.persistLocked(); err != nil {
		return mcppkg.ServerQuarantineRecord{}, err
	}
	return record, nil
}

func (r *SurfaceRegistry) ListMCPServers() []mcppkg.ServerQuarantineRecord {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]mcppkg.ServerQuarantineRecord, 0, len(r.mcpServers))
	for _, record := range r.mcpServers {
		out = append(out, record)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ServerID < out[j].ServerID })
	return out
}

func (r *SurfaceRegistry) GetMCPServer(id string) (mcppkg.ServerQuarantineRecord, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	record, ok := r.mcpServers[id]
	return record, ok
}

func (r *SurfaceRegistry) PutSandboxGrant(grant contracts.SandboxGrant) (contracts.SandboxGrant, error) {
	sealed, err := grant.Seal()
	if err != nil {
		return contracts.SandboxGrant{}, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sandboxGrants[sealed.GrantID] = sealed
	if err := r.appendEventLocked("sandbox_grant", sealed.GrantID, sealed); err != nil {
		return contracts.SandboxGrant{}, err
	}
	if err := r.persistLocked(); err != nil {
		return contracts.SandboxGrant{}, err
	}
	return sealed, nil
}

func (r *SurfaceRegistry) ListSandboxGrants() []contracts.SandboxGrant {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]contracts.SandboxGrant, 0, len(r.sandboxGrants))
	for _, grant := range r.sandboxGrants {
		out = append(out, grant)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].GrantID < out[j].GrantID })
	return out
}

func (r *SurfaceRegistry) GetSandboxGrant(id string) (contracts.SandboxGrant, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	grant, ok := r.sandboxGrants[id]
	return grant, ok
}

func (r *SurfaceRegistry) PutSnapshot(snapshot contracts.AuthzSnapshot) (contracts.AuthzSnapshot, error) {
	sealed, err := snapshot.Seal()
	if err != nil {
		return contracts.AuthzSnapshot{}, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.authzSnapshots[sealed.SnapshotID] = sealed
	if err := r.appendEventLocked("authz_snapshot", sealed.SnapshotID, sealed); err != nil {
		return contracts.AuthzSnapshot{}, err
	}
	if err := r.persistLocked(); err != nil {
		return contracts.AuthzSnapshot{}, err
	}
	return sealed, nil
}

func (r *SurfaceRegistry) ListSnapshots() []contracts.AuthzSnapshot {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]contracts.AuthzSnapshot, 0, len(r.authzSnapshots))
	for _, snapshot := range r.authzSnapshots {
		out = append(out, snapshot)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].SnapshotID < out[j].SnapshotID })
	return out
}

func (r *SurfaceRegistry) GetSnapshot(id string) (contracts.AuthzSnapshot, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	snapshot, ok := r.authzSnapshots[id]
	return snapshot, ok
}

func (r *SurfaceRegistry) ListAgents() []contracts.AgentIdentityProfile {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]contracts.AgentIdentityProfile, 0, len(r.agents))
	for _, agent := range r.agents {
		out = append(out, agent)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].AgentID < out[j].AgentID })
	return out
}

func (r *SurfaceRegistry) ListBudgets() []contracts.BudgetCeiling {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]contracts.BudgetCeiling, 0, len(r.budgets))
	for _, budget := range r.budgets {
		out = append(out, budget)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].BudgetID < out[j].BudgetID })
	return out
}

func (r *SurfaceRegistry) PutBudget(budget contracts.BudgetCeiling) (contracts.BudgetCeiling, error) {
	if budget.UpdatedAt.IsZero() {
		budget.UpdatedAt = r.now().UTC()
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.budgets[budget.BudgetID] = budget
	if err := r.appendEventLocked("budget", budget.BudgetID, budget); err != nil {
		return contracts.BudgetCeiling{}, err
	}
	if err := r.persistLocked(); err != nil {
		return contracts.BudgetCeiling{}, err
	}
	return budget, nil
}

func (r *SurfaceRegistry) PutReport(report map[string]any) error {
	id, _ := report["report_id"].(string)
	if id == "" {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.reports[id] = report
	if err := r.appendEventLocked("conformance_report", id, report); err != nil {
		return err
	}
	return r.persistLocked()
}

func (r *SurfaceRegistry) ListReports() []map[string]any {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]map[string]any, 0, len(r.reports))
	for _, report := range r.reports {
		out = append(out, report)
	}
	sort.Slice(out, func(i, j int) bool {
		left, _ := out[i]["report_id"].(string)
		right, _ := out[j]["report_id"].(string)
		return left < right
	})
	return out
}

func (r *SurfaceRegistry) ensureMaps() {
	if r.records == nil {
		r.records = map[string]contracts.ExecutionBoundaryRecord{}
	}
	if r.checkpoints == nil {
		r.checkpoints = map[string]contracts.BoundaryCheckpoint{}
	}
	if r.approvals == nil {
		r.approvals = map[string]contracts.ApprovalCeremony{}
	}
	if r.challenges == nil {
		r.challenges = map[string]contracts.ApprovalWebAuthnChallenge{}
	}
	if r.authProfiles == nil {
		r.authProfiles = map[string]contracts.MCPAuthorizationProfile{}
	}
	if r.mcpServers == nil {
		r.mcpServers = map[string]mcppkg.ServerQuarantineRecord{}
	}
	if r.sandboxGrants == nil {
		r.sandboxGrants = map[string]contracts.SandboxGrant{}
	}
	if r.authzSnapshots == nil {
		r.authzSnapshots = map[string]contracts.AuthzSnapshot{}
	}
	if r.envelopes == nil {
		r.envelopes = map[string]contracts.EvidenceEnvelopeManifest{}
	}
	if r.envelopePayloads == nil {
		r.envelopePayloads = map[string]contracts.EvidenceEnvelopePayload{}
	}
	if r.verificationScopes == nil {
		r.verificationScopes = map[string]contracts.VerificationScope{}
	}
	if r.harnessTraces == nil {
		r.harnessTraces = map[string]contracts.HarnessTrace{}
	}
	if r.planTransactions == nil {
		r.planTransactions = map[string]contracts.PlanTransaction{}
	}
	if r.harnessChanges == nil {
		r.harnessChanges = map[string]contracts.HarnessChangeContract{}
	}
	if r.groundedActions == nil {
		r.groundedActions = map[string]contracts.GroundedActionRef{}
	}
	if r.guiReceipts == nil {
		r.guiReceipts = map[string]contracts.GUIActionReceipt{}
	}
	if r.budgets == nil {
		r.budgets = map[string]contracts.BudgetCeiling{}
	}
	if r.agents == nil {
		r.agents = map[string]contracts.AgentIdentityProfile{}
	}
	if r.reports == nil {
		r.reports = map[string]map[string]any{}
	}
}

func (r *SurfaceRegistry) seed() {
	now := r.now().UTC()
	record, _ := contracts.ExecutionBoundaryRecord{
		RecordID:    "boundary-record-bootstrap",
		Verdict:     contracts.VerdictDeny,
		ReasonCode:  contracts.ReasonApprovalRequired,
		ToolName:    "mcp.unknown",
		ArgsHash:    "sha256:bootstrap",
		PolicyEpoch: "bootstrap",
		MCPServerID: "mcp-unapproved",
		CreatedAt:   now,
	}.Seal()
	r.records[record.RecordID] = record

	profile, _ := contracts.MCPAuthorizationProfile{
		ProfileID:            "mcp-default",
		Resource:             "https://helm.local/mcp",
		AuthorizationServers: []string{"https://helm.local/oauth"},
		ScopesSupported:      []string{"tools.read", "tools.call", "evidence.read"},
		RequiredScopes:       []string{"tools.read"},
		ProtocolVersions:     []string{"2025-11-25", "2025-06-18", "2025-03-26"},
	}.Seal()
	r.authProfiles[profile.ProfileID] = profile

	approval, _ := contracts.ApprovalCeremony{
		ApprovalID:       "approval-bootstrap",
		Subject:          "mcp:mcp-unapproved",
		Action:           "mcp.approve",
		State:            contracts.ApprovalCeremonyPending,
		RequestedBy:      "system",
		Quorum:           1,
		Reason:           "unknown MCP servers are quarantined until reviewed",
		BoundaryRecordID: record.RecordID,
		CreatedAt:        now,
		UpdatedAt:        now,
	}.Seal()
	r.approvals[approval.ApprovalID] = approval
	r.mcpServers["mcp-unapproved"] = mcppkg.ServerQuarantineRecord{
		ServerID:     "mcp-unapproved",
		Name:         "Unapproved MCP server",
		Risk:         mcppkg.ServerRiskHigh,
		State:        mcppkg.QuarantineQuarantined,
		DiscoveredAt: now,
		Reason:       "unknown MCP servers are quarantined until reviewed",
	}

	r.agents["agent-anonymous-dev"] = contracts.AgentIdentityProfile{
		AgentID:      "agent-anonymous-dev",
		DisplayName:  "Anonymous local dev agent",
		IdentityType: "anonymous-dev",
		AnonymousDev: true,
		LastVerified: now,
	}
	r.budgets["budget-default"] = contracts.BudgetCeiling{
		BudgetID:              "budget-default",
		Subject:               "tenant:default",
		ToolCallLimit:         1000,
		SpendLimitCents:       100000,
		EgressLimitBytes:      10 << 20,
		WriteOperationLimit:   100,
		ApprovalRequiredAbove: 50000,
		Window:                "24h",
		PolicyEpoch:           "bootstrap",
		UpdatedAt:             now,
	}
	_, _ = r.CreateCheckpoint(0)
}

func matchesRecord(query contracts.BoundarySearchRequest, record contracts.ExecutionBoundaryRecord) bool {
	if query.Verdict != "" && !strings.EqualFold(query.Verdict, string(record.Verdict)) {
		return false
	}
	if query.ReasonCode != "" && !strings.EqualFold(query.ReasonCode, string(record.ReasonCode)) {
		return false
	}
	if query.ToolName != "" && record.ToolName != query.ToolName {
		return false
	}
	if query.MCPServerID != "" && record.MCPServerID != query.MCPServerID {
		return false
	}
	if query.PolicyEpoch != "" && record.PolicyEpoch != query.PolicyEpoch {
		return false
	}
	if query.ReceiptID != "" && record.ReceiptID != query.ReceiptID {
		return false
	}
	return true
}

func (r *SurfaceRegistry) sortedCheckpointsLocked() []contracts.BoundaryCheckpoint {
	out := make([]contracts.BoundaryCheckpoint, 0, len(r.checkpoints))
	for _, checkpoint := range r.checkpoints {
		out = append(out, checkpoint)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Sequence < out[j].Sequence })
	return out
}

func appendUnique(values []string, value string) []string {
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
}

func containsString(values []string, value string) bool {
	for _, existing := range values {
		if existing == value {
			return true
		}
	}
	return false
}

func passFail(ok bool) string {
	if ok {
		return "PASS"
	}
	return "FAIL"
}
