package boundary

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/canonicalize"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/contracts"
	mcppkg "github.com/Mindburn-Labs/helm-oss/core/pkg/mcp"
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

	records          map[string]contracts.ExecutionBoundaryRecord
	checkpoints      map[string]contracts.BoundaryCheckpoint
	approvals        map[string]contracts.ApprovalCeremony
	challenges       map[string]contracts.ApprovalWebAuthnChallenge
	authProfiles     map[string]contracts.MCPAuthorizationProfile
	mcpServers       map[string]mcppkg.ServerQuarantineRecord
	sandboxGrants    map[string]contracts.SandboxGrant
	authzSnapshots   map[string]contracts.AuthzSnapshot
	envelopes        map[string]contracts.EvidenceEnvelopeManifest
	envelopePayloads map[string]contracts.EvidenceEnvelopePayload
	budgets          map[string]contracts.BudgetCeiling
	agents           map[string]contracts.AgentIdentityProfile
	reports          map[string]map[string]any
}

func NewSurfaceRegistry(now func() time.Time) *SurfaceRegistry {
	r := newSurfaceRegistry(now)
	r.seed()
	return r
}

// NewFileBackedSurfaceRegistry creates a registry that persists OSS boundary
// surface state to a local JSON snapshot after every mutation.
func NewFileBackedSurfaceRegistry(path string, now func() time.Time) (*SurfaceRegistry, error) {
	if strings.TrimSpace(path) == "" || strings.EqualFold(path, "memory") {
		return NewSurfaceRegistry(now), nil
	}
	r := newSurfaceRegistry(now)
	if data, err := os.ReadFile(path); err == nil {
		if len(strings.TrimSpace(string(data))) == 0 {
			r.seed()
		} else if err := r.loadSnapshot(data); err != nil {
			return nil, fmt.Errorf("load boundary registry %s: %w", path, err)
		}
	} else if os.IsNotExist(err) {
		r.seed()
	} else {
		return nil, fmt.Errorf("read boundary registry %s: %w", path, err)
	}
	r.path = path
	r.mu.Lock()
	err := r.persistLocked()
	r.mu.Unlock()
	if err != nil {
		return nil, err
	}
	return r, nil
}

// NewSQLSurfaceRegistry creates a durable registry backed by the same SQLite or
// Postgres database as the OSS runtime. It stores a versioned snapshot in one
// row so API, Console, and SDK surfaces share durable state without becoming a
// second policy authority.
func NewSQLSurfaceRegistry(ctx context.Context, db *sql.DB, now func() time.Time) (*SurfaceRegistry, error) {
	if db == nil {
		return NewSurfaceRegistry(now), nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if _, err := db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS boundary_surface_snapshots (
		id TEXT PRIMARY KEY,
		snapshot_json TEXT NOT NULL,
		updated_at TEXT NOT NULL
	)`); err != nil {
		return nil, fmt.Errorf("init boundary surface table: %w", err)
	}
	if _, err := db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS boundary_surface_events (
		sequence INTEGER PRIMARY KEY AUTOINCREMENT,
		event_kind TEXT NOT NULL,
		object_id TEXT NOT NULL,
		object_json TEXT NOT NULL,
		created_at TEXT NOT NULL
	)`); err != nil {
		return nil, fmt.Errorf("init boundary surface event table: %w", err)
	}
	if _, err := db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS boundary_records_index (
		record_id TEXT PRIMARY KEY,
		verdict TEXT NOT NULL,
		reason_code TEXT,
		tool_name TEXT,
		mcp_server_id TEXT,
		policy_epoch TEXT NOT NULL,
		receipt_id TEXT,
		record_hash TEXT NOT NULL,
		created_at TEXT NOT NULL
	)`); err != nil {
		return nil, fmt.Errorf("init boundary record index: %w", err)
	}
	r := newSurfaceRegistry(now)
	var snapshotJSON string
	err := db.QueryRowContext(ctx, `SELECT snapshot_json FROM boundary_surface_snapshots WHERE id = $1`, "default").Scan(&snapshotJSON)
	if err == nil {
		if err := r.loadSnapshot([]byte(snapshotJSON)); err != nil {
			return nil, fmt.Errorf("load boundary surface snapshot: %w", err)
		}
	} else if err == sql.ErrNoRows {
		r.seed()
	} else {
		return nil, fmt.Errorf("read boundary surface snapshot: %w", err)
	}
	r.db = db
	r.ctx = ctx
	r.mu.Lock()
	err = r.persistLocked()
	r.mu.Unlock()
	if err != nil {
		return nil, err
	}
	return r, nil
}

func newSurfaceRegistry(now func() time.Time) *SurfaceRegistry {
	if now == nil {
		now = time.Now
	}
	return &SurfaceRegistry{
		now:              now,
		records:          map[string]contracts.ExecutionBoundaryRecord{},
		checkpoints:      map[string]contracts.BoundaryCheckpoint{},
		approvals:        map[string]contracts.ApprovalCeremony{},
		challenges:       map[string]contracts.ApprovalWebAuthnChallenge{},
		authProfiles:     map[string]contracts.MCPAuthorizationProfile{},
		mcpServers:       map[string]mcppkg.ServerQuarantineRecord{},
		sandboxGrants:    map[string]contracts.SandboxGrant{},
		authzSnapshots:   map[string]contracts.AuthzSnapshot{},
		envelopes:        map[string]contracts.EvidenceEnvelopeManifest{},
		envelopePayloads: map[string]contracts.EvidenceEnvelopePayload{},
		budgets:          map[string]contracts.BudgetCeiling{},
		agents:           map[string]contracts.AgentIdentityProfile{},
		reports:          map[string]map[string]any{},
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
		{CapabilityID: "boundary-records", Category: "execution-boundary", Status: "implemented", Authority: "native-receipt", PublicRoutes: []string{"/api/v1/boundary/records", "/api/v1/boundary/checkpoints"}, CLICommands: []string{"helm boundary records", "helm boundary checkpoint"}, ReceiptBindings: []string{"record_hash", "receipt_id"}, ConformanceLevel: "L1"},
		{CapabilityID: "mcp-firewall", Category: "mcp", Status: "implemented", Authority: "pre-dispatch-pep", PublicRoutes: []string{"/api/v1/mcp/registry", "/api/v1/mcp/authorize-call", "/.well-known/oauth-protected-resource/mcp"}, CLICommands: []string{"helm mcp scan", "helm mcp authorize-call"}, ReceiptBindings: []string{"mcp_server_id", "oauth_scopes", "record_hash"}, ConformanceLevel: "L2"},
		{CapabilityID: "sandbox-grants", Category: "sandbox", Status: "implemented", Authority: "native-grant", PublicRoutes: []string{"/api/v1/sandbox/grants", "/api/v1/sandbox/preflight"}, CLICommands: []string{"helm sandbox grant", "helm sandbox preflight"}, ReceiptBindings: []string{"sandbox_grant_hash"}, ConformanceLevel: "L3"},
		{CapabilityID: "authz-snapshots", Category: "identity-authz", Status: "implemented", Authority: "pdp-snapshot", PublicRoutes: []string{"/api/v1/authz/check", "/api/v1/authz/snapshots"}, CLICommands: []string{"helm authz check", "helm authz snapshots"}, ReceiptBindings: []string{"authz_snapshot_hash"}, ConformanceLevel: "L3"},
		{CapabilityID: "evidence-envelopes", Category: "evidence", Status: "implemented", Authority: "native-evidencepack", PublicRoutes: []string{"/api/v1/evidence/envelopes"}, CLICommands: []string{"helm evidence envelope"}, ReceiptBindings: []string{"evidence_manifest_hash"}, ConformanceLevel: "L4"},
		{CapabilityID: "telemetry-coexistence", Category: "telemetry", Status: "non-authoritative", Authority: "export-only", PublicRoutes: []string{"/api/v1/telemetry/otel/config", "/api/v1/coexistence/capabilities"}, CLICommands: []string{"helm telemetry otel-config", "helm coexistence manifest"}, ReceiptBindings: []string{"receipt_id", "record_hash"}, ConformanceLevel: "L4"},
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

func (r *SurfaceRegistry) VerifyCheckpoint(id string) map[string]any {
	r.mu.RLock()
	checkpoint, ok := r.checkpoints[id]
	r.mu.RUnlock()
	if !ok {
		return map[string]any{
			"checkpoint_id": id,
			"verdict":       "FAIL",
			"verified":      false,
			"errors":        []string{"checkpoint not found"},
			"checks":        map[string]string{"checkpoint": "FAIL"},
			"verified_at":   r.now().UTC(),
		}
	}
	expected := checkpoint
	expected.CheckpointHash = ""
	hash, err := canonicalize.CanonicalHash(expected)
	checks := map[string]string{
		"checkpoint_hash": "PASS",
		"record_root":     "PASS",
		"inclusion_order": "PASS",
	}
	var errs []string
	if err != nil || "sha256:"+hash != checkpoint.CheckpointHash {
		checks["checkpoint_hash"] = "FAIL"
		errs = append(errs, "checkpoint hash mismatch")
	}
	root, err := canonicalize.CanonicalHash(checkpoint.RecordHashes)
	if err != nil || "sha256:"+root != checkpoint.RecordRootHash {
		checks["record_root"] = "FAIL"
		errs = append(errs, "record root mismatch")
	}
	if len(checkpoint.RecordHashes) != checkpoint.RecordCount {
		checks["inclusion_order"] = "FAIL"
		errs = append(errs, "record count does not match inclusion proof")
	}
	return map[string]any{
		"checkpoint_id":   checkpoint.CheckpointID,
		"checkpoint_hash": checkpoint.CheckpointHash,
		"verdict":         passFail(len(errs) == 0),
		"verified":        len(errs) == 0,
		"checks":          checks,
		"errors":          errs,
		"record_hashes":   checkpoint.RecordHashes,
		"verified_at":     r.now().UTC(),
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

func (r *SurfaceRegistry) PutApproval(approval contracts.ApprovalCeremony) (contracts.ApprovalCeremony, error) {
	sealed, err := approval.Seal()
	if err != nil {
		return contracts.ApprovalCeremony{}, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.approvals[sealed.ApprovalID] = sealed
	if err := r.appendEventLocked("approval", sealed.ApprovalID, sealed); err != nil {
		return contracts.ApprovalCeremony{}, err
	}
	if err := r.persistLocked(); err != nil {
		return contracts.ApprovalCeremony{}, err
	}
	return sealed, nil
}

func (r *SurfaceRegistry) ListApprovals() []contracts.ApprovalCeremony {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]contracts.ApprovalCeremony, 0, len(r.approvals))
	for _, approval := range r.approvals {
		out = append(out, approval)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ApprovalID < out[j].ApprovalID })
	return out
}

func (r *SurfaceRegistry) TransitionApproval(id string, state contracts.ApprovalCeremonyState, actor, receiptID, reason string) (contracts.ApprovalCeremony, error) {
	r.mu.RLock()
	approval, ok := r.approvals[id]
	r.mu.RUnlock()
	if !ok {
		return contracts.ApprovalCeremony{}, fmt.Errorf("approval %q not found", id)
	}
	now := r.now().UTC()
	if !approval.ExpiresAt.IsZero() && now.After(approval.ExpiresAt) && state == contracts.ApprovalCeremonyAllowed {
		approval.State = contracts.ApprovalCeremonyExpired
		approval.UpdatedAt = now
		approval.Reason = "approval expired before assertion"
		return r.PutApproval(approval)
	}
	if state == contracts.ApprovalCeremonyAllowed && !approval.TimelockUntil.IsZero() && now.Before(approval.TimelockUntil) {
		approval.UpdatedAt = now
		approval.Reason = "approval timelock has not elapsed"
		return r.PutApproval(approval)
	}
	if state == contracts.ApprovalCeremonyAllowed && approval.BreakGlass && (strings.TrimSpace(reason) == "" || strings.TrimSpace(receiptID) == "") {
		return contracts.ApprovalCeremony{}, fmt.Errorf("break-glass approval requires reason and receipt_id")
	}
	approval.State = state
	approval.UpdatedAt = now
	approval.Reason = reason
	if actor != "" {
		approval.Approvers = appendUnique(approval.Approvers, actor)
	}
	if receiptID != "" {
		approval.ReceiptID = receiptID
	}
	if state == contracts.ApprovalCeremonyAllowed {
		quorum := approval.Quorum
		if quorum <= 0 {
			quorum = 1
		}
		if len(approval.Approvers) < quorum {
			approval.State = contracts.ApprovalCeremonyPending
			approval.Reason = fmt.Sprintf("approval quorum pending: %d/%d", len(approval.Approvers), quorum)
		}
	}
	return r.PutApproval(approval)
}

func (r *SurfaceRegistry) CreateApprovalChallenge(approvalID, method string, ttl time.Duration) (contracts.ApprovalWebAuthnChallenge, error) {
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	if strings.TrimSpace(method) == "" {
		method = "passkey"
	}
	r.mu.RLock()
	_, ok := r.approvals[approvalID]
	r.mu.RUnlock()
	if !ok {
		return contracts.ApprovalWebAuthnChallenge{}, fmt.Errorf("approval %q not found", approvalID)
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return contracts.ApprovalWebAuthnChallenge{}, fmt.Errorf("generate approval challenge: %w", err)
	}
	challenge := base64.RawURLEncoding.EncodeToString(raw)
	hash, err := canonicalize.CanonicalHash(map[string]string{"approval_id": approvalID, "challenge": challenge, "method": method})
	if err != nil {
		return contracts.ApprovalWebAuthnChallenge{}, err
	}
	now := r.now().UTC()
	record := contracts.ApprovalWebAuthnChallenge{
		ChallengeID:   contracts.SurfaceID("challenge", approvalID+"-"+challenge[:12]),
		ApprovalID:    approvalID,
		Method:        method,
		Challenge:     challenge,
		ChallengeHash: "sha256:" + hash,
		CreatedAt:     now,
		ExpiresAt:     now.Add(ttl),
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.challenges[record.ChallengeID] = record
	if err := r.appendEventLocked("approval_challenge", record.ChallengeID, record); err != nil {
		return contracts.ApprovalWebAuthnChallenge{}, err
	}
	if err := r.persistLocked(); err != nil {
		return contracts.ApprovalWebAuthnChallenge{}, err
	}
	return record, nil
}

func (r *SurfaceRegistry) AssertApprovalChallenge(assertion contracts.ApprovalWebAuthnAssertion) (contracts.ApprovalCeremony, error) {
	if strings.TrimSpace(assertion.ChallengeID) == "" || strings.TrimSpace(assertion.Actor) == "" || strings.TrimSpace(assertion.Assertion) == "" {
		return contracts.ApprovalCeremony{}, fmt.Errorf("challenge_id, actor, and assertion are required")
	}
	r.mu.RLock()
	challenge, ok := r.challenges[assertion.ChallengeID]
	r.mu.RUnlock()
	if !ok {
		return contracts.ApprovalCeremony{}, fmt.Errorf("approval challenge %q not found", assertion.ChallengeID)
	}
	if r.now().UTC().After(challenge.ExpiresAt) {
		return contracts.ApprovalCeremony{}, fmt.Errorf("approval challenge expired")
	}
	assertionHash, err := canonicalize.CanonicalHash(map[string]string{
		"challenge_id": assertion.ChallengeID,
		"actor":        assertion.Actor,
		"assertion":    assertion.Assertion,
	})
	if err != nil {
		return contracts.ApprovalCeremony{}, err
	}
	approval, err := r.TransitionApproval(challenge.ApprovalID, contracts.ApprovalCeremonyAllowed, assertion.Actor, assertion.ReceiptID, assertion.Reason)
	if err != nil {
		return contracts.ApprovalCeremony{}, err
	}
	approval.AuthMethod = challenge.Method
	approval.ChallengeID = challenge.ChallengeID
	approval.ChallengeHash = challenge.ChallengeHash
	approval.AssertionHash = "sha256:" + assertionHash
	sealed, err := r.PutApproval(approval)
	if err != nil {
		return contracts.ApprovalCeremony{}, err
	}
	challenge.Verified = sealed.State == contracts.ApprovalCeremonyAllowed
	challenge.AssertionHash = sealed.AssertionHash
	r.mu.Lock()
	r.challenges[challenge.ChallengeID] = challenge
	err = r.persistLocked()
	r.mu.Unlock()
	if err != nil {
		return contracts.ApprovalCeremony{}, err
	}
	return sealed, nil
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

func (r *SurfaceRegistry) PutEnvelope(manifest contracts.EvidenceEnvelopeManifest) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.envelopes[manifest.ManifestID] = manifest
	if err := r.appendEventLocked("evidence_envelope", manifest.ManifestID, manifest); err != nil {
		return err
	}
	return r.persistLocked()
}

func (r *SurfaceRegistry) PutEnvelopePayload(payload contracts.EvidenceEnvelopePayload) error {
	if strings.TrimSpace(payload.ManifestID) == "" {
		return fmt.Errorf("envelope payload manifest id is required")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.envelopePayloads[payload.ManifestID] = payload
	if err := r.appendEventLocked("evidence_envelope_payload", payload.ManifestID, payload); err != nil {
		return err
	}
	return r.persistLocked()
}

func (r *SurfaceRegistry) ListEnvelopes() []contracts.EvidenceEnvelopeManifest {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]contracts.EvidenceEnvelopeManifest, 0, len(r.envelopes))
	for _, manifest := range r.envelopes {
		out = append(out, manifest)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ManifestID < out[j].ManifestID })
	return out
}

func (r *SurfaceRegistry) GetEnvelope(id string) (contracts.EvidenceEnvelopeManifest, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	manifest, ok := r.envelopes[id]
	return manifest, ok
}

func (r *SurfaceRegistry) GetEnvelopePayload(id string) (contracts.EvidenceEnvelopePayload, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	payload, ok := r.envelopePayloads[id]
	return payload, ok
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

type surfaceRegistrySnapshot struct {
	Version          int                                            `json:"version"`
	Records          map[string]contracts.ExecutionBoundaryRecord   `json:"records"`
	Checkpoints      map[string]contracts.BoundaryCheckpoint        `json:"checkpoints"`
	Approvals        map[string]contracts.ApprovalCeremony          `json:"approvals"`
	Challenges       map[string]contracts.ApprovalWebAuthnChallenge `json:"challenges"`
	AuthProfiles     map[string]contracts.MCPAuthorizationProfile   `json:"auth_profiles"`
	MCPServers       map[string]mcppkg.ServerQuarantineRecord       `json:"mcp_servers"`
	SandboxGrants    map[string]contracts.SandboxGrant              `json:"sandbox_grants"`
	AuthzSnapshots   map[string]contracts.AuthzSnapshot             `json:"authz_snapshots"`
	Envelopes        map[string]contracts.EvidenceEnvelopeManifest  `json:"envelopes"`
	EnvelopePayloads map[string]contracts.EvidenceEnvelopePayload   `json:"envelope_payloads"`
	Budgets          map[string]contracts.BudgetCeiling             `json:"budgets"`
	Agents           map[string]contracts.AgentIdentityProfile      `json:"agents"`
	Reports          map[string]map[string]any                      `json:"reports"`
}

func (r *SurfaceRegistry) loadSnapshot(data []byte) error {
	var snap surfaceRegistrySnapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		return err
	}
	r.records = snap.Records
	r.checkpoints = snap.Checkpoints
	r.approvals = snap.Approvals
	r.challenges = snap.Challenges
	r.authProfiles = snap.AuthProfiles
	r.mcpServers = snap.MCPServers
	r.sandboxGrants = snap.SandboxGrants
	r.authzSnapshots = snap.AuthzSnapshots
	r.envelopes = snap.Envelopes
	r.envelopePayloads = snap.EnvelopePayloads
	r.budgets = snap.Budgets
	r.agents = snap.Agents
	r.reports = snap.Reports
	r.ensureMaps()
	return nil
}

func (r *SurfaceRegistry) persistLocked() error {
	data, err := json.MarshalIndent(surfaceRegistrySnapshot{
		Version:          2,
		Records:          r.records,
		Checkpoints:      r.checkpoints,
		Approvals:        r.approvals,
		Challenges:       r.challenges,
		AuthProfiles:     r.authProfiles,
		MCPServers:       r.mcpServers,
		SandboxGrants:    r.sandboxGrants,
		AuthzSnapshots:   r.authzSnapshots,
		Envelopes:        r.envelopes,
		EnvelopePayloads: r.envelopePayloads,
		Budgets:          r.budgets,
		Agents:           r.agents,
		Reports:          r.reports,
	}, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal boundary registry: %w", err)
	}
	if r.db != nil {
		ctx := r.ctx
		if ctx == nil {
			ctx = context.Background()
		}
		_, err := r.db.ExecContext(ctx, `INSERT INTO boundary_surface_snapshots (id, snapshot_json, updated_at)
			VALUES ($1, $2, $3)
			ON CONFLICT(id) DO UPDATE SET snapshot_json = excluded.snapshot_json, updated_at = excluded.updated_at`,
			"default", string(data), r.now().UTC().Format(time.RFC3339Nano))
		if err != nil {
			return fmt.Errorf("persist boundary surface snapshot: %w", err)
		}
		return nil
	}
	if strings.TrimSpace(r.path) == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(r.path), 0o700); err != nil {
		return fmt.Errorf("create boundary registry directory: %w", err)
	}
	tmpPath := fmt.Sprintf("%s.tmp.%d", r.path, time.Now().UnixNano())
	if err := os.WriteFile(tmpPath, append(data, '\n'), 0o600); err != nil {
		return fmt.Errorf("write boundary registry snapshot: %w", err)
	}
	if err := os.Rename(tmpPath, r.path); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("commit boundary registry snapshot: %w", err)
	}
	return nil
}

func (r *SurfaceRegistry) appendEventLocked(kind, id string, value any) error {
	if r.db == nil {
		return nil
	}
	data, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("marshal boundary surface event: %w", err)
	}
	ctx := r.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	_, err = r.db.ExecContext(ctx, `INSERT INTO boundary_surface_events (event_kind, object_id, object_json, created_at)
		VALUES ($1, $2, $3, $4)`,
		kind, id, string(data), r.now().UTC().Format(time.RFC3339Nano))
	if err != nil {
		return fmt.Errorf("append boundary surface event: %w", err)
	}
	return nil
}

func (r *SurfaceRegistry) persistRecordIndexLocked(record contracts.ExecutionBoundaryRecord) error {
	if r.db == nil {
		return nil
	}
	ctx := r.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	_, err := r.db.ExecContext(ctx, `INSERT INTO boundary_records_index (
		record_id, verdict, reason_code, tool_name, mcp_server_id, policy_epoch, receipt_id, record_hash, created_at
	) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
	ON CONFLICT(record_id) DO UPDATE SET
		verdict = excluded.verdict,
		reason_code = excluded.reason_code,
		tool_name = excluded.tool_name,
		mcp_server_id = excluded.mcp_server_id,
		policy_epoch = excluded.policy_epoch,
		receipt_id = excluded.receipt_id,
		record_hash = excluded.record_hash,
		created_at = excluded.created_at`,
		record.RecordID,
		string(record.Verdict),
		string(record.ReasonCode),
		record.ToolName,
		record.MCPServerID,
		record.PolicyEpoch,
		record.ReceiptID,
		record.RecordHash,
		record.CreatedAt.UTC().Format(time.RFC3339Nano))
	if err != nil {
		return fmt.Errorf("persist boundary record index: %w", err)
	}
	return nil
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

func (r *SurfaceRegistry) countOpenApprovalsLocked() int {
	count := 0
	for _, approval := range r.approvals {
		if approval.State == contracts.ApprovalCeremonyPending {
			count++
		}
	}
	return count
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
