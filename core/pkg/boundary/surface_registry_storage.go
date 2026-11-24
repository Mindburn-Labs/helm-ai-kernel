package boundary

// quantum_posture: Registry persistence stores existing receipt and checkpoint records.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	mcppkg "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/mcp"
)

// NewFileBackedSurfaceRegistry creates a registry that persists OSS boundary
// surface state to a local JSON snapshot after every mutation.
func NewFileBackedSurfaceRegistry(path string, now func() time.Time) (*SurfaceRegistry, error) {
	if strings.TrimSpace(path) == "" || strings.EqualFold(path, "memory") {
		return NewSurfaceRegistry(now), nil
	}
	r := newSurfaceRegistry(now)
	seeded := false
	if data, err := os.ReadFile(path); err == nil {
		if len(strings.TrimSpace(string(data))) == 0 {
			r.seed()
			seeded = true
		} else if err := r.loadSnapshot(data); err != nil {
			return nil, fmt.Errorf("load boundary registry %s: %w", path, err)
		}
	} else if os.IsNotExist(err) {
		r.seed()
		seeded = true
	} else {
		return nil, fmt.Errorf("read boundary registry %s: %w", path, err)
	}
	r.path = path
	// Only a fresh seed is written back. Persisting an unchanged snapshot meant
	// that merely opening the registry — which every read-only surface command
	// does, including help paths — rewrote authority state on disk. The seed
	// still persists on first use, so its generated ids stay stable across
	// invocations; that stability was the reason for the unconditional write.
	if seeded {
		r.mu.Lock()
		err := r.persistLocked()
		r.mu.Unlock()
		if err != nil {
			return nil, err
		}
	}
	return r, nil
}

// NewSQLSurfaceRegistry creates a durable registry backed by the same SQLite or
// Postgres database as the OSS runtime. It stores a versioned snapshot in one
// row so API, Console, and SDK surfaces share durable state without becoming a
// second policy authority.
func NewSQLSurfaceRegistry(ctx context.Context, db *sql.DB, databaseMode string, now func() time.Time) (*SurfaceRegistry, error) {
	if db == nil {
		return NewSurfaceRegistry(now), nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	var eventTableDDL string
	switch strings.ToLower(strings.TrimSpace(databaseMode)) {
	case "sqlite", "sqlite3":
		eventTableDDL = `CREATE TABLE IF NOT EXISTS boundary_surface_events (
			sequence INTEGER PRIMARY KEY AUTOINCREMENT,
			event_kind TEXT NOT NULL,
			object_id TEXT NOT NULL,
			object_json TEXT NOT NULL,
			created_at TEXT NOT NULL
		)`
	case "postgres", "postgresql":
		eventTableDDL = `CREATE TABLE IF NOT EXISTS boundary_surface_events (
			sequence BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
			event_kind TEXT NOT NULL,
			object_id TEXT NOT NULL,
			object_json TEXT NOT NULL,
			created_at TEXT NOT NULL
		)`
	default:
		return nil, fmt.Errorf("init boundary surface registry: unsupported database mode %q", databaseMode)
	}
	if _, err := db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS boundary_surface_snapshots (
		id TEXT PRIMARY KEY,
		snapshot_json TEXT NOT NULL,
		updated_at TEXT NOT NULL
	)`); err != nil {
		return nil, fmt.Errorf("init boundary surface table: %w", err)
	}
	if _, err := db.ExecContext(ctx, eventTableDDL); err != nil {
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
	return loadSQLSurfaceRegistry(ctx, db, now)
}

// NewRuntimeSQLSurfaceRegistry opens the boundary surface registry using an
// already migrated Postgres database. It performs only reads followed by the
// normal snapshot DML; it never executes DDL.
func NewRuntimeSQLSurfaceRegistry(ctx context.Context, db *sql.DB, now func() time.Time) (*SurfaceRegistry, error) {
	if db == nil {
		return NewSurfaceRegistry(now), nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	return loadSQLSurfaceRegistry(ctx, db, now)
}

// MigratePostgresSurfaceRegistry applies the Postgres boundary surface schema
// as an explicit owner operation. The SQLite-compatible schema above remains
// available to the local combined constructor.
func MigratePostgresSurfaceRegistry(ctx context.Context, db *sql.DB) error {
	if db == nil {
		return errors.New("postgres boundary surface migration requires database")
	}
	if _, err := db.ExecContext(ctx, postgresSurfaceRegistrySchema); err != nil {
		return fmt.Errorf("init postgres boundary surface schema: %w", err)
	}
	return nil
}

const postgresSurfaceRegistrySchema = `
CREATE TABLE IF NOT EXISTS boundary_surface_snapshots (
	id TEXT PRIMARY KEY,
	snapshot_json TEXT NOT NULL,
	updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS boundary_surface_events (
	sequence BIGSERIAL PRIMARY KEY,
	event_kind TEXT NOT NULL,
	object_id TEXT NOT NULL,
	object_json TEXT NOT NULL,
	created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS boundary_records_index (
	record_id TEXT PRIMARY KEY,
	verdict TEXT NOT NULL,
	reason_code TEXT,
	tool_name TEXT,
	mcp_server_id TEXT,
	policy_epoch TEXT NOT NULL,
	receipt_id TEXT,
	record_hash TEXT NOT NULL,
	created_at TEXT NOT NULL
);
`

func loadSQLSurfaceRegistry(ctx context.Context, db *sql.DB, now func() time.Time) (*SurfaceRegistry, error) {
	r := newSurfaceRegistry(now)
	seeded := false
	var snapshotJSON string
	err := db.QueryRowContext(ctx, `SELECT snapshot_json FROM boundary_surface_snapshots WHERE id = $1`, "default").Scan(&snapshotJSON)
	if err == nil {
		if err := r.loadSnapshot([]byte(snapshotJSON)); err != nil {
			return nil, fmt.Errorf("load boundary surface snapshot: %w", err)
		}
	} else if err == sql.ErrNoRows {
		r.seed()
		seeded = true
	} else {
		return nil, fmt.Errorf("read boundary surface snapshot: %w", err)
	}
	r.db = db
	r.ctx = ctx
	if seeded {
		r.mu.Lock()
		err = r.persistLocked()
		r.mu.Unlock()
		if err != nil {
			return nil, err
		}
	}
	return r, nil
}

// StorageBackend reports the persistence mode backing the registry. It is used
// by diagnostics only, so it intentionally exposes no database DSN or secret.
func (r *SurfaceRegistry) StorageBackend() string {
	if r == nil {
		return "unavailable"
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	switch {
	case r.db != nil:
		return "sql"
	case strings.TrimSpace(r.path) != "":
		return "file"
	default:
		return "memory"
	}
}

type surfaceRegistrySnapshot struct {
	Version            int                                            `json:"version"`
	Records            map[string]contracts.ExecutionBoundaryRecord   `json:"records"`
	Checkpoints        map[string]contracts.BoundaryCheckpoint        `json:"checkpoints"`
	Approvals          map[string]contracts.ApprovalCeremony          `json:"approvals"`
	Challenges         map[string]contracts.ApprovalWebAuthnChallenge `json:"challenges"`
	AuthProfiles       map[string]contracts.MCPAuthorizationProfile   `json:"auth_profiles"`
	MCPServers         map[string]mcppkg.ServerQuarantineRecord       `json:"mcp_servers"`
	SandboxGrants      map[string]contracts.SandboxGrant              `json:"sandbox_grants"`
	AuthzSnapshots     map[string]contracts.AuthzSnapshot             `json:"authz_snapshots"`
	Envelopes          map[string]contracts.EvidenceEnvelopeManifest  `json:"envelopes"`
	EnvelopePayloads   map[string]contracts.EvidenceEnvelopePayload   `json:"envelope_payloads"`
	VerificationScopes map[string]contracts.VerificationScope         `json:"verification_scopes"`
	HarnessTraces      map[string]contracts.HarnessTrace              `json:"harness_traces"`
	PlanTransactions   map[string]contracts.PlanTransaction           `json:"plan_transactions"`
	HarnessChanges     map[string]contracts.HarnessChangeContract     `json:"harness_change_contracts"`
	GroundedActions    map[string]contracts.GroundedActionRef         `json:"grounded_action_refs"`
	GUIReceipts        map[string]contracts.GUIActionReceipt          `json:"gui_action_receipts"`
	Budgets            map[string]contracts.BudgetCeiling             `json:"budgets"`
	Agents             map[string]contracts.AgentIdentityProfile      `json:"agents"`
	Reports            map[string]map[string]any                      `json:"reports"`
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
	for id, record := range r.mcpServers {
		r.mcpServers[id] = mcppkg.FailClosedUnverifiedApproval(record)
	}
	r.sandboxGrants = snap.SandboxGrants
	r.authzSnapshots = snap.AuthzSnapshots
	r.envelopes = snap.Envelopes
	r.envelopePayloads = snap.EnvelopePayloads
	r.verificationScopes = snap.VerificationScopes
	r.harnessTraces = snap.HarnessTraces
	r.planTransactions = snap.PlanTransactions
	r.harnessChanges = snap.HarnessChanges
	r.groundedActions = snap.GroundedActions
	r.guiReceipts = snap.GUIReceipts
	r.budgets = snap.Budgets
	r.agents = snap.Agents
	r.reports = snap.Reports
	r.ensureMaps()
	return nil
}

func (r *SurfaceRegistry) persistLocked() error {
	data, err := json.MarshalIndent(surfaceRegistrySnapshot{
		Version:            2,
		Records:            r.records,
		Checkpoints:        r.checkpoints,
		Approvals:          r.approvals,
		Challenges:         r.challenges,
		AuthProfiles:       r.authProfiles,
		MCPServers:         r.mcpServers,
		SandboxGrants:      r.sandboxGrants,
		AuthzSnapshots:     r.authzSnapshots,
		Envelopes:          r.envelopes,
		EnvelopePayloads:   r.envelopePayloads,
		VerificationScopes: r.verificationScopes,
		HarnessTraces:      r.harnessTraces,
		PlanTransactions:   r.planTransactions,
		HarnessChanges:     r.harnessChanges,
		GroundedActions:    r.groundedActions,
		GUIReceipts:        r.guiReceipts,
		Budgets:            r.budgets,
		Agents:             r.agents,
		Reports:            r.reports,
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
