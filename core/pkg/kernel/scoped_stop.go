// Scoped emergency-stop fences are durable, tenant/workspace-bound barriers for
// newly governed dispatches. They intentionally do not claim to cancel work
// that was already in flight; callers must surface that coverage boundary.
//
// This package persists active fence state only. It is not the immutable
// control-plane command ledger or acknowledgement-evidence store; those remain
// required before an operator-facing receipt-backed Emergency Stop is claimed.

package kernel

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
)

var (
	ErrScopedStopInvalid    = errors.New("invalid scoped emergency-stop command")
	ErrScopedStopStaleEpoch = errors.New("stale scoped emergency-stop epoch")
	ErrScopedStopConflict   = errors.New("scoped emergency-stop command conflict")
)

const (
	EmergencyStopFenceContractVersion = "emergency-stop-fence.v1"
	EmergencyStopSignerClassical      = "classical"
	EmergencyStopSignerHybrid         = "hybrid"
	// RFC 8785 JCS numbers are interoperable only through the ECMAScript safe
	// integer range. Keeping epochs below this bound prevents a JavaScript CP
	// from signing a value that a Go verifier interprets differently.
	EmergencyStopMaxEpoch uint64 = 9007199254740991
)

type StopScope struct {
	TenantID    string `json:"tenant_id"`
	WorkspaceID string `json:"workspace_id"`
}

// AcknowledgementIdentity is the deployment-pinned Kernel signing identity
// that is bound into a durable FENCE_ACK. A consumer must resolve KeyID and
// SignerProfile through its configured Kernel trust keyring and compare that
// record with PublicKey before accepting the acknowledgement signature.
type AcknowledgementIdentity struct {
	KeyID         string `json:"kernel_key_id"`
	SignerProfile string `json:"kernel_signer_profile"`
	PublicKey     string `json:"kernel_public_key"`
}

func (i AcknowledgementIdentity) normalize() (AcknowledgementIdentity, error) {
	if hasOuterWhitespace(i.KeyID) || !validEmergencyStopKeyID(i.KeyID) {
		return AcknowledgementIdentity{}, fmt.Errorf("%w: kernel_key_id is invalid", ErrScopedStopInvalid)
	}
	if hasOuterWhitespace(i.SignerProfile) {
		return AcknowledgementIdentity{}, fmt.Errorf("%w: kernel_signer_profile is invalid", ErrScopedStopInvalid)
	}
	if i.SignerProfile != EmergencyStopSignerClassical && i.SignerProfile != EmergencyStopSignerHybrid {
		return AcknowledgementIdentity{}, fmt.Errorf("%w: kernel_signer_profile is unsupported", ErrScopedStopInvalid)
	}
	if i.PublicKey == "" || i.PublicKey != strings.TrimSpace(i.PublicKey) || len(i.PublicKey) > 16384 {
		return AcknowledgementIdentity{}, fmt.Errorf("%w: kernel_public_key is invalid", ErrScopedStopInvalid)
	}
	return i, nil
}

func (s StopScope) normalized() (StopScope, error) {
	if s.TenantID == "" || s.WorkspaceID == "" || hasOuterWhitespace(s.TenantID) || hasOuterWhitespace(s.WorkspaceID) {
		return StopScope{}, fmt.Errorf("%w: tenant_id and workspace_id are required", ErrScopedStopInvalid)
	}
	if len(s.TenantID) > 255 || len(s.WorkspaceID) > 255 {
		return StopScope{}, fmt.Errorf("%w: scope exceeds maximum length", ErrScopedStopInvalid)
	}
	return s, nil
}

// FenceCommand is the unsigned logical payload that the control plane signs
// before asking the Kernel to fence a scope. CommandID is the idempotency key;
// Epoch must monotonically increase per scope.
type FenceCommand struct {
	ContractVersion string    `json:"contract_version"`
	Audience        string    `json:"audience"`
	KeyID           string    `json:"key_id"`
	CommandID       string    `json:"command_id"`
	TenantID        string    `json:"tenant_id"`
	WorkspaceID     string    `json:"workspace_id"`
	Epoch           uint64    `json:"epoch"`
	ActorID         string    `json:"actor_id"`
	Reason          string    `json:"reason"`
	IssuedAt        time.Time `json:"issued_at"`
	ExpiresAt       time.Time `json:"expires_at"`
}

func (c FenceCommand) normalize() (FenceCommand, error) {
	if hasOuterWhitespace(c.ContractVersion) || hasOuterWhitespace(c.Audience) || hasOuterWhitespace(c.KeyID) || hasOuterWhitespace(c.CommandID) || hasOuterWhitespace(c.TenantID) || hasOuterWhitespace(c.WorkspaceID) || hasOuterWhitespace(c.ActorID) || hasOuterWhitespace(c.Reason) {
		return FenceCommand{}, fmt.Errorf("%w: command strings must not have outer whitespace", ErrScopedStopInvalid)
	}
	if c.ContractVersion != EmergencyStopFenceContractVersion {
		return FenceCommand{}, fmt.Errorf("%w: unsupported contract_version", ErrScopedStopInvalid)
	}
	if c.Audience == "" || c.KeyID == "" || c.CommandID == "" || c.ActorID == "" || c.Reason == "" || c.Epoch == 0 || c.IssuedAt.IsZero() || c.ExpiresAt.IsZero() {
		return FenceCommand{}, fmt.Errorf("%w: audience, key_id, command_id, actor_id, reason, epoch, issued_at, and expires_at are required", ErrScopedStopInvalid)
	}
	if c.Epoch > EmergencyStopMaxEpoch {
		return FenceCommand{}, fmt.Errorf("%w: epoch exceeds the JCS-safe integer range", ErrScopedStopInvalid)
	}
	if len(c.Audience) > 255 || !validEmergencyStopKeyID(c.KeyID) || len(c.CommandID) > 128 || len(c.ActorID) > 255 || len(c.Reason) > 2048 {
		return FenceCommand{}, fmt.Errorf("%w: command fields exceed maximum length", ErrScopedStopInvalid)
	}
	scope, err := (StopScope{TenantID: c.TenantID, WorkspaceID: c.WorkspaceID}).normalized()
	if err != nil {
		return FenceCommand{}, err
	}
	c.TenantID = scope.TenantID
	c.WorkspaceID = scope.WorkspaceID
	c.IssuedAt = c.IssuedAt.UTC()
	c.ExpiresAt = c.ExpiresAt.UTC()
	if !c.ExpiresAt.After(c.IssuedAt) || c.ExpiresAt.Sub(c.IssuedAt) > 10*time.Minute {
		return FenceCommand{}, fmt.Errorf("%w: expires_at must be after issued_at and within ten minutes", ErrScopedStopInvalid)
	}
	return c, nil
}

func hasOuterWhitespace(value string) bool {
	return value != strings.TrimSpace(value)
}

func validEmergencyStopKeyID(value string) bool {
	if len(value) == 0 || len(value) > 128 {
		return false
	}
	for _, r := range value {
		if (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') && r != '.' && r != '_' && r != '-' {
			return false
		}
	}
	return true
}

func (c FenceCommand) Scope() StopScope {
	return StopScope{TenantID: c.TenantID, WorkspaceID: c.WorkspaceID}
}

// CanonicalPayload is stable across producer and verifier implementations. It
// is intentionally separate from a transport envelope so a signature can never
// cover a caller-controlled header or route value.
func (c FenceCommand) CanonicalPayload() ([]byte, error) {
	normalized, err := c.normalize()
	if err != nil {
		return nil, err
	}
	return canonicalize.JCS(struct {
		Action          string `json:"action"`
		ContractVersion string `json:"contract_version"`
		Audience        string `json:"audience"`
		KeyID           string `json:"key_id"`
		CommandID       string `json:"command_id"`
		TenantID        string `json:"tenant_id"`
		WorkspaceID     string `json:"workspace_id"`
		Epoch           uint64 `json:"epoch"`
		ActorID         string `json:"actor_id"`
		Reason          string `json:"reason"`
		IssuedAt        string `json:"issued_at"`
		ExpiresAt       string `json:"expires_at"`
	}{
		Action:          "FENCE",
		ContractVersion: normalized.ContractVersion,
		Audience:        normalized.Audience,
		KeyID:           normalized.KeyID,
		CommandID:       normalized.CommandID,
		TenantID:        normalized.TenantID,
		WorkspaceID:     normalized.WorkspaceID,
		Epoch:           normalized.Epoch,
		ActorID:         normalized.ActorID,
		Reason:          normalized.Reason,
		IssuedAt:        normalized.IssuedAt.Format(time.RFC3339Nano),
		ExpiresAt:       normalized.ExpiresAt.Format(time.RFC3339Nano),
	})
}

type FenceState struct {
	StopScope
	ContractVersion string    `json:"contract_version"`
	Audience        string    `json:"audience"`
	KeyID           string    `json:"key_id"`
	CommandID       string    `json:"command_id"`
	CommandHash     string    `json:"command_hash"`
	Epoch           uint64    `json:"epoch"`
	ActorID         string    `json:"actor_id"`
	Reason          string    `json:"reason"`
	IssuedAt        time.Time `json:"issued_at"`
	ExpiresAt       time.Time `json:"expires_at"`
	FencedAt        time.Time `json:"fenced_at"`
	AcknowledgementIdentity
	ReceiptHash string `json:"receipt_hash"`
}

func (s FenceState) canonicalPayload() ([]byte, error) {
	return canonicalize.JCS(struct {
		Action          string `json:"action"`
		ContractVersion string `json:"contract_version"`
		Audience        string `json:"audience"`
		KeyID           string `json:"key_id"`
		CommandID       string `json:"command_id"`
		CommandHash     string `json:"command_hash"`
		TenantID        string `json:"tenant_id"`
		WorkspaceID     string `json:"workspace_id"`
		Epoch           uint64 `json:"epoch"`
		ActorID         string `json:"actor_id"`
		Reason          string `json:"reason"`
		IssuedAt        string `json:"issued_at"`
		ExpiresAt       string `json:"expires_at"`
		FencedAt        string `json:"fenced_at"`
		KernelKeyID     string `json:"kernel_key_id"`
		SignerProfile   string `json:"kernel_signer_profile"`
		KernelPublicKey string `json:"kernel_public_key"`
	}{
		Action:          "FENCE_ACK",
		ContractVersion: s.ContractVersion,
		Audience:        s.Audience,
		KeyID:           s.KeyID,
		CommandID:       s.CommandID,
		CommandHash:     s.CommandHash,
		TenantID:        s.TenantID,
		WorkspaceID:     s.WorkspaceID,
		Epoch:           s.Epoch,
		ActorID:         s.ActorID,
		Reason:          s.Reason,
		IssuedAt:        s.IssuedAt.UTC().Format(time.RFC3339Nano),
		ExpiresAt:       s.ExpiresAt.UTC().Format(time.RFC3339Nano),
		FencedAt:        s.FencedAt.UTC().Format(time.RFC3339Nano),
		KernelKeyID:     s.AcknowledgementIdentity.KeyID,
		SignerProfile:   s.AcknowledgementIdentity.SignerProfile,
		KernelPublicKey: s.AcknowledgementIdentity.PublicKey,
	})
}

func (s FenceState) withReceiptHash() (FenceState, error) {
	payload, err := s.canonicalPayload()
	if err != nil {
		return FenceState{}, err
	}
	sum := sha256.Sum256(payload)
	s.ReceiptHash = "sha256:" + hex.EncodeToString(sum[:])
	return s, nil
}

// AcknowledgementPayload is what the Kernel signs after it has durably
// persisted a fence. It excludes the hash and signature fields themselves.
func (s FenceState) AcknowledgementPayload() ([]byte, error) {
	return s.canonicalPayload()
}

// ScopedStopReader is the narrow Guardian dependency. A reader error means
// scope status is unverified and must be denied by a configured Guardian.
type ScopedStopReader interface {
	IsFenced(ctx context.Context, scope StopScope) (FenceState, bool, error)
}

// ScopedStopStore uses the Kernel runtime database (SQLite in local mode,
// Postgres in production) so fences survive process restart.
type ScopedStopStore struct {
	db  *sql.DB
	now func() time.Time
}

func NewScopedStopStore(db *sql.DB, now func() time.Time) *ScopedStopStore {
	if now == nil {
		now = time.Now
	}
	return &ScopedStopStore{db: db, now: now}
}

func (s *ScopedStopStore) Init(ctx context.Context) error {
	if s == nil || s.db == nil {
		return fmt.Errorf("%w: scoped emergency-stop store requires a database", ErrScopedStopInvalid)
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if _, err := s.db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS emergency_stop_fences (
		tenant_id TEXT NOT NULL,
		workspace_id TEXT NOT NULL,
		contract_version TEXT NOT NULL,
		audience TEXT NOT NULL,
		key_id TEXT NOT NULL,
		command_id TEXT NOT NULL,
		command_hash TEXT NOT NULL,
		epoch BIGINT NOT NULL,
		actor_id TEXT NOT NULL,
		reason TEXT NOT NULL,
		issued_at TEXT NOT NULL,
		expires_at TEXT NOT NULL,
		fenced_at TEXT NOT NULL,
		kernel_key_id TEXT NOT NULL,
		kernel_signer_profile TEXT NOT NULL,
		kernel_public_key TEXT NOT NULL,
		receipt_hash TEXT NOT NULL,
		PRIMARY KEY (tenant_id, workspace_id),
		UNIQUE (command_id)
	)`); err != nil {
		return fmt.Errorf("init scoped emergency-stop fences: %w", err)
	}
	return nil
}

func (s *ScopedStopStore) Get(ctx context.Context, scope StopScope) (FenceState, bool, error) {
	if s == nil || s.db == nil {
		return FenceState{}, false, fmt.Errorf("%w: scoped emergency-stop store unavailable", ErrScopedStopInvalid)
	}
	normalizedScope, err := scope.normalized()
	if err != nil {
		return FenceState{}, false, err
	}
	if ctx == nil {
		ctx = context.Background()
	}

	var state FenceState
	var issuedAt, expiresAt, fencedAt string
	err = s.db.QueryRowContext(ctx, `SELECT contract_version, audience, key_id, command_id, command_hash, epoch, actor_id, reason, issued_at, expires_at, fenced_at, kernel_key_id, kernel_signer_profile, kernel_public_key, receipt_hash
		FROM emergency_stop_fences
		WHERE tenant_id = $1 AND workspace_id = $2`, normalizedScope.TenantID, normalizedScope.WorkspaceID).Scan(
		&state.ContractVersion,
		&state.Audience,
		&state.KeyID,
		&state.CommandID,
		&state.CommandHash,
		&state.Epoch,
		&state.ActorID,
		&state.Reason,
		&issuedAt,
		&expiresAt,
		&fencedAt,
		&state.AcknowledgementIdentity.KeyID,
		&state.AcknowledgementIdentity.SignerProfile,
		&state.AcknowledgementIdentity.PublicKey,
		&state.ReceiptHash,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return FenceState{}, false, nil
	}
	if err != nil {
		return FenceState{}, false, fmt.Errorf("read scoped emergency-stop fence: %w", err)
	}
	state.StopScope = normalizedScope
	state.IssuedAt, err = time.Parse(time.RFC3339Nano, issuedAt)
	if err != nil {
		return FenceState{}, false, fmt.Errorf("parse scoped emergency-stop issued_at: %w", err)
	}
	state.ExpiresAt, err = time.Parse(time.RFC3339Nano, expiresAt)
	if err != nil {
		return FenceState{}, false, fmt.Errorf("parse scoped emergency-stop expires_at: %w", err)
	}
	state.FencedAt, err = time.Parse(time.RFC3339Nano, fencedAt)
	if err != nil {
		return FenceState{}, false, fmt.Errorf("parse scoped emergency-stop fenced_at: %w", err)
	}
	return state, true, nil
}

func (s *ScopedStopStore) IsFenced(ctx context.Context, scope StopScope) (FenceState, bool, error) {
	return s.Get(ctx, scope)
}

// Fence atomically persists a higher scoped fence epoch. Replaying the same
// command returns the original state; lower/equal competing epochs cannot
// replace a fence.
func (s *ScopedStopStore) Fence(ctx context.Context, command FenceCommand, acknowledgement AcknowledgementIdentity) (FenceState, bool, error) {
	if s == nil || s.db == nil {
		return FenceState{}, false, fmt.Errorf("%w: scoped emergency-stop store unavailable", ErrScopedStopInvalid)
	}
	normalized, err := command.normalize()
	if err != nil {
		return FenceState{}, false, err
	}
	normalizedAcknowledgement, err := acknowledgement.normalize()
	if err != nil {
		return FenceState{}, false, err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	commandPayload, err := normalized.CanonicalPayload()
	if err != nil {
		return FenceState{}, false, fmt.Errorf("canonicalize scoped emergency-stop command: %w", err)
	}
	commandSum := sha256.Sum256(commandPayload)
	commandHash := "sha256:" + hex.EncodeToString(commandSum[:])

	existing, found, err := s.Get(ctx, normalized.Scope())
	if err != nil {
		return FenceState{}, false, err
	}
	if found {
		if existing.CommandID == normalized.CommandID {
			if existing.CommandHash != commandHash {
				return FenceState{}, false, fmt.Errorf("%w: command_id replay does not match its original payload", ErrScopedStopConflict)
			}
			if existing.AcknowledgementIdentity != normalizedAcknowledgement {
				return FenceState{}, false, fmt.Errorf("%w: command replay does not match its persisted kernel acknowledgement identity", ErrScopedStopConflict)
			}
			return existing, true, nil
		}
		if normalized.Epoch <= existing.Epoch {
			return FenceState{}, false, fmt.Errorf("%w: requested=%d active=%d", ErrScopedStopStaleEpoch, normalized.Epoch, existing.Epoch)
		}
	}

	state, err := (FenceState{
		StopScope:               normalized.Scope(),
		ContractVersion:         normalized.ContractVersion,
		Audience:                normalized.Audience,
		KeyID:                   normalized.KeyID,
		CommandID:               normalized.CommandID,
		CommandHash:             commandHash,
		Epoch:                   normalized.Epoch,
		ActorID:                 normalized.ActorID,
		Reason:                  normalized.Reason,
		IssuedAt:                normalized.IssuedAt,
		ExpiresAt:               normalized.ExpiresAt,
		FencedAt:                s.now().UTC(),
		AcknowledgementIdentity: normalizedAcknowledgement,
	}).withReceiptHash()
	if err != nil {
		return FenceState{}, false, fmt.Errorf("hash scoped emergency-stop receipt: %w", err)
	}

	result, err := s.db.ExecContext(ctx, `INSERT INTO emergency_stop_fences (
		tenant_id, workspace_id, contract_version, audience, key_id, command_id, command_hash, epoch, actor_id, reason, issued_at, expires_at, fenced_at, kernel_key_id, kernel_signer_profile, kernel_public_key, receipt_hash
	) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)
	ON CONFLICT(tenant_id, workspace_id) DO UPDATE SET
		contract_version = excluded.contract_version,
		audience = excluded.audience,
		key_id = excluded.key_id,
		command_id = excluded.command_id,
		command_hash = excluded.command_hash,
		epoch = excluded.epoch,
		actor_id = excluded.actor_id,
		reason = excluded.reason,
		issued_at = excluded.issued_at,
		expires_at = excluded.expires_at,
		fenced_at = excluded.fenced_at,
		kernel_key_id = excluded.kernel_key_id,
		kernel_signer_profile = excluded.kernel_signer_profile,
		kernel_public_key = excluded.kernel_public_key,
		receipt_hash = excluded.receipt_hash
	WHERE emergency_stop_fences.epoch < excluded.epoch`,
		state.TenantID,
		state.WorkspaceID,
		state.ContractVersion,
		state.Audience,
		state.KeyID,
		state.CommandID,
		state.CommandHash,
		state.Epoch,
		state.ActorID,
		state.Reason,
		state.IssuedAt.Format(time.RFC3339Nano),
		state.ExpiresAt.Format(time.RFC3339Nano),
		state.FencedAt.Format(time.RFC3339Nano),
		state.AcknowledgementIdentity.KeyID,
		state.AcknowledgementIdentity.SignerProfile,
		state.AcknowledgementIdentity.PublicKey,
		state.ReceiptHash,
	)
	if err != nil {
		return FenceState{}, false, fmt.Errorf("%w: persist scoped emergency-stop fence: %v", ErrScopedStopConflict, err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return FenceState{}, false, fmt.Errorf("read scoped emergency-stop fence result: %w", err)
	}
	if affected == 0 {
		current, currentFound, readErr := s.Get(ctx, state.StopScope)
		if readErr != nil {
			return FenceState{}, false, readErr
		}
		if currentFound && current.CommandID == state.CommandID {
			if current.CommandHash == state.CommandHash {
				if current.AcknowledgementIdentity != normalizedAcknowledgement {
					return FenceState{}, false, fmt.Errorf("%w: command replay does not match its persisted kernel acknowledgement identity", ErrScopedStopConflict)
				}
				return current, true, nil
			}
			return FenceState{}, false, fmt.Errorf("%w: command_id replay does not match its original payload", ErrScopedStopConflict)
		}
		if currentFound {
			return FenceState{}, false, fmt.Errorf("%w: requested=%d active=%d", ErrScopedStopStaleEpoch, state.Epoch, current.Epoch)
		}
		return FenceState{}, false, fmt.Errorf("%w: fence write was not applied", ErrScopedStopConflict)
	}
	return state, false, nil
}
