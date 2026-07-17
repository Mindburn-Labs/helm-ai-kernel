package connectors

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

var (
	ErrReleaseAuthorityNotFound = errors.New("connector release authority not found")
	ErrReleaseAuthorityConflict = errors.New("connector release authority revision conflict")
	ErrReleaseAuthorityTerminal = errors.New("connector release authority is terminally revoked")
	ErrReleaseAuthorityStore    = errors.New("connector release authority store rejected request")
)

// ReleaseAuthorityEnvelopeVerifier is the cryptographic boundary required by
// both the source-authority writer and the read-only runtime projection.
type ReleaseAuthorityEnvelopeVerifier interface {
	VerifyEnvelope(contracts.ConnectorReleaseAuthorityEnvelope) error
	VerifyCurrentCertifiedAt(contracts.ConnectorReleaseAuthorityEnvelope, time.Time) error
}

// ReleaseAuthorityLookup identifies one exact release and one exact authority
// scope. There is deliberately no implicit tenant-to-global fallback.
type ReleaseAuthorityLookup struct {
	ScopeKind        string
	TenantID         string
	WorkspaceID      string
	ConnectorID      string
	ConnectorVersion string
}

func (l ReleaseAuthorityLookup) validate() error {
	if !releaseAuthorityToken(l.ConnectorID) || !releaseAuthorityToken(l.ConnectorVersion) {
		return releaseAuthorityStoreRejected("connector_id and connector_version are required")
	}
	switch l.ScopeKind {
	case contracts.ConnectorReleaseAuthorityScopeGlobal:
		if l.TenantID != "" || l.WorkspaceID != "" {
			return releaseAuthorityStoreRejected("global lookup must not carry tenant or workspace")
		}
	case contracts.ConnectorReleaseAuthorityScopeWorkspace:
		if !releaseAuthorityToken(l.TenantID) || !releaseAuthorityToken(l.WorkspaceID) {
			return releaseAuthorityStoreRejected("tenant_workspace lookup requires tenant and workspace")
		}
	default:
		return releaseAuthorityStoreRejected("unsupported scope_kind")
	}
	return nil
}

func releaseAuthorityLookup(authority contracts.ConnectorReleaseAuthority) ReleaseAuthorityLookup {
	return ReleaseAuthorityLookup{
		ScopeKind: authority.ScopeKind, TenantID: authority.TenantID, WorkspaceID: authority.WorkspaceID,
		ConnectorID: authority.ConnectorID, ConnectorVersion: authority.ConnectorVersion,
	}
}

// ReleaseAuthorityAppendResult distinguishes an idempotent exact replay from
// the one transaction that appended a new immutable revision.
type ReleaseAuthorityAppendResult struct {
	Envelope contracts.ConnectorReleaseAuthorityEnvelope
	Replay   bool
}

// PostgresReleaseAuthorityAdminStore is the source-authority import path. Its
// database role needs SELECT and INSERT only; UPDATE, DELETE, and DDL remain
// forbidden by grants and the database append-only trigger.
type PostgresReleaseAuthorityAdminStore struct {
	db       *sql.DB
	verifier ReleaseAuthorityEnvelopeVerifier
}

func NewPostgresReleaseAuthorityAdminStore(db *sql.DB, verifier ReleaseAuthorityEnvelopeVerifier) (*PostgresReleaseAuthorityAdminStore, error) {
	if db == nil || verifier == nil {
		return nil, releaseAuthorityStoreRejected("admin store requires database and verifier")
	}
	return &PostgresReleaseAuthorityAdminStore{db: db, verifier: verifier}, nil
}

// PostgresReleaseAuthorityStore is the runtime read projection. Production
// runtime roles require only USAGE on the schema and SELECT on the table.
type PostgresReleaseAuthorityStore struct {
	db       *sql.DB
	verifier ReleaseAuthorityEnvelopeVerifier
}

func NewPostgresReleaseAuthorityStore(db *sql.DB, verifier ReleaseAuthorityEnvelopeVerifier) (*PostgresReleaseAuthorityStore, error) {
	if db == nil || verifier == nil {
		return nil, releaseAuthorityStoreRejected("runtime store requires database and verifier")
	}
	return &PostgresReleaseAuthorityStore{db: db, verifier: verifier}, nil
}

const releaseAuthorityRecordColumns = `
scope_kind, tenant_id, workspace_id, connector_id, connector_version,
registry_revision, state, authority_hash, previous_authority_hash,
revokes_authority_hash, signed_at, valid_from, valid_until,
envelope_json, signature, created_at
`

type releaseAuthorityRecord struct {
	Envelope  contracts.ConnectorReleaseAuthorityEnvelope
	CreatedAt time.Time
}

func (s *PostgresReleaseAuthorityAdminStore) Append(ctx context.Context, envelope contracts.ConnectorReleaseAuthorityEnvelope) (ReleaseAuthorityAppendResult, error) {
	if s == nil || s.db == nil || s.verifier == nil {
		return ReleaseAuthorityAppendResult{}, releaseAuthorityStoreRejected("admin store is not configured")
	}
	if err := s.verifier.VerifyEnvelope(envelope); err != nil {
		return ReleaseAuthorityAppendResult{}, err
	}
	authority := envelope.Authority
	lookup := releaseAuthorityLookup(authority)
	if err := lookup.validate(); err != nil {
		return ReleaseAuthorityAppendResult{}, err
	}

	tx, err := beginReleaseAuthorityTx(ctx, s.db, lookup, false)
	if err != nil {
		return ReleaseAuthorityAppendResult{}, err
	}
	defer func() { _ = tx.Rollback() }()
	if err := lockReleaseAuthority(ctx, tx, lookup, false); err != nil {
		return ReleaseAuthorityAppendResult{}, err
	}

	current, err := queryCurrentReleaseAuthority(ctx, tx, lookup)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		if authority.RegistryRevision != 1 {
			return ReleaseAuthorityAppendResult{}, fmt.Errorf("%w: first revision must be 1", ErrReleaseAuthorityConflict)
		}
	case err != nil:
		return ReleaseAuthorityAppendResult{}, err
	default:
		if err := validateStoredReleaseAuthority(current, s.verifier); err != nil {
			return ReleaseAuthorityAppendResult{}, err
		}
		previous := current.Envelope.Authority
		if authority.RegistryRevision <= previous.RegistryRevision {
			if authority.RegistryRevision == previous.RegistryRevision &&
				authority.AuthorityHash == previous.AuthorityHash &&
				envelope.Signature == current.Envelope.Signature {
				if err := tx.Commit(); err != nil {
					return ReleaseAuthorityAppendResult{}, fmt.Errorf("commit connector release authority replay: %w", err)
				}
				return ReleaseAuthorityAppendResult{Envelope: current.Envelope, Replay: true}, nil
			}
			return ReleaseAuthorityAppendResult{}, fmt.Errorf("%w: stale or competing revision", ErrReleaseAuthorityConflict)
		}
		if previous.State == contracts.ConnectorReleaseAuthorityStateRevoked {
			return ReleaseAuthorityAppendResult{}, ErrReleaseAuthorityTerminal
		}
		if authority.RegistryRevision != previous.RegistryRevision+1 || authority.PreviousAuthorityHash != previous.AuthorityHash {
			return ReleaseAuthorityAppendResult{}, fmt.Errorf("%w: revision or predecessor is not the current head", ErrReleaseAuthorityConflict)
		}
		if authority.SignedAt.Before(previous.SignedAt) || authority.ValidFrom.Before(previous.ValidFrom) {
			return ReleaseAuthorityAppendResult{}, fmt.Errorf("%w: signed timeline moved backwards", ErrReleaseAuthorityConflict)
		}
		if !sameConnectorReleaseMaterial(authority, previous) {
			return ReleaseAuthorityAppendResult{}, fmt.Errorf("%w: exact release material changed across revisions", ErrReleaseAuthorityConflict)
		}
	}

	payload, err := json.Marshal(envelope)
	if err != nil {
		return ReleaseAuthorityAppendResult{}, fmt.Errorf("marshal connector release authority envelope: %w", err)
	}
	inserted, err := scanReleaseAuthorityRecord(tx.QueryRowContext(ctx, `
		INSERT INTO connector_release_authorities (
			scope_kind, tenant_id, workspace_id, connector_id, connector_version,
			registry_revision, state, authority_hash, previous_authority_hash,
			revokes_authority_hash, signed_at, valid_from, valid_until,
			envelope_json, signature
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15
		)
		RETURNING `+releaseAuthorityRecordColumns,
		authority.ScopeKind, authority.TenantID, authority.WorkspaceID,
		authority.ConnectorID, authority.ConnectorVersion, authority.RegistryRevision,
		authority.State, authority.AuthorityHash, nullableAuthorityHash(authority.PreviousAuthorityHash),
		nullableAuthorityHash(authority.RevokesAuthorityHash), authority.SignedAt,
		authority.ValidFrom, authority.ValidUntil, payload, envelope.Signature,
	))
	if err != nil {
		return ReleaseAuthorityAppendResult{}, fmt.Errorf("persist connector release authority: %w", err)
	}
	if err := validateStoredReleaseAuthority(inserted, s.verifier); err != nil {
		return ReleaseAuthorityAppendResult{}, err
	}
	if inserted.Envelope.Authority.AuthorityHash != authority.AuthorityHash {
		return ReleaseAuthorityAppendResult{}, releaseAuthorityStoreRejected("inserted authority differs from request")
	}
	if err := tx.Commit(); err != nil {
		return ReleaseAuthorityAppendResult{}, fmt.Errorf("commit connector release authority append: %w", err)
	}
	return ReleaseAuthorityAppendResult{Envelope: inserted.Envelope}, nil
}

// LoadCurrent returns the latest cryptographically verified statement for
// diagnostics and reconciliation, including a terminal revocation. It is not
// execution authority. Connector start requires a separate durable admission
// reservation and must not rely on this diagnostic/reconciliation projection.
func (s *PostgresReleaseAuthorityStore) LoadCurrent(ctx context.Context, lookup ReleaseAuthorityLookup) (contracts.ConnectorReleaseAuthorityEnvelope, error) {
	if s == nil || s.db == nil || s.verifier == nil {
		return contracts.ConnectorReleaseAuthorityEnvelope{}, releaseAuthorityStoreRejected("runtime store is not configured")
	}
	if err := lookup.validate(); err != nil {
		return contracts.ConnectorReleaseAuthorityEnvelope{}, err
	}
	tx, err := beginReleaseAuthorityTx(ctx, s.db, lookup, true)
	if err != nil {
		return contracts.ConnectorReleaseAuthorityEnvelope{}, err
	}
	defer func() { _ = tx.Rollback() }()
	if err := lockReleaseAuthority(ctx, tx, lookup, true); err != nil {
		return contracts.ConnectorReleaseAuthorityEnvelope{}, err
	}
	record, err := queryCurrentReleaseAuthority(ctx, tx, lookup)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return contracts.ConnectorReleaseAuthorityEnvelope{}, ErrReleaseAuthorityNotFound
		}
		return contracts.ConnectorReleaseAuthorityEnvelope{}, err
	}
	if err := validateStoredReleaseAuthority(record, s.verifier); err != nil {
		return contracts.ConnectorReleaseAuthorityEnvelope{}, err
	}
	if err := tx.Commit(); err != nil {
		return contracts.ConnectorReleaseAuthorityEnvelope{}, fmt.Errorf("commit connector release authority read: %w", err)
	}
	return record.Envelope, nil
}

// LoadCurrentCertified returns the current certified authority for
// non-effecting planning. Validity is evaluated against the database clock,
// never caller-supplied time. The result can become historical immediately
// after return and is not connector-start authority; effect admission requires
// a separate durable, idempotent reservation boundary.
func (s *PostgresReleaseAuthorityStore) LoadCurrentCertified(ctx context.Context, lookup ReleaseAuthorityLookup) (contracts.ConnectorReleaseAuthorityEnvelope, error) {
	if s == nil || s.db == nil || s.verifier == nil {
		return contracts.ConnectorReleaseAuthorityEnvelope{}, releaseAuthorityStoreRejected("runtime store is not configured")
	}
	if err := lookup.validate(); err != nil {
		return contracts.ConnectorReleaseAuthorityEnvelope{}, err
	}
	tx, err := beginReleaseAuthorityTx(ctx, s.db, lookup, true)
	if err != nil {
		return contracts.ConnectorReleaseAuthorityEnvelope{}, err
	}
	defer func() { _ = tx.Rollback() }()
	if err := lockReleaseAuthority(ctx, tx, lookup, true); err != nil {
		return contracts.ConnectorReleaseAuthorityEnvelope{}, err
	}
	record, err := queryCurrentReleaseAuthority(ctx, tx, lookup)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return contracts.ConnectorReleaseAuthorityEnvelope{}, ErrReleaseAuthorityNotFound
		}
		return contracts.ConnectorReleaseAuthorityEnvelope{}, err
	}
	if err := validateStoredReleaseAuthority(record, s.verifier); err != nil {
		return contracts.ConnectorReleaseAuthorityEnvelope{}, err
	}
	var databaseNow time.Time
	if err := tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&databaseNow); err != nil {
		return contracts.ConnectorReleaseAuthorityEnvelope{}, fmt.Errorf("read connector release authority database clock: %w", err)
	}
	if err := s.verifier.VerifyCurrentCertifiedAt(record.Envelope, databaseNow); err != nil {
		return contracts.ConnectorReleaseAuthorityEnvelope{}, err
	}
	if err := tx.Commit(); err != nil {
		return contracts.ConnectorReleaseAuthorityEnvelope{}, fmt.Errorf("commit connector release authority planning read: %w", err)
	}
	return record.Envelope, nil
}

func beginReleaseAuthorityTx(ctx context.Context, db *sql.DB, lookup ReleaseAuthorityLookup, readOnly bool) (*sql.Tx, error) {
	if db == nil {
		return nil, releaseAuthorityStoreRejected("database is not configured")
	}
	if err := lookup.validate(); err != nil {
		return nil, err
	}
	tx, err := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted, ReadOnly: readOnly})
	if err != nil {
		return nil, fmt.Errorf("begin connector release authority transaction: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `SELECT set_config('app.current_tenant', $1, true)`, lookup.TenantID); err != nil {
		_ = tx.Rollback()
		return nil, fmt.Errorf("set connector release authority tenant: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `SELECT set_config('app.current_workspace', $1, true)`, lookup.WorkspaceID); err != nil {
		_ = tx.Rollback()
		return nil, fmt.Errorf("set connector release authority workspace: %w", err)
	}
	return tx, nil
}

func lockReleaseAuthority(ctx context.Context, tx *sql.Tx, lookup ReleaseAuthorityLookup, shared bool) error {
	if tx == nil {
		return releaseAuthorityStoreRejected("authority transaction is unavailable")
	}
	lockFunction := "pg_advisory_xact_lock"
	if shared {
		lockFunction = "pg_advisory_xact_lock_shared"
	}
	lockIdentity := strings.Join([]string{
		lookup.ScopeKind, lookup.TenantID, lookup.WorkspaceID,
		lookup.ConnectorID, lookup.ConnectorVersion,
	}, "\x1f")
	if _, err := tx.ExecContext(ctx, `SELECT `+lockFunction+`(hashtextextended($1, 0))`, lockIdentity); err != nil {
		return fmt.Errorf("lock connector release authority head: %w", err)
	}
	return nil
}

func queryCurrentReleaseAuthority(ctx context.Context, tx *sql.Tx, lookup ReleaseAuthorityLookup) (releaseAuthorityRecord, error) {
	query := `SELECT ` + releaseAuthorityRecordColumns + `
		FROM connector_release_authorities
		WHERE scope_kind = $1 AND tenant_id = $2 AND workspace_id = $3
		  AND connector_id = $4 AND connector_version = $5
		ORDER BY registry_revision DESC
		LIMIT 1`
	return scanReleaseAuthorityRecord(tx.QueryRowContext(ctx, query,
		lookup.ScopeKind, lookup.TenantID, lookup.WorkspaceID,
		lookup.ConnectorID, lookup.ConnectorVersion,
	))
}

type releaseAuthorityRowScanner interface {
	Scan(...any) error
}

func scanReleaseAuthorityRecord(row releaseAuthorityRowScanner) (releaseAuthorityRecord, error) {
	var record releaseAuthorityRecord
	var scopeKind, tenantID, workspaceID, connectorID, connectorVersion string
	var revision uint64
	var state, authorityHash, signature string
	var previousHash, revokesHash sql.NullString
	var signedAt, validFrom time.Time
	var validUntil sql.NullTime
	var envelopeJSON []byte
	if err := row.Scan(
		&scopeKind, &tenantID, &workspaceID, &connectorID, &connectorVersion,
		&revision, &state, &authorityHash, &previousHash, &revokesHash,
		&signedAt, &validFrom, &validUntil, &envelopeJSON, &signature, &record.CreatedAt,
	); err != nil {
		return releaseAuthorityRecord{}, err
	}
	envelope, err := decodeReleaseAuthorityEnvelope(envelopeJSON)
	if err != nil {
		return releaseAuthorityRecord{}, err
	}
	authority := envelope.Authority
	if authority.ScopeKind != scopeKind || authority.TenantID != tenantID || authority.WorkspaceID != workspaceID ||
		authority.ConnectorID != connectorID || authority.ConnectorVersion != connectorVersion ||
		authority.RegistryRevision != revision || authority.State != state || authority.AuthorityHash != authorityHash ||
		authority.PreviousAuthorityHash != previousHash.String || authority.RevokesAuthorityHash != revokesHash.String ||
		!authority.SignedAt.Equal(signedAt) || !authority.ValidFrom.Equal(validFrom) ||
		!equalOptionalReleaseAuthorityTime(authority.ValidUntil, validUntil) || envelope.Signature != signature {
		return releaseAuthorityRecord{}, releaseAuthorityStoreRejected("database shadow columns do not match signed envelope")
	}
	record.Envelope = envelope
	return record, nil
}

func decodeReleaseAuthorityEnvelope(payload []byte) (contracts.ConnectorReleaseAuthorityEnvelope, error) {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var envelope contracts.ConnectorReleaseAuthorityEnvelope
	if err := decoder.Decode(&envelope); err != nil {
		return contracts.ConnectorReleaseAuthorityEnvelope{}, releaseAuthorityStoreRejected("decode stored envelope: " + err.Error())
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return contracts.ConnectorReleaseAuthorityEnvelope{}, releaseAuthorityStoreRejected("stored envelope has trailing data")
	}
	return envelope, nil
}

func validateStoredReleaseAuthority(record releaseAuthorityRecord, verifier ReleaseAuthorityEnvelopeVerifier) error {
	if verifier == nil {
		return releaseAuthorityStoreRejected("verifier is not configured")
	}
	if record.CreatedAt.IsZero() {
		return releaseAuthorityStoreRejected("stored authority is missing created_at")
	}
	if err := verifier.VerifyEnvelope(record.Envelope); err != nil {
		return err
	}
	return nil
}

func sameConnectorReleaseMaterial(a, b contracts.ConnectorReleaseAuthority) bool {
	return a.SchemaVersion == b.SchemaVersion && a.ContractVersion == b.ContractVersion &&
		a.AuthorityID == b.AuthorityID && a.Algorithm == b.Algorithm &&
		a.ScopeKind == b.ScopeKind && a.TenantID == b.TenantID && a.WorkspaceID == b.WorkspaceID &&
		a.ConnectorID == b.ConnectorID && a.ConnectorVersion == b.ConnectorVersion &&
		a.ConnectorExecutorKind == b.ConnectorExecutorKind &&
		a.ConnectorSandboxProfile == b.ConnectorSandboxProfile &&
		a.ConnectorDriftPolicyRef == b.ConnectorDriftPolicyRef &&
		a.ConnectorBinaryHash == b.ConnectorBinaryHash &&
		a.ConnectorSignatureRef == b.ConnectorSignatureRef &&
		a.ConnectorSignatureHash == b.ConnectorSignatureHash &&
		a.ConnectorSignerID == b.ConnectorSignerID &&
		a.CertificationRef == b.CertificationRef &&
		a.CertificationHash == b.CertificationHash &&
		a.CertificationAuthority == b.CertificationAuthority
}

func equalOptionalReleaseAuthorityTime(value *time.Time, stored sql.NullTime) bool {
	if value == nil {
		return !stored.Valid
	}
	return stored.Valid && value.Equal(stored.Time)
}

func nullableAuthorityHash(value string) any {
	if value == "" {
		return nil
	}
	return value
}

func releaseAuthorityStoreRejected(message string) error {
	return fmt.Errorf("%w: %s", ErrReleaseAuthorityStore, message)
}
