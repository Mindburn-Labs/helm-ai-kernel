// quantum_posture: this test fixture signs and appends classical Ed25519
// connector release authority records; no hybrid or post-quantum claim.
package connectors

// No shipped binary appends a connector release authority (helm-tracker#266):
// the runtime reads the table only through PostgresReleaseAuthorityStore. The
// writer and the signing helper live here so the reader's tests can seed
// signed revisions through the same append-only, head-checked path.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
)

var (
	ErrReleaseAuthorityConflict = errors.New("connector release authority revision conflict")
	ErrReleaseAuthorityTerminal = errors.New("connector release authority is terminally revoked")
)

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

func nullableAuthorityHash(value string) any {
	if value == "" {
		return nil
	}
	return value
}

func SignConnectorReleaseAuthority(authority contracts.ConnectorReleaseAuthority, signer crypto.Signer) (contracts.ConnectorReleaseAuthorityEnvelope, error) {
	if signer == nil {
		return contracts.ConnectorReleaseAuthorityEnvelope{}, releaseAuthorityRejected("signer is not configured")
	}
	payload, err := ConnectorReleaseAuthoritySigningPayload(authority)
	if err != nil {
		return contracts.ConnectorReleaseAuthorityEnvelope{}, err
	}
	signature, err := signer.Sign(payload)
	if err != nil {
		return contracts.ConnectorReleaseAuthorityEnvelope{}, releaseAuthorityRejected("sign authority: " + err.Error())
	}
	envelope := contracts.ConnectorReleaseAuthorityEnvelope{Authority: authority, Signature: signature}
	if err := envelope.Validate(); err != nil {
		return contracts.ConnectorReleaseAuthorityEnvelope{}, releaseAuthorityRejected("signer returned invalid signature encoding")
	}
	return envelope, nil
}
