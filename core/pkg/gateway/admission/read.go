package admission

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

// Attempt is the stored effect attempt.
type Attempt struct {
	ID                   string
	WorkspaceID          string
	IdempotencyKey       string
	RequestDigest        []byte
	RequesterPrincipalID string
	RequesterActorID     string
	MandateID            string
	CommitmentID         string
	CaseID               string
	EffectType           string
	Target               string
	TargetDigest         []byte
	ArgumentDigest       []byte
	RiskClass            string
	Quote                []Amount
	State                string
	ReasonCode           string
	Outcome              string
	OutcomeBasis         string
	ApprovalDigest       []byte
	ApprovalExpiresAt    *time.Time
	Permit               *Permit
	Exposures            []Exposure
	LatestObservation    *Observation
	Version              int64
	CreatedAt            time.Time
	UpdatedAt            time.Time
}

// Permit is an attempt's single-use permit.
type Permit struct {
	ID                string
	ArgumentDigest    []byte
	AuthorityVersions []AuthorityVersion
	ExpiresAt         time.Time
	ConsumedAt        *time.Time
	ClaimID           string
	VoidReasonCode    string
}

// AuthorityVersion is one authority row's version at admission. Kind is
// tenant, principal, mandate, effect_type or limit; Key is empty for the
// tenant.
type AuthorityVersion struct {
	Kind    string `json:"kind"`
	Key     string `json:"key,omitempty"`
	Version int64  `json:"version"`
}

// Exposure is the attempt's current load on one counter bucket. BucketStart
// is nil for a limit without a window.
type Exposure struct {
	LimitID     string
	BucketStart *time.Time
	Kind        string
	Amount      int64
}

// Observation is the attempt's latest read of its outcome.
type Observation struct {
	Source         string
	TrustClass     string
	Outcome        string
	EvidenceDigest []byte
	ObservedAt     time.Time
	ResultRef      string
}

// Get returns an attempt of the caller's tenant and workspace. Any other
// attempt, including one of another tenant or workspace, is not found.
func (s *Service) Get(ctx context.Context, caller Caller, attemptID string) (Attempt, error) {
	if err := checkCaller(caller); err != nil {
		return Attempt{}, err
	}
	if err := checkAttemptID(attemptID); err != nil {
		return Attempt{}, err
	}
	var a Attempt
	err := s.inTenant(ctx, caller.TenantID, func(tx *sql.Tx) error {
		var err error
		a, err = loadAttempt(ctx, tx, caller, attemptID)
		return err
	})
	return a, err
}

// GetContent returns the argument bytes of an attempt the caller may read.
func (s *Service) GetContent(ctx context.Context, caller Caller, attemptID string) ([]byte, error) {
	if err := checkCaller(caller); err != nil {
		return nil, err
	}
	if err := checkAttemptID(attemptID); err != nil {
		return nil, err
	}
	var content []byte
	err := s.inTenant(ctx, caller.TenantID, func(tx *sql.Tx) error {
		err := tx.QueryRowContext(ctx, `SELECT c.arguments FROM authority_attempt_contents c
			JOIN authority_effect_attempts a ON a.tenant_id = c.tenant_id AND a.attempt_id = c.attempt_id
			WHERE c.tenant_id = $1 AND c.attempt_id = $2 AND a.workspace_id = $3`,
			caller.TenantID, attemptID, caller.WorkspaceID).Scan(&content)
		if errors.Is(err, sql.ErrNoRows) {
			return errNotFound
		}
		return err
	})
	return content, err
}

func checkAttemptID(id string) error {
	if _, err := uuid.Parse(id); err != nil || strings.ToLower(id) != id || len(id) != 36 {
		return refuse(CodeInvalidArgument, contracts.ReasonSchemaViolation, "attempt_id must be a lowercase UUID")
	}
	return nil
}

// loadAttempt reads the attempt, its permit, exposures and latest
// observation in the caller's transaction.
func loadAttempt(ctx context.Context, tx *sql.Tx, caller Caller, attemptID string) (Attempt, error) {
	var a Attempt
	var mandate, commitment, caseID, risk, outcome, basis sql.NullString
	var quote []byte
	var expires sql.NullTime
	err := tx.QueryRowContext(ctx, `SELECT attempt_id, workspace_id, idempotency_key, request_digest, requester_principal_id,
			requester_actor_id, mandate_id::text, commitment_id, case_id, effect_type, target, target_digest, argument_digest,
			risk_class, quote, state, reason_code, outcome, outcome_basis, approval_digest, approval_expires_at, version,
			created_at, updated_at
		FROM authority_effect_attempts WHERE tenant_id = $1 AND attempt_id = $2 AND workspace_id = $3`,
		caller.TenantID, attemptID, caller.WorkspaceID).Scan(&a.ID, &a.WorkspaceID, &a.IdempotencyKey, &a.RequestDigest,
		&a.RequesterPrincipalID, &a.RequesterActorID, &mandate, &commitment, &caseID, &a.EffectType, &a.Target,
		&a.TargetDigest, &a.ArgumentDigest, &risk, &quote, &a.State, &a.ReasonCode, &outcome, &basis, &a.ApprovalDigest,
		&expires, &a.Version, &a.CreatedAt, &a.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return Attempt{}, errNotFound
	}
	if err != nil {
		return Attempt{}, err
	}
	a.MandateID, a.CommitmentID, a.CaseID = mandate.String, commitment.String, caseID.String
	a.RiskClass, a.Outcome, a.OutcomeBasis = risk.String, outcome.String, basis.String
	a.CreatedAt, a.UpdatedAt = a.CreatedAt.UTC(), a.UpdatedAt.UTC()
	if expires.Valid {
		t := expires.Time.UTC()
		a.ApprovalExpiresAt = &t
	}
	if err := json.Unmarshal(quote, &a.Quote); err != nil {
		return Attempt{}, err
	}

	var p Permit
	var versions []byte
	var consumed sql.NullTime
	var claim, void sql.NullString
	err = tx.QueryRowContext(ctx, `SELECT permit_id, argument_digest, authority_versions, expires_at, consumed_at, claim_id::text, void_reason_code
		FROM authority_permits WHERE tenant_id = $1 AND attempt_id = $2`, caller.TenantID, attemptID).
		Scan(&p.ID, &p.ArgumentDigest, &versions, &p.ExpiresAt, &consumed, &claim, &void)
	switch {
	case errors.Is(err, sql.ErrNoRows):
	case err != nil:
		return Attempt{}, err
	default:
		if err := json.Unmarshal(versions, &p.AuthorityVersions); err != nil {
			return Attempt{}, err
		}
		p.ExpiresAt = p.ExpiresAt.UTC()
		if consumed.Valid {
			t := consumed.Time.UTC()
			p.ConsumedAt = &t
		}
		p.ClaimID, p.VoidReasonCode = claim.String, void.String
		a.Permit = &p
	}

	rows, err := tx.QueryContext(ctx, `SELECT limit_id::text, bucket_start, kind, amount FROM authority_exposures
		WHERE tenant_id = $1 AND attempt_id = $2 ORDER BY limit_id, bucket_start`, caller.TenantID, attemptID)
	if err != nil {
		return Attempt{}, err
	}
	for rows.Next() {
		var x Exposure
		var start time.Time
		if err := rows.Scan(&x.LimitID, &start, &x.Kind, &x.Amount); err != nil {
			_ = rows.Close()
			return Attempt{}, err
		}
		if !start.Equal(time.Unix(0, 0)) {
			start = start.UTC()
			x.BucketStart = &start
		}
		a.Exposures = append(a.Exposures, x)
	}
	if err := rows.Close(); err != nil {
		return Attempt{}, err
	}

	var o Observation
	var observedOutcome sql.NullString
	err = tx.QueryRowContext(ctx, `SELECT source, trust_class, outcome, evidence_digest, observed_at, result_ref
		FROM authority_observations WHERE tenant_id = $1 AND attempt_id = $2 ORDER BY observation_id DESC LIMIT 1`,
		caller.TenantID, attemptID).Scan(&o.Source, &o.TrustClass, &observedOutcome, &o.EvidenceDigest, &o.ObservedAt, &o.ResultRef)
	switch {
	case errors.Is(err, sql.ErrNoRows):
	case err != nil:
		return Attempt{}, err
	default:
		o.Outcome = observedOutcome.String
		o.ObservedAt = o.ObservedAt.UTC()
		a.LatestObservation = &o
	}
	return a, nil
}
