package admission

// quantum_posture: SHA-256 request digests for idempotency; nothing here
// signs or verifies, and no post-quantum claim is made.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/effectargs"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/kernel/authority/mandates"
)

// StopInput is a StopRequest. ScopeKind is tenant, principal, mandate or
// effect_type; ScopeKey is empty for the tenant.
type StopInput struct {
	IdempotencyKey string
	ScopeKind      string
	ScopeKey       string
	Reason         string
	ExpiresAt      *time.Time
}

// Stop is a stop row. ScopeKey is empty for the tenant scope.
type Stop struct {
	ID        string
	ScopeKind string
	ScopeKey  string
	Reason    string
	IssuedBy  string
	CreatedAt time.Time
	ExpiresAt *time.Time
	LiftedAt  *time.Time
}

// LiftInput is a LiftRequest.
type LiftInput struct {
	IdempotencyKey string
	StopID         string
	MandateID      string
}

const maxStopReasonBytes = 1024

// Stop writes a stop and bumps its scope's control row in one transaction
// (ADR-0001 §1: narrowing needs no approval). Admissions after the commit are
// DENIED and admitted attempts are CANCELLED at their dispatch claim, both
// EMERGENCY_STOP_FENCED; a call already dispatched is not retracted.
//
// The caller is an active human operator of the tenant with a single-use
// helm.gateway.stop token. The same idempotency key and request return the
// stored stop without using up the token, so a retry after a lost answer is
// safe; another request under the key is IDEMPOTENCY_CONFLICT.
func (s *Service) Stop(ctx context.Context, caller Caller, token Token, in StopInput) (Stop, bool, error) {
	if err := checkCaller(caller); err != nil {
		return Stop{}, false, err
	}
	if err := validateStop(caller, &in); err != nil {
		return Stop{}, false, err
	}
	digest := stopDigest(caller, in)
	var stopID string
	var existing bool
	err := s.inTenant(ctx, caller.TenantID, func(tx *sql.Tx) error {
		var stored []byte
		err := tx.QueryRowContext(ctx, `SELECT stop_id::text, request_digest FROM authority_stops
			WHERE tenant_id = $1 AND idempotency_key = $2`, caller.TenantID, in.IdempotencyKey).Scan(&stopID, &stored)
		switch {
		case err == nil && bytes.Equal(stored, digest):
			existing = true
			return nil
		case err == nil:
			return refuse(CodeAlreadyExists, contracts.ReasonIdempotencyConflict, "the idempotency key was used with a different stop")
		case !errors.Is(err, sql.ErrNoRows):
			return err
		}
		if err := consumeToken(ctx, tx, caller.TenantID, token); err != nil {
			return err
		}
		if err := requireActiveHuman(ctx, tx, caller, "an operator"); err != nil {
			return err
		}
		found, err := mandates.BumpControlRow(ctx, tx, caller.TenantID, in.ScopeKind, in.ScopeKey)
		if err != nil {
			return err
		}
		if !found {
			return refuse(CodeNotFound, "", "no %s %q in the tenant", in.ScopeKind, in.ScopeKey)
		}
		id, err := uuid.NewV7()
		if err != nil {
			return err
		}
		stopID = id.String()
		var expires any
		if in.ExpiresAt != nil {
			expires = *in.ExpiresAt
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO authority_stops
				(tenant_id, stop_id, scope_kind, scope_key, reason, issued_by, expires_at, idempotency_key, request_digest)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
			caller.TenantID, id, in.ScopeKind, in.ScopeKey, in.Reason, caller.PrincipalID, expires, in.IdempotencyKey, digest)
		return err
	})
	if err != nil {
		return Stop{}, false, err
	}
	stop, err := s.getStop(ctx, caller.TenantID, stopID)
	return stop, existing, err
}

func validateStop(caller Caller, in *StopInput) error {
	bad := func(format string, args ...any) error {
		return refuse(CodeInvalidArgument, contracts.ReasonSchemaViolation, format, args...)
	}
	if n := len(in.IdempotencyKey); n < 1 || n > 255 || !utf8.ValidString(in.IdempotencyKey) {
		return bad("idempotency_key must be 1 to 255 bytes of UTF-8")
	}
	switch in.ScopeKind {
	case "tenant":
		if in.ScopeKey != "" {
			return bad("a tenant stop names no scope_key: it is always the token's tenant")
		}
		in.ScopeKey = caller.TenantID
	case "principal", "effect_type":
		if strings.TrimSpace(in.ScopeKey) == "" || len(in.ScopeKey) > 255 {
			return bad("scope_key must name the %s", in.ScopeKind)
		}
	case "mandate":
		if checkAttemptID(in.ScopeKey) != nil {
			return bad("a mandate scope_key is a lowercase UUID")
		}
	default:
		return bad("scope_kind must be tenant, principal, mandate or effect_type")
	}
	if n := len(in.Reason); n < 1 || n > maxStopReasonBytes || !utf8.ValidString(in.Reason) {
		return bad("reason must be 1 to %d bytes of UTF-8", maxStopReasonBytes)
	}
	if in.ExpiresAt != nil && !in.ExpiresAt.After(time.Now()) {
		return bad("expires_at must be in the future")
	}
	return nil
}

// stopDigest covers every StopRequest field but the key, and the principal.
func stopDigest(caller Caller, in StopInput) []byte {
	var m bytes.Buffer
	field(&m, []byte("helm.gateway.v1.stop-digest.v1"))
	field(&m, []byte(caller.PrincipalID))
	field(&m, []byte(in.ScopeKind))
	field(&m, []byte(in.ScopeKey))
	field(&m, []byte(in.Reason))
	expires := ""
	if in.ExpiresAt != nil {
		expires = in.ExpiresAt.UTC().Format(time.RFC3339Nano)
	}
	field(&m, []byte(expires))
	sum := sha256.Sum256(m.Bytes())
	return sum[:]
}

func (s *Service) getStop(ctx context.Context, tenantID, stopID string) (Stop, error) {
	var out Stop
	err := s.inTenant(ctx, tenantID, func(tx *sql.Tx) error {
		var expires, lifted sql.NullTime
		if err := tx.QueryRowContext(ctx, `SELECT stop_id::text, scope_kind, scope_key, reason, issued_by, created_at, expires_at, lifted_at
			FROM authority_stops WHERE tenant_id = $1 AND stop_id = $2`, tenantID, stopID).Scan(&out.ID, &out.ScopeKind,
			&out.ScopeKey, &out.Reason, &out.IssuedBy, &out.CreatedAt, &expires, &lifted); err != nil {
			return err
		}
		out.CreatedAt = out.CreatedAt.UTC()
		if out.ScopeKind == "tenant" {
			out.ScopeKey = ""
		}
		if expires.Valid {
			t := expires.Time.UTC()
			out.ExpiresAt = &t
		}
		if lifted.Valid {
			t := lifted.Time.UTC()
			out.LiftedAt = &t
		}
		return nil
	})
	return out, err
}

// Lift proposes lifting a stop. Lifting widens authority, so it is a
// helm.authority.lift attempt (target "stop:<stop_id>") that always needs a
// distinct human approver with step-up (§4.1 item 7, §10.1), and a stop never
// blocks its own lift. The caller is an active human operator with a
// single-use helm.gateway.stop token, which the server has bound to the stop
// (authorization_details helm_stop_lift). A replayed key returns the stored
// attempt without using up the token.
func (s *Service) Lift(ctx context.Context, caller Caller, token Token, in LiftInput) (Attempt, bool, error) {
	if err := checkCaller(caller); err != nil {
		return Attempt{}, false, err
	}
	if checkAttemptID(in.StopID) != nil {
		return Attempt{}, false, refuse(CodeInvalidArgument, contracts.ReasonSchemaViolation, "stop_id must be a lowercase UUID")
	}
	proposal := ProposeInput{
		IdempotencyKey: in.IdempotencyKey, MandateID: in.MandateID, EffectType: effectargs.AuthorityLift,
		Target:    "stop:" + in.StopID,
		Arguments: []byte(`{"schema":"helm.authority.lift.v1","stop_id":"` + in.StopID + `"}`),
	}
	args, err := validateProposal(proposal)
	if err != nil {
		return Attempt{}, false, err
	}
	var attemptID string
	var existing bool
	err = s.inTenant(ctx, caller.TenantID, func(tx *sql.Tx) error {
		if err := requireActiveHuman(ctx, tx, caller, "an operator"); err != nil {
			return err
		}
		var lifted sql.NullTime
		err := tx.QueryRowContext(ctx, `SELECT lifted_at FROM authority_stops WHERE tenant_id = $1 AND stop_id = $2 FOR SHARE`,
			caller.TenantID, in.StopID).Scan(&lifted)
		if errors.Is(err, sql.ErrNoRows) {
			return refuse(CodeNotFound, "", "no such stop in the tenant")
		}
		if err != nil {
			return err
		}
		if attemptID, existing, err = s.proposeTx(ctx, tx, caller, proposal, args); err != nil || existing {
			return err
		}
		if lifted.Valid {
			return refuse(CodeFailedPrecondition, "", "the stop is already lifted")
		}
		return consumeToken(ctx, tx, caller.TenantID, token)
	})
	if err != nil {
		return Attempt{}, false, err
	}
	attempt, err := s.Get(ctx, caller, attemptID)
	return attempt, existing, err
}
