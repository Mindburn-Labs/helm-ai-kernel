package admission

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/effectargs"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/kernel/authority/mandates"
)

// Token is what a verified decide or stop token contributes to the call it
// authorizes. Those scopes are single-use (proposed ADR-0005 §10): the jti is
// recorded in the operation's own transaction.
type Token struct {
	Issuer    string
	ID        string
	Scope     string
	ExpiresAt time.Time
}

// DecideInput is an ApproveRequest or a RejectRequest.
type DecideInput struct {
	AttemptID      string
	ApprovalDigest []byte
	Reason         string
}

// The scopes that reach Cancel.
const (
	scopePropose = "helm.gateway.propose"
	scopeStop    = "helm.gateway.stop"
)

// maxReasonBytes bounds an approver's reason.
const maxReasonBytes = 2000

// Approve records a distinct human's approval of an ESCALATED attempt and
// re-runs admission with it in the same transaction (ADR-0001 §1 "Approval",
// §5.5): stops, the mandate chain and counters are read again, and the
// attempt becomes ADMITTED or DENIED. A refused precondition (self-approval,
// a digest that differs, a missing step-up, an expired escalation) is an
// error, and the attempt stays ESCALATED. An attempt no longer ESCALATED is
// returned unchanged with existing true.
func (s *Service) Approve(ctx context.Context, caller Caller, token Token, in DecideInput) (Attempt, bool, error) {
	return s.decide(ctx, caller, token, in, true)
}

// Reject records a distinct human's rejection of an ESCALATED attempt, which
// becomes REJECTED (APPROVAL_REJECTED). Nothing was reserved, so nothing is
// released.
func (s *Service) Reject(ctx context.Context, caller Caller, token Token, in DecideInput) (Attempt, bool, error) {
	return s.decide(ctx, caller, token, in, false)
}

func (s *Service) decide(ctx context.Context, caller Caller, token Token, in DecideInput, approve bool) (Attempt, bool, error) {
	if err := checkCaller(caller); err != nil {
		return Attempt{}, false, err
	}
	if err := checkAttemptID(in.AttemptID); err != nil {
		return Attempt{}, false, err
	}
	bad := func(format string, args ...any) error {
		return refuse(CodeInvalidArgument, contracts.ReasonSchemaViolation, format, args...)
	}
	if len(in.ApprovalDigest) != 32 {
		return Attempt{}, false, bad("approval_digest must be 32 bytes")
	}
	if len(in.Reason) > maxReasonBytes || !utf8.ValidString(in.Reason) {
		return Attempt{}, false, bad("reason must be at most %d bytes of UTF-8", maxReasonBytes)
	}
	if !approve && in.Reason == "" {
		return Attempt{}, false, bad("a rejection needs a reason")
	}
	var existing bool
	err := s.inTenant(ctx, caller.TenantID, func(tx *sql.Tx) error {
		if err := consumeToken(ctx, tx, caller.TenantID, token); err != nil {
			return err
		}
		a, err := lockAttempt(ctx, tx, caller, in.AttemptID)
		if err != nil {
			return err
		}
		if a.state != "ESCALATED" {
			existing = true
			return nil
		}
		if caller.PrincipalID == a.requester {
			return refuse(CodePermissionDenied, contracts.ReasonApproverNotDistinct,
				"the approver is the requester; a distinct human must decide")
		}
		if err := requireActiveHuman(ctx, tx, caller, "an approver"); err != nil {
			return err
		}
		if !bytes.Equal(in.ApprovalDigest, a.approvalDigest) {
			return refuse(CodeFailedPrecondition, "", "approval_digest is not the attempt's approval digest")
		}
		if !a.now.Before(a.approvalExpiresAt) {
			return refuse(CodeFailedPrecondition, contracts.ReasonApprovalTimeout, "the escalation expired")
		}
		if approve && needsStepUp(a) {
			return refuse(CodePermissionDenied, contracts.ReasonStepUpRequired,
				"approving a high-risk, irreversible or authority-widening effect needs a step-up assertion")
		}
		decision := "REJECTED"
		if approve {
			decision = "APPROVED"
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO authority_approvals
				(tenant_id, attempt_id, approver_principal_id, approver_actor_id, decision, approval_digest, reason)
			VALUES ($1, $2, $3, $4, $5, $6, $7)`,
			caller.TenantID, a.id, caller.PrincipalID, caller.ActorID, decision, in.ApprovalDigest, in.Reason); err != nil {
			return err
		}
		if !approve {
			return transition(ctx, tx, caller.TenantID, a.id, "ESCALATED", "REJECTED", contracts.ReasonApprovalRejected)
		}
		return s.readmit(ctx, tx, a, &ApprovalState{ApproverID: caller.PrincipalID, Approved: true})
	})
	if err != nil {
		return Attempt{}, false, err
	}
	attempt, err := s.Get(ctx, caller, in.AttemptID)
	return attempt, existing, err
}

// needsStepUp: §10.1 step-up covers high and irreversible effects and
// authority widening (helm.authority.*). A medium effect a mandate escalates
// is approved without it.
func needsStepUp(a lockedAttempt) bool {
	return a.risk == string(mandates.RiskHigh) || a.risk == string(mandates.RiskIrreversible) ||
		strings.HasPrefix(a.effectType, "helm.authority.")
}

// readmit re-runs admission for an ESCALATED attempt with its approval, on
// the request the attempt stored.
func (s *Service) readmit(ctx context.Context, tx *sql.Tx, a lockedAttempt, approval *ApprovalState) error {
	var content []byte
	err := tx.QueryRowContext(ctx, `SELECT arguments FROM authority_attempt_contents WHERE tenant_id = $1 AND attempt_id = $2`,
		a.tenantID, a.id).Scan(&content)
	if errors.Is(err, sql.ErrNoRows) {
		return refuse(CodeFailedPrecondition, contracts.ReasonPreconditionFailed, "the attempt's content is no longer retained")
	}
	if err != nil {
		return err
	}
	args, err := effectargs.Validate(a.effectType, a.target, content)
	if err != nil {
		return err
	}
	in := ProposeInput{
		MandateID: a.mandateID, EffectType: a.effectType, Target: a.target, Arguments: content,
		Quote: a.quote, Distinct: a.distinct,
	}
	requester := Caller{TenantID: a.tenantID, WorkspaceID: a.workspaceID, PrincipalID: a.requester, ActorID: a.requesterActor}
	return s.admit(ctx, tx, requester, in, args, a.id, a.argumentDigest, a.targetDigest, approval, "ESCALATED")
}

// Cancel withdraws an ESCALATED or ADMITTED attempt (ADR-0001 narrowing,
// ADR-0003 release). A propose token cancels only its own principal's
// attempt; a stop token (single-use) lets an active human operator cancel
// another's. ADMITTED voids the permit and releases every held exposure in
// the same transaction. An attempt already DENIED, REJECTED, EXPIRED or
// CANCELLED is returned unchanged with existing true; DISPATCHING or later
// is failed_precondition.
func (s *Service) Cancel(ctx context.Context, caller Caller, token Token, attemptID string) (Attempt, bool, error) {
	if err := checkCaller(caller); err != nil {
		return Attempt{}, false, err
	}
	if err := checkAttemptID(attemptID); err != nil {
		return Attempt{}, false, err
	}
	var existing bool
	err := s.inTenant(ctx, caller.TenantID, func(tx *sql.Tx) error {
		if token.Scope == scopeStop {
			if err := consumeToken(ctx, tx, caller.TenantID, token); err != nil {
				return err
			}
		}
		a, err := lockAttempt(ctx, tx, caller, attemptID)
		if err != nil {
			return err
		}
		switch token.Scope {
		case scopePropose:
			if caller.PrincipalID != a.requester {
				return refuse(CodePermissionDenied, contracts.ReasonInsufficientPrivilege,
					"a propose token cancels only its own principal's attempts; an operator uses a stop token")
			}
		case scopeStop:
			if err := requireActiveHuman(ctx, tx, caller, "an operator"); err != nil {
				return err
			}
		default:
			return refuse(CodePermissionDenied, contracts.ReasonInsufficientPrivilege, "the token's scope does not cover Cancel")
		}
		switch a.state {
		case "DENIED", "REJECTED", "EXPIRED", "CANCELLED":
			existing = true
			return nil
		case "ESCALATED":
			return transition(ctx, tx, caller.TenantID, a.id, "ESCALATED", "CANCELLED", "")
		case "ADMITTED":
			if _, err := tx.ExecContext(ctx, `UPDATE authority_permits SET voided_at = now()
				WHERE tenant_id = $1 AND attempt_id = $2 AND consumed_at IS NULL AND voided_at IS NULL`,
				caller.TenantID, a.id); err != nil {
				return err
			}
			if err := release(ctx, tx, caller.TenantID, a.id, "cancel"); err != nil {
				return err
			}
			return transition(ctx, tx, caller.TenantID, a.id, "ADMITTED", "CANCELLED", "")
		}
		return refuse(CodeFailedPrecondition, "", "an attempt in %s can no longer be cancelled; a dispatched call cannot be retracted", a.state)
	})
	if err != nil {
		return Attempt{}, false, err
	}
	attempt, err := s.Get(ctx, caller, attemptID)
	return attempt, existing, err
}

// transition moves the attempt from one state to another and bumps its
// version.
func transition(ctx context.Context, tx *sql.Tx, tenantID, attemptID, from, to string, reason contracts.ReasonCode) error {
	res, err := tx.ExecContext(ctx, `UPDATE authority_effect_attempts SET state = $4, reason_code = $5, version = version + 1, updated_at = now()
		WHERE tenant_id = $1 AND attempt_id = $2 AND state = $3`, tenantID, attemptID, from, to, string(reason))
	if err != nil {
		return err
	}
	if n, err := res.RowsAffected(); err != nil || n != 1 {
		return errors.New("admission: the attempt changed state during the transition")
	}
	return nil
}

// release moves every held exposure of the attempt to released: the counter
// gives the amount back, and a reversing posting records it (ADR-0003, a
// lower-exposure transition in the transaction that makes it).
func release(ctx context.Context, tx *sql.Tx, tenantID, attemptID, cause string) error {
	rows, err := tx.QueryContext(ctx, `SELECT limit_id::text, bucket_start, amount FROM authority_exposures
		WHERE tenant_id = $1 AND attempt_id = $2 AND kind = 'held'
		ORDER BY limit_id, bucket_start FOR UPDATE`, tenantID, attemptID)
	if err != nil {
		return err
	}
	type held struct {
		limitID string
		start   time.Time
		amount  int64
	}
	var exposures []held
	for rows.Next() {
		var h held
		if err := rows.Scan(&h.limitID, &h.start, &h.amount); err != nil {
			_ = rows.Close()
			return err
		}
		exposures = append(exposures, h)
	}
	if err := rows.Close(); err != nil {
		return err
	}
	for _, h := range exposures {
		if _, err := tx.ExecContext(ctx, `UPDATE authority_counters SET reserved = reserved - $4
			WHERE tenant_id = $1 AND limit_id = $2 AND bucket_start = $3`, tenantID, h.limitID, h.start, h.amount); err != nil {
			return err
		}
		if h.amount != 0 {
			if _, err := tx.ExecContext(ctx, `INSERT INTO authority_postings (tenant_id, attempt_id, limit_id, bucket_start, kind, amount, cause)
				VALUES ($1, $2, $3, $4, 'held', $5, $6)`, tenantID, attemptID, h.limitID, h.start, -h.amount, "reverse:"+cause); err != nil {
				return err
			}
		}
		if _, err := tx.ExecContext(ctx, `UPDATE authority_exposures SET kind = 'released', amount = 0
			WHERE tenant_id = $1 AND attempt_id = $2 AND limit_id = $3 AND bucket_start = $4`,
			tenantID, attemptID, h.limitID, h.start); err != nil {
			return err
		}
	}
	return nil
}

// consumeToken records a single-use token's jti in the caller's transaction,
// after purging the tenant's rows whose token has expired past the skew
// allowance. A jti already recorded is refused. A refused call rolls the
// record back with everything else, so only an accepted operation uses up
// its token.
func consumeToken(ctx context.Context, tx *sql.Tx, tenantID string, token Token) error {
	if token.ID == "" || token.Issuer == "" || token.ExpiresAt.IsZero() {
		return refuse(CodePermissionDenied, contracts.ReasonInsufficientPrivilege, "a single-use token needs iss, jti and exp")
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM authority_token_replay
		WHERE tenant_id = $1 AND expires_at < now() - interval '30 seconds'`, tenantID); err != nil {
		return err
	}
	res, err := tx.ExecContext(ctx, `INSERT INTO authority_token_replay (tenant_id, issuer, jti, scope, expires_at)
		VALUES ($1, $2, $3, $4, $5) ON CONFLICT DO NOTHING`, tenantID, token.Issuer, token.ID, token.Scope, token.ExpiresAt)
	if err != nil {
		return err
	}
	if n, err := res.RowsAffected(); err != nil || n != 1 {
		return refuse(CodePermissionDenied, contracts.ReasonInsufficientPrivilege, "the token was already used; decide and stop tokens are single-use")
	}
	return nil
}

// requireActiveHuman: approvers and operators are active human principals of
// the tenant, per the gateway's own principal rows, never a token claim.
func requireActiveHuman(ctx context.Context, tx *sql.Tx, caller Caller, role string) error {
	var kind, status string
	err := tx.QueryRowContext(ctx, `SELECT kind, status FROM authority_principals WHERE tenant_id = $1 AND principal_id = $2`,
		caller.TenantID, caller.PrincipalID).Scan(&kind, &status)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && (kind != string(mandates.PrincipalHuman) || status != "active")) {
		return refuse(CodePermissionDenied, contracts.ReasonInsufficientPrivilege, "%s must be an active human principal of the tenant", role)
	}
	return err
}

// lockedAttempt is an attempt row locked FOR UPDATE, with the database time.
type lockedAttempt struct {
	tenantID, id, workspaceID       string
	requester, requesterActor       string
	state, risk, effectType, target string
	mandateID                       string
	approvalDigest                  []byte
	approvalExpiresAt, now          time.Time
	argumentDigest, targetDigest    []byte
	quote                           []Amount
	distinct                        []DistinctValue
}

func lockAttempt(ctx context.Context, tx *sql.Tx, caller Caller, attemptID string) (lockedAttempt, error) {
	a := lockedAttempt{tenantID: caller.TenantID}
	var risk, mandate sql.NullString
	var expires sql.NullTime
	var quote, distinct []byte
	err := tx.QueryRowContext(ctx, `SELECT attempt_id, workspace_id, requester_principal_id, requester_actor_id, state, risk_class,
			effect_type, target, mandate_id::text, approval_digest, approval_expires_at, argument_digest, target_digest,
			quote, distinct_values, now()
		FROM authority_effect_attempts WHERE tenant_id = $1 AND attempt_id = $2 AND workspace_id = $3 FOR UPDATE`,
		caller.TenantID, attemptID, caller.WorkspaceID).Scan(&a.id, &a.workspaceID, &a.requester, &a.requesterActor, &a.state, &risk,
		&a.effectType, &a.target, &mandate, &a.approvalDigest, &expires, &a.argumentDigest, &a.targetDigest, &quote, &distinct, &a.now)
	if errors.Is(err, sql.ErrNoRows) {
		return a, errNotFound
	}
	if err != nil {
		return a, err
	}
	a.risk, a.mandateID, a.approvalExpiresAt = risk.String, mandate.String, expires.Time
	if err := json.Unmarshal(quote, &a.quote); err != nil {
		return a, err
	}
	var stored []storedDistinct
	if err := json.Unmarshal(distinct, &stored); err != nil {
		return a, err
	}
	for _, d := range stored {
		a.distinct = append(a.distinct, DistinctValue{Unit: d.Unit, Digest: d.Digest})
	}
	return a, nil
}
