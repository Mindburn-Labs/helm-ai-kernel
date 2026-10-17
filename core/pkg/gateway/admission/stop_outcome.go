package admission

import (
	"context"
	"database/sql"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

// StopOutcome is one workspace's current ledger snapshot under a principal
// Stop. The five attempt-ID sets are sorted and disjoint. They describe
// attempts proposed by, or carried by, the stopped principal; they do not
// attribute an attempt to this specific Stop when multiple Stops overlap.
//
// AwaitingClaimAttemptIDs have not yet been voided. If the Stop stays active,
// their claim will void their permits and release held exposure. A claimed
// effect may have reached its provider: CheckingAttemptIDs are never cancelled
// by Stop. HumanReviewAttemptIDs need a human after inconclusive read-back.
type StopOutcome struct {
	Stop                       Stop
	Active                     bool
	BlockedAdmissionAttemptIDs []string
	AwaitingClaimAttemptIDs    []string
	VoidedAtClaimAttemptIDs    []string
	CheckingAttemptIDs         []string
	HumanReviewAttemptIDs      []string
}

// StopOutcome reads a principal Stop and its scope-matching attempts in one
// repeatable-read snapshot. The Stop is tenant-scoped; attempt sets are limited
// to the caller's workspace. An episode token cannot read the other attempts
// of its principal. Other Stop scopes need their own exact attempt selector.
func (s *Service) StopOutcome(ctx context.Context, caller Caller, stopID string) (StopOutcome, error) {
	if err := checkCaller(caller); err != nil {
		return StopOutcome{}, err
	}
	if caller.Episode != nil {
		return StopOutcome{}, refuse(CodePermissionDenied, contracts.ReasonInsufficientPrivilege,
			"an episode token cannot read a principal Stop outcome")
	}
	if err := checkAttemptID(stopID); err != nil {
		return StopOutcome{}, err
	}
	out := StopOutcome{
		BlockedAdmissionAttemptIDs: []string{},
		AwaitingClaimAttemptIDs:    []string{},
		VoidedAtClaimAttemptIDs:    []string{},
		CheckingAttemptIDs:         []string{},
		HumanReviewAttemptIDs:      []string{},
	}
	err := s.inTenantWith(ctx, caller.TenantID, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true}, func(tx *sql.Tx) error {
		var err error
		out.Stop, out.Active, err = readStop(ctx, tx, caller.TenantID, stopID)
		if err != nil {
			return err
		}
		if out.Stop.ScopeKind != "principal" {
			return refuse(CodeFailedPrecondition, "", "StopOutcome requires a principal Stop")
		}
		rows, err := tx.QueryContext(ctx, `SELECT a.attempt_id::text, a.state,
			p.voided_at, p.void_reason_code
			FROM authority_effect_attempts a
			LEFT JOIN authority_permits p ON p.tenant_id = a.tenant_id AND p.attempt_id = a.attempt_id
			WHERE a.tenant_id = $1 AND a.workspace_id = $2
				AND (a.requester_principal_id = $3 OR a.requester_actor_id = $3)
				AND (a.state IN ('ADMITTED', 'DISPATCHING', 'DISPATCHED', 'UNKNOWN', 'ESCALATED_TO_HUMAN')
					OR (a.state IN ('DENIED', 'CANCELLED') AND a.reason_code = $4))
			ORDER BY a.attempt_id`, caller.TenantID, caller.WorkspaceID, out.Stop.ScopeKey,
			string(contracts.ReasonEmergencyStopFenced))
		if err != nil {
			return err
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var id, state string
			var voided sql.NullTime
			var voidReason sql.NullString
			if err := rows.Scan(&id, &state, &voided, &voidReason); err != nil {
				return err
			}
			switch state {
			case "DENIED":
				out.BlockedAdmissionAttemptIDs = append(out.BlockedAdmissionAttemptIDs, id)
			case "ADMITTED":
				out.AwaitingClaimAttemptIDs = append(out.AwaitingClaimAttemptIDs, id)
			case "CANCELLED":
				if voided.Valid && voidReason.String == string(contracts.ReasonEmergencyStopFenced) {
					out.VoidedAtClaimAttemptIDs = append(out.VoidedAtClaimAttemptIDs, id)
				}
			case "DISPATCHING", "DISPATCHED", "UNKNOWN":
				out.CheckingAttemptIDs = append(out.CheckingAttemptIDs, id)
			case "ESCALATED_TO_HUMAN":
				out.HumanReviewAttemptIDs = append(out.HumanReviewAttemptIDs, id)
			}
		}
		return rows.Err()
	})
	return out, err
}
