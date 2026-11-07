package admission

// quantum_posture: outcome receipts are signed with classical Ed25519 under
// receipt.v5 and chained with SHA-256 (receipts.go); no hybrid or
// post-quantum protection is provided or claimed.
//
// The outcome of an admitted effect is its external proof of closure
// (helm-tracker#276): every write that records it appends a signed receipt
// in its own transaction, to the same per-(tenant, workspace) chain as the
// decision that admitted it. The outcome states are:
//
//   - OBSERVED: a read-back, or the adapter's own answer, established the
//     outcome (SUCCEEDED or FAILED) while the attempt was DISPATCHING or
//     DISPATCHED; also a model call's late usage confirming an ESTIMATED one;
//   - RECONCILED: the same, established while the attempt was UNKNOWN;
//   - SETTLED: a model call whose provider reported its usage, after it was
//     OBSERVED or RECONCILED in the same transaction.
//
// The writes are settleState (dispatch.go: NOT_SENT, every established
// read-back of Dispatch, Observe, the reconciliation job and the MCP tools,
// and a model call's confirmed, estimated and refused settlement) and a model
// call's SETTLED write (modelcall.go). Both run recordOutcome. Migration 16
// refuses at commit any attempt version that enters one of these states
// without its receipt.
//
// Not outcomes, and not receipted: UNKNOWN and ESCALATED_TO_HUMAN (no outcome
// is known; the reservation stays held), CANCELLED (a refused claim or a
// cancellation: nothing was dispatched), REJECTED and EXPIRED (an escalation
// that was never admitted), and the lifecycle in between (DISPATCHING,
// DISPATCHED). COMPENSATED is in the schema but no code writes it.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/adapters"
)

// outcomeWrite is one outcome an attempt's transaction records.
type outcomeWrite struct {
	tenantID, attemptID string
	from, to            string
	// outcome is SUCCEEDED or FAILED when to is OBSERVED or RECONCILED, and
	// empty for SETTLED, which keeps the stored outcome.
	outcome adapters.Outcome
	reason  contracts.ReasonCode
	// observationID names the stored observation the outcome rests on.
	observationID int64
}

// outcomeColumns is what an outcome write returns of the attempt row.
const outcomeColumns = `workspace_id, version, updated_at, state, reason_code, outcome, outcome_basis, effect_type,
	requester_principal_id, requester_actor_id, mandate_id::text, risk_class, request_digest, target_digest,
	argument_digest, approval_digest, approval_expires_at, quote, episode_id, organization_version_id`

// recordOutcome moves the attempt from state from to an outcome state, bumps
// its version and appends the outcome's signed receipt. OBSERVED and
// RECONCILED set the outcome and its basis (the state itself); SETTLED keeps
// the outcome the same transaction recorded. The receipt describes the row as
// the UPDATE returned it, the permit the effect was dispatched under and the
// stored observation the outcome rests on. The caller holds the attempt row
// and every exposure and counter it moves; the receipt chain is locked last.
func recordOutcome(ctx context.Context, tx *sql.Tx, signer ReceiptSigner, w outcomeWrite) error {
	var row *sql.Row
	switch w.to {
	case "OBSERVED", "RECONCILED":
		if w.outcome != adapters.OutcomeSucceeded && w.outcome != adapters.OutcomeFailed {
			return fmt.Errorf("admission: %s needs a SUCCEEDED or FAILED outcome, not %q", w.to, w.outcome)
		}
		row = tx.QueryRowContext(ctx, `UPDATE authority_effect_attempts
			SET state = $4, outcome = $5, outcome_basis = $4, reason_code = $6, version = version + 1, updated_at = now()
			WHERE tenant_id = $1 AND attempt_id = $2 AND state = $3
			RETURNING `+outcomeColumns, w.tenantID, w.attemptID, w.from, w.to, string(w.outcome), string(w.reason))
	case "SETTLED":
		if w.outcome != "" {
			return errors.New("admission: SETTLED keeps the outcome its transaction recorded")
		}
		row = tx.QueryRowContext(ctx, `UPDATE authority_effect_attempts
			SET state = 'SETTLED', reason_code = $4, version = version + 1, updated_at = now()
			WHERE tenant_id = $1 AND attempt_id = $2 AND state = $3 AND outcome IS NOT NULL
			RETURNING `+outcomeColumns, w.tenantID, w.attemptID, w.from, string(w.reason))
	default:
		return fmt.Errorf("admission: %q is not an outcome state", w.to)
	}
	o := storedOutcome{storedDecision: storedDecision{TenantID: w.tenantID, AttemptID: w.attemptID, FromState: w.from}}
	var outcome, basis, mandate, risk, episode, organizationVersion sql.NullString
	var quote []byte
	var expires sql.NullTime
	err := row.Scan(&o.WorkspaceID, &o.Version, &o.SettledAt, &o.State, &o.ReasonCode, &outcome, &basis, &o.EffectType,
		&o.RequesterPrincipalID, &o.RequesterActorID, &mandate, &risk, &o.RequestDigest, &o.TargetDigest,
		&o.ArgumentDigest, &o.ApprovalDigest, &expires, &quote, &episode, &organizationVersion)
	if errors.Is(err, sql.ErrNoRows) {
		return errors.New("admission: the attempt changed state while its outcome was recorded")
	}
	if err != nil {
		return err
	}
	o.Outcome, o.OutcomeBasis = outcome.String, basis.String
	o.MandateID, o.RiskClass = mandate.String, risk.String
	o.EpisodeID, o.OrganizationVersionID = episode.String, organizationVersion.String
	if expires.Valid {
		t := expires.Time.UTC()
		o.ApprovalExpiresAt = &t
	}
	if err := json.Unmarshal(quote, &o.Quote); err != nil {
		return fmt.Errorf("attempt %s quote: %w", w.attemptID, err)
	}
	// The permit the dispatch claim consumed: the outcome receipt names it and
	// signs the authority versions it was issued under, as the decision
	// receipt that issued it did.
	var versions []byte
	if err := tx.QueryRowContext(ctx, `SELECT permit_id::text, authority_versions FROM authority_permits
		WHERE tenant_id = $1 AND attempt_id = $2`, w.tenantID, w.attemptID).Scan(&o.PermitID, &versions); err != nil {
		return fmt.Errorf("attempt %s permit: %w", w.attemptID, err)
	}
	if err := json.Unmarshal(versions, &o.AuthorityVersions); err != nil {
		return fmt.Errorf("attempt %s permit authority versions: %w", w.attemptID, err)
	}
	ob := &o.Observation
	var observed sql.NullString
	if err := tx.QueryRowContext(ctx, `SELECT observation_id, source, trust_class, outcome, evidence_digest, result_kind, result_ref, observed_at
		FROM authority_observations WHERE tenant_id = $1 AND attempt_id = $2 AND observation_id = $3`,
		w.tenantID, w.attemptID, w.observationID).Scan(&ob.ID, &ob.Source, &ob.TrustClass, &observed, &ob.EvidenceDigest,
		&ob.ResultKind, &ob.ResultRef, &ob.ObservedAt); err != nil {
		return fmt.Errorf("attempt %s observation %d: %w", w.attemptID, w.observationID, err)
	}
	ob.Outcome = observed.String
	_, err = appendReceipt(ctx, tx, signer, o)
	return err
}

// observationOf names the stored observation that holds a provider fact: the
// row an insert just returned, or, when the insert found the fact already
// recorded (the unique evidence index), the row that holds it.
func observationOf(ctx context.Context, tx *sql.Tx, tenantID, attemptID string, inserted sql.NullInt64, evidence []byte) (int64, error) {
	if inserted.Valid {
		return inserted.Int64, nil
	}
	if len(evidence) == 0 {
		return 0, errors.New("admission: an observation without evidence was not recorded")
	}
	var id int64
	err := tx.QueryRowContext(ctx, `SELECT observation_id FROM authority_observations
		WHERE tenant_id = $1 AND attempt_id = $2 AND evidence_digest = $3`, tenantID, attemptID, evidence).Scan(&id)
	return id, err
}
