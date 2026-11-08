package admission

// quantum_posture: outcome receipts are signed with classical Ed25519 under
// receipt.v5 and chained with SHA-256 (receipts.go); the usage digest is
// SHA-256 over the RFC 8785 form. No hybrid or post-quantum protection is
// provided or claimed.
//
// The outcome of an admitted effect is its external proof of closure
// (helm-tracker#276): every write that records it appends a signed receipt
// in its own transaction, to the same per-(tenant, workspace) chain as the
// decision that admitted it. The outcome states are:
//
//   - OBSERVED: a read-back, or the adapter's own NOT_SENT answer, established
//     the outcome (SUCCEEDED or FAILED) while the attempt was DISPATCHING or
//     DISPATCHED; also a model call's settlement, and its late usage
//     re-settling an estimated OBSERVED call at a new version;
//   - RECONCILED: the same, established while the attempt was UNKNOWN;
//   - SETTLED: a model call whose provider reported its usage, after it was
//     OBSERVED or RECONCILED in the same transaction.
//
// Every one of these writes is recordOutcome, called from recordDispatch
// (NOT_SENT), recordObservation (every established read-back of Dispatch,
// Observe, the reconciliation job and the MCP tools) and settleModelCallTx (a
// model call's confirmed, estimated and refused settlement, and its SETTLED
// write). Migration 16 refuses at commit any attempt version that enters one
// of these states without its receipt.
//
// An outcome receipt signs its own closed document,
// helm.gateway.outcome-binding.v1, not the decision's receipt-binding.v1: the
// attempt core that ties it to the decision (tenant, workspace, attempt,
// version, states, effect type, digests, permit and the authority versions
// the permit was issued under), the outcome, the stored observation it rests
// on, and the settlement facts as the ledger holds them after the write (what
// the outcome did to the reservation, every exposure, and a model call's
// money row and usage digest).
//
// Not outcomes, and not receipted: UNKNOWN and ESCALATED_TO_HUMAN (no outcome
// is known; an effect's reservation stays held, but a cut model call's hold
// has moved to estimated, budget spent as an estimate, and that estimate is
// receipted only when a provider confirmation reconciles the call, RECONCILED
// then SETTLED, or never if none arrives), CANCELLED (a refused claim or a
// cancellation: nothing was dispatched), REJECTED and EXPIRED (an escalation
// that was never admitted), and the lifecycle in between (DISPATCHING,
// DISPATCHED). COMPENSATED is in the schema but no code writes it.

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/adapters"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/receiptverify"
)

// OutcomeBindingVersion names the closed document whose SHA-256 an outcome
// receipt signs as output_hash. Its JSON schema is
// protocols/json-schemas/gateway/outcome-binding.v1.schema.json; the verifier
// owns the one definition of its shape (receiptverify).
const OutcomeBindingVersion = receiptverify.GatewayOutcomeBindingVersion

// What established an outcome.
const (
	settledByReadback  = "readback"
	settledByNotSent   = "not_sent"
	settledByModelCall = "model_call"
)

// outcomeFrom is every (from state, outcome state) pair an outcome write
// makes. OBSERVED to OBSERVED is a model call's late usage re-settling an
// estimated call.
var outcomeFrom = map[string]map[string]bool{
	"OBSERVED":   {"DISPATCHING": true, "DISPATCHED": true, "OBSERVED": true},
	"RECONCILED": {"UNKNOWN": true},
	"SETTLED":    {"OBSERVED": true, "RECONCILED": true},
}

// storedOutcome is the attempt row an outcome write left, as UPDATE ...
// RETURNING gave it back, with the permit it was dispatched under, the
// observation it rests on and the settlement as the ledger holds it after
// the write. Only the attempt core of the embedded storedDecision is used:
// its decision-only members (approver, step-up proof, decision time, quote,
// requester, mandate, approval, episode) stay unset and are not signed.
type storedOutcome struct {
	storedDecision
	Outcome, OutcomeBasis string
	SettledBy             string
	// ReadbackAbsent: a read-back established FAILED by the object's absence.
	ReadbackAbsent bool
	// Reservation is the exposure kind the write moved the attempt's held
	// reservation to: confirmed, released or estimated.
	Reservation string
	Exposures   []Exposure
	ModelCall   *settledModelCall
	Observation boundObservation
	SettledAt   time.Time
}

// boundObservation is the stored observation an outcome receipt binds.
type boundObservation struct {
	ID                    int64
	Source, TrustClass    string
	Outcome               string
	EvidenceDigest        []byte
	ResultKind, ResultRef string
	ObservedAt            time.Time
}

// settledModelCall is a model call's money row after its settlement. Its
// amounts are micro-units of CurrencyCode. UsageDigest is the SHA-256 of the
// RFC 8785 form of the usage the row stores, nil when it stores none.
type settledModelCall struct {
	State           string
	CurrencyCode    string
	HeldMicros      int64
	EstimatedMicros *int64
	ConfirmedMicros *int64
	BillableMicros  int64
	UsageDigest     []byte
}

func (o storedOutcome) row() (string, string, string, int64, string) {
	return o.TenantID, o.WorkspaceID, o.AttemptID, o.Version, o.State
}

func (o storedOutcome) build(receiptID string, seq uint64, prevDigest string) (*contracts.Receipt, []byte, error) {
	return buildOutcomeReceipt(o, receiptID, seq, prevDigest)
}

// outcomeBinding is helm.gateway.outcome-binding.v1. Its one definition is
// receiptverify.GatewayOutcomeBinding, which receipt_verify parses as a closed
// document: every member is always present, model_call is null for an effect
// that is not a model call, and amounts are decimal strings (empty for an
// amount the ledger does not hold).
type outcomeBinding = receiptverify.GatewayOutcomeBinding

type outcomeObservation = receiptverify.GatewayOutcomeObservation

type bindingExposure = receiptverify.GatewayOutcomeExposure

type bindingModelCall = receiptverify.GatewayOutcomeModelCall

func decimal(v *int64) string {
	if v == nil {
		return ""
	}
	return strconv.FormatInt(*v, 10)
}

// checkSettlement refuses settlement facts that do not fit how the outcome
// was established.
func checkSettlement(o storedOutcome) error {
	for _, x := range o.Exposures {
		if x.Kind != o.Reservation {
			return fmt.Errorf("the outcome moved the reservation to %s, but an exposure is %s", o.Reservation, x.Kind)
		}
	}
	if o.ReadbackAbsent && (o.SettledBy != settledByReadback || o.Outcome != string(adapters.OutcomeFailed) || o.Reservation != "released") {
		return errors.New("only a read-back that released the reservation establishes FAILED by absence")
	}
	switch o.SettledBy {
	case settledByNotSent:
		if o.FromState != "DISPATCHING" || o.State != "OBSERVED" || o.Outcome != string(adapters.OutcomeFailed) || o.Reservation != "released" {
			return errors.New("NOT_SENT is a DISPATCHING attempt OBSERVED to have FAILED, its reservation released")
		}
	case settledByReadback:
		if o.State == "SETTLED" || o.FromState == "DISPATCHING" || o.FromState == o.State ||
			(o.Reservation != "confirmed" && o.Reservation != "released") {
			return errors.New("a read-back settles a DISPATCHED or UNKNOWN attempt and confirms or releases its reservation")
		}
	case settledByModelCall:
		m := o.ModelCall
		if m == nil {
			return errors.New("a model call's outcome binds its money row")
		}
		want := map[string]string{SettlementConfirmed: "confirmed", SettlementEstimated: "estimated", SettlementReleased: "released"}[m.State]
		if want == "" || want != o.Reservation || (m.State == SettlementReleased) != (o.Outcome == string(adapters.OutcomeFailed)) {
			return fmt.Errorf("a model call settled %s cannot move its reservation to %s with outcome %s", m.State, o.Reservation, o.Outcome)
		}
		if (o.State == "SETTLED" || o.FromState == o.State) && m.State != SettlementConfirmed {
			return errors.New("only a confirmed model call is SETTLED or re-settled by its late usage")
		}
		if n := len(m.UsageDigest); n != 0 && n != sha256.Size {
			return errors.New("the usage digest is not a SHA-256 digest")
		}
		if len(m.CurrencyCode) != 3 {
			return fmt.Errorf("a model call's amounts are micro-units of a three-letter currency, not %q", m.CurrencyCode)
		}
	default:
		return fmt.Errorf("an outcome is settled by a read-back, a NOT_SENT answer or a model call, not %q", o.SettledBy)
	}
	if o.SettledBy != settledByModelCall && o.ModelCall != nil {
		return errors.New("only a model call's outcome binds a money row")
	}
	if o.FromState == o.State && o.SettledBy != settledByModelCall {
		return errors.New("only a model call's late usage re-settles an outcome")
	}
	return nil
}

// buildOutcomeReceipt maps a stored outcome to its unsigned receipt and the
// exact bytes of its outcome-binding.v1 document. The receipt's status is the
// outcome state, its verdict empty, its policy_hash that of the authority
// versions the permit was issued under (the admitting decision receipt's),
// args_hash the exact-argument digest and output_hash the binding's SHA-256.
// It is pure: the receipt id, the sequence number and the predecessor digest
// come from the caller.
func buildOutcomeReceipt(o storedOutcome, receiptID string, seq uint64, prevDigest string) (*contracts.Receipt, []byte, error) {
	from, ok := outcomeFrom[o.State]
	switch {
	case !ok:
		return nil, nil, fmt.Errorf("state %q is not an outcome a receipt records", o.State)
	case !from[o.FromState]:
		return nil, nil, fmt.Errorf("no outcome write moves an attempt from %s to %s", o.FromState, o.State)
	case o.Outcome != string(adapters.OutcomeSucceeded) && o.Outcome != string(adapters.OutcomeFailed):
		return nil, nil, fmt.Errorf("an outcome receipt records SUCCEEDED or FAILED, not %q", o.Outcome)
	case o.OutcomeBasis != "OBSERVED" && o.OutcomeBasis != "RECONCILED",
		o.State != "SETTLED" && o.State != o.OutcomeBasis:
		return nil, nil, fmt.Errorf("state %s cannot rest on outcome basis %q", o.State, o.OutcomeBasis)
	case o.Observation.ID <= 0 || o.Observation.Source == "" || o.Observation.TrustClass == "" || o.Observation.ObservedAt.IsZero():
		return nil, nil, errors.New("an outcome receipt needs the stored observation it rests on")
	case o.Observation.Outcome != o.Outcome:
		return nil, nil, fmt.Errorf("the observation records %q, the outcome is %s", o.Observation.Outcome, o.Outcome)
	case seq == 0 || (seq == 1) != (prevDigest == "") || (prevDigest != "" && !isChainDigest(prevDigest)):
		return nil, nil, fmt.Errorf("receipt %d of a chain cannot link to %q", seq, prevDigest)
	case o.TenantID == "" || o.WorkspaceID == "" || o.AttemptID == "" || o.Version <= 0 || o.SettledAt.IsZero() || o.PermitID == "":
		return nil, nil, errors.New("an outcome receipt needs the stored tenant, workspace, attempt, version, settlement time and permit")
	}
	if err := checkSettlement(o); err != nil {
		return nil, nil, err
	}
	request, err := digestHex("request_digest", o.RequestDigest, false)
	if err != nil {
		return nil, nil, err
	}
	target, err := digestHex("target_digest", o.TargetDigest, false)
	if err != nil {
		return nil, nil, err
	}
	argument, err := digestHex("argument_digest", o.ArgumentDigest, false)
	if err != nil {
		return nil, nil, err
	}
	evidence, err := digestHex("evidence_digest", o.Observation.EvidenceDigest, true)
	if err != nil {
		return nil, nil, err
	}
	policyHash, err := authoritySnapshotHash(o.AuthorityVersions)
	if err != nil {
		return nil, nil, err
	}
	exposures := make([]bindingExposure, 0, len(o.Exposures))
	for _, x := range o.Exposures {
		start := ""
		if x.BucketStart != nil {
			start = x.BucketStart.UTC().Format(time.RFC3339Nano)
		}
		exposures = append(exposures, bindingExposure{LimitID: x.LimitID, BucketStart: start, Kind: x.Kind, Amount: strconv.FormatInt(x.Amount, 10)})
	}
	var model *bindingModelCall
	if m := o.ModelCall; m != nil {
		usage, err := digestHex("usage_digest", m.UsageDigest, true)
		if err != nil {
			return nil, nil, err
		}
		model = &bindingModelCall{State: m.State, CurrencyCode: m.CurrencyCode, HeldMicros: strconv.FormatInt(m.HeldMicros, 10), EstimatedMicros: decimal(m.EstimatedMicros),
			ConfirmedMicros: decimal(m.ConfirmedMicros), BillableMicros: strconv.FormatInt(m.BillableMicros, 10), UsageDigest: usage}
	}
	chain := receiptChainID(o.TenantID, o.WorkspaceID)
	ob := o.Observation
	binding, err := canonicalize.InteroperableJCS(outcomeBinding{
		BindingVersion: OutcomeBindingVersion, ChainID: chain, Seq: seq,
		TenantID: o.TenantID, WorkspaceID: o.WorkspaceID, AttemptID: o.AttemptID, AttemptVersion: o.Version,
		FromState: o.FromState, State: o.State, ReasonCode: o.ReasonCode, EffectType: o.EffectType,
		RequestDigest: request, TargetDigest: target, ArgumentDigest: argument,
		PermitID: o.PermitID, AuthorityVersions: bindingVersions(o.AuthorityVersions), PolicyHash: policyHash,
		Outcome: o.Outcome, OutcomeBasis: o.OutcomeBasis, SettledBy: o.SettledBy,
		Observation: outcomeObservation{ID: ob.ID, Source: ob.Source, TrustClass: ob.TrustClass, Outcome: ob.Outcome,
			EvidenceDigest: evidence, ResultKind: ob.ResultKind, ResultRef: ob.ResultRef,
			ObservedAt: ob.ObservedAt.UTC().Format(time.RFC3339Nano)},
		Reservation: o.Reservation, ReadbackAbsent: o.ReadbackAbsent, Exposures: exposures, ModelCall: model,
		SettledAt: o.SettledAt.UTC().Format(time.RFC3339Nano),
	})
	if err != nil {
		return nil, nil, fmt.Errorf("outcome binding: %w", err)
	}
	sum := sha256.Sum256(binding)
	// receipt.v5 as a decision receipt fills it (receipts.go), with the
	// outcome state as status and no verdict.
	return &contracts.Receipt{
		ReceiptID: receiptID, DecisionID: o.AttemptID + ":" + strconv.FormatInt(o.Version, 10), EffectID: o.AttemptID,
		Status: o.State, OutputHash: hex.EncodeToString(sum[:]), Timestamp: o.SettledAt.UTC(),
		PrevHash: prevDigest, LamportClock: seq, ArgsHash: argument, ReasonCode: o.ReasonCode,
		PolicyHash: policyHash, SessionID: chain,
	}, binding, nil
}

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
	// settledBy, readbackAbsent and reservation say how the outcome was
	// established and what it did to the held reservation; the exposures
	// and a model call's money row are read back from the ledger.
	settledBy      string
	readbackAbsent bool
	reservation    string
}

// outcomeColumns is what an outcome write returns of the attempt row.
const outcomeColumns = `workspace_id, version, updated_at, state, reason_code, outcome, outcome_basis, effect_type,
	request_digest, target_digest, argument_digest`

// recordOutcome moves the attempt from state from to an outcome state, bumps
// its version and appends the outcome's signed receipt. OBSERVED and
// RECONCILED set the outcome and its basis (the state itself); SETTLED keeps
// the outcome the same transaction recorded. The receipt describes the row as
// the UPDATE returned it, the permit the effect was dispatched under, the
// stored observation the outcome rests on and the settlement as the ledger
// holds it. The caller holds the attempt row and every exposure and counter
// it moves; the receipt chain is locked last.
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
	o := storedOutcome{storedDecision: storedDecision{TenantID: w.tenantID, AttemptID: w.attemptID, FromState: w.from},
		SettledBy: w.settledBy, ReadbackAbsent: w.readbackAbsent, Reservation: w.reservation}
	var outcome, basis sql.NullString
	err := row.Scan(&o.WorkspaceID, &o.Version, &o.SettledAt, &o.State, &o.ReasonCode, &outcome, &basis, &o.EffectType,
		&o.RequestDigest, &o.TargetDigest, &o.ArgumentDigest)
	if errors.Is(err, sql.ErrNoRows) {
		return errors.New("admission: the attempt changed state while its outcome was recorded")
	}
	if err != nil {
		return err
	}
	o.Outcome, o.OutcomeBasis = outcome.String, basis.String
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
	if o.Exposures, err = settledExposures(ctx, tx, w.tenantID, w.attemptID); err != nil {
		return err
	}
	if w.settledBy == settledByModelCall {
		if o.ModelCall, err = settledCall(ctx, tx, w.tenantID, w.attemptID); err != nil {
			return err
		}
	}
	_, err = appendReceipt(ctx, tx, signer, o)
	return err
}

// settledExposures reads the attempt's exposures as the outcome left them,
// in limit and bucket order.
func settledExposures(ctx context.Context, tx *sql.Tx, tenantID, attemptID string) ([]Exposure, error) {
	rows, err := tx.QueryContext(ctx, `SELECT limit_id::text, bucket_start, kind, amount FROM authority_exposures
		WHERE tenant_id = $1 AND attempt_id = $2 ORDER BY limit_id, bucket_start`, tenantID, attemptID)
	if err != nil {
		return nil, fmt.Errorf("attempt %s exposures: %w", attemptID, err)
	}
	defer func() { _ = rows.Close() }()
	var out []Exposure
	for rows.Next() {
		var x Exposure
		var start time.Time
		if err := rows.Scan(&x.LimitID, &start, &x.Kind, &x.Amount); err != nil {
			return nil, err
		}
		start = start.UTC()
		x.BucketStart = &start
		out = append(out, x)
	}
	return out, rows.Err()
}

// settledCall reads a model call's money row as its settlement left it.
func settledCall(ctx context.Context, tx *sql.Tx, tenantID, attemptID string) (*settledModelCall, error) {
	var m settledModelCall
	var estimated, confirmed sql.NullInt64
	var usage []byte
	if err := tx.QueryRowContext(ctx, `SELECT state, currency_code, held_micros, estimated_micros, confirmed_micros, billable_micros, usage
		FROM authority_model_calls WHERE tenant_id = $1 AND attempt_id = $2`, tenantID, attemptID).
		Scan(&m.State, &m.CurrencyCode, &m.HeldMicros, &estimated, &confirmed, &m.BillableMicros, &usage); err != nil {
		return nil, fmt.Errorf("attempt %s model call: %w", attemptID, err)
	}
	if estimated.Valid {
		m.EstimatedMicros = &estimated.Int64
	}
	if confirmed.Valid {
		m.ConfirmedMicros = &confirmed.Int64
	}
	if len(usage) > 0 {
		digest, err := usageDigest(usage)
		if err != nil {
			return nil, fmt.Errorf("attempt %s usage: %w", attemptID, err)
		}
		m.UsageDigest = digest
	}
	return &m, nil
}

// usageDigest is the SHA-256 of the RFC 8785 form of stored usage JSON,
// computed by the reference implementation (jsoncanonicalizer): numbers are
// IEEE 754 doubles serialized as ECMAScript does, so the usage a provider
// sent (1e-7, 1.50) and the JSONB rendering of it the row returns
// (0.0000001, 1.50) have the same digest, and any RFC 8785 implementation
// recomputes it from the call row.
func usageDigest(usage []byte) ([]byte, error) {
	canonical, err := jsoncanonicalizer.Transform(usage)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(canonical)
	return sum[:], nil
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
