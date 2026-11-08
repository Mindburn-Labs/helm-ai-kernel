package admission

// CTL-059 outcome receipts against real PostgreSQL 16 (listed in
// scripts/ci/postgres-proofs.txt): every outcome of an admitted effect
// (OBSERVED, RECONCILED, SETTLED) commits with one signed receipt that chains
// after its decision's in the workspace's chain and verifies offline under
// the gateway's key alone, and the ledger refuses an outcome without one.
//
// quantum_posture: verifies classical Ed25519 test receipts and recomputes
// SHA-256 digests; no post-quantum claim.

import (
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/adapters"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/receiptverify"
)

// receiptsOf is an attempt's rows in its workspace's chain, in chain order.
func (f *fixture) receiptsOf(ws, attemptID string) []storedReceipt {
	f.t.Helper()
	var out []storedReceipt
	for _, r := range f.chainRows(tenantA, ws) {
		if r.attemptID == attemptID {
			out = append(out, r)
		}
	}
	return out
}

// wantReceipted checks an attempt's receipts are exactly states, in chain
// order: the decision first, then each outcome at a later sequence, each
// verifying offline on its own under the gateway key. Every outcome receipt
// signs the decision's policy_hash (its permit's authority), binds the
// permit, the attempt's outcome and the stored observation it rests on, and
// the last one describes the attempt's current version and its settlement as
// the ledger holds it (wantSettlement). It returns the outcome bindings in
// chain order, a zero value in each decision's place.
func (f *fixture) wantReceipted(a Attempt, states ...string) []outcomeBinding {
	f.t.Helper()
	rows := f.receiptsOf(a.WorkspaceID, a.ID)
	got := make([]string, 0, len(rows))
	for _, r := range rows {
		got = append(got, r.state)
	}
	if !slices.Equal(got, states) {
		f.t.Fatalf("attempt %s (%s) has receipts %v, want %v", a.ID, a.State, got, states)
	}
	if len(a.Receipts) != len(rows) {
		f.t.Fatalf("attempt %s carries %d receipt refs, the chain holds %d", a.ID, len(a.Receipts), len(rows))
	}
	bindings := make([]outcomeBinding, len(rows))
	var decision *contracts.Receipt
	for i, r := range rows {
		receipt := mustReceipt(f.t, r.envelope)
		if result := verifyBundle(f.t, r.envelope, trustTestKey()); !result.Valid {
			f.t.Fatalf("receipt %d of %s does not verify alone: %+v", r.seq, a.ID, result)
		}
		if ref := a.Receipts[i]; ref.ReceiptID != r.receiptID || ref.Seq != uint64(r.seq) || ref.State != r.state || ref.Digest != r.digest {
			f.t.Fatalf("receipt ref %d of %s = %+v, the chain holds %+v", i, a.ID, ref, r)
		}
		if i > 0 && r.seq <= rows[i-1].seq {
			f.t.Fatalf("receipt %d of %s does not follow its predecessor in the chain", i, a.ID)
		}
		if _, err := receiptVerdict(r.state); err == nil {
			decision = receipt
			var d receiptBinding
			must(f.t, json.Unmarshal(r.binding, &d))
			if d.BindingVersion != ReceiptBindingVersion || receipt.Verdict == "" {
				f.t.Fatalf("decision receipt of %s = %+v", a.ID, d)
			}
			continue
		}
		must(f.t, json.Unmarshal(r.binding, &bindings[i]))
		b := bindings[i]
		var source, trust, kind, ref string
		var observed sql.NullString
		var evidence []byte
		var observedAt time.Time
		f.ownerTx(tenantA, func(tx *sql.Tx) error {
			return tx.QueryRow(`SELECT source, trust_class, outcome, evidence_digest, result_kind, result_ref, observed_at
				FROM authority_observations WHERE attempt_id = $1 AND observation_id = $2`,
				a.ID, b.Observation.ID).Scan(&source, &trust, &observed, &evidence, &kind, &ref, &observedAt)
		})
		o := b.Observation
		if decision == nil || receipt.PolicyHash != decision.PolicyHash || receipt.Verdict != "" || receipt.ArgsHash != decision.ArgsHash ||
			b.BindingVersion != OutcomeBindingVersion || a.Permit == nil || b.PermitID != a.Permit.ID ||
			b.Outcome != a.Outcome || b.OutcomeBasis != a.OutcomeBasis || b.ArgumentDigest != receipt.ArgsHash ||
			o.Source != source || o.TrustClass != trust || o.Outcome != observed.String || o.Outcome != b.Outcome ||
			o.EvidenceDigest != hex.EncodeToString(evidence) || o.ResultKind != kind || o.ResultRef != ref ||
			o.ObservedAt != observedAt.UTC().Format(time.RFC3339Nano) || b.SettledAt == "" {
			f.t.Fatalf("outcome receipt %d of %s binds %+v (receipt %+v), not the stored outcome %+v", r.seq, a.ID, b, receipt, a)
		}
	}
	// An attempt in a receipted state was last written with its receipt;
	// UNKNOWN, ESCALATED_TO_HUMAN and the lifecycle in between carry none.
	if _, ok := outcomeFrom[a.State]; ok {
		last := rows[len(rows)-1]
		if last.version != a.Version || last.state != a.State {
			f.t.Fatalf("the last receipt of %s describes %s at %d, the attempt is %s at %d", a.ID, last.state, last.version, a.State, a.Version)
		}
		f.wantSettlement(a.ID, bindings[len(bindings)-1])
	}
	return bindings
}

// wantSettlement checks an outcome binding's settlement facts against the
// ledger rows: every exposure, its kind the reservation the outcome moved,
// and for a model call its money row, with the usage digest recomputed from
// the stored usage.
func (f *fixture) wantSettlement(attemptID string, b outcomeBinding) {
	f.t.Helper()
	var exposures []bindingExposure
	var modelCall *bindingModelCall
	f.ownerTx(tenantA, func(tx *sql.Tx) error {
		rows, err := tx.Query(`SELECT limit_id::text, bucket_start, kind, amount FROM authority_exposures WHERE attempt_id = $1
			ORDER BY limit_id, bucket_start`, attemptID)
		if err != nil {
			return err
		}
		for rows.Next() {
			var x bindingExposure
			var start time.Time
			var amount int64
			if err := rows.Scan(&x.LimitID, &start, &x.Kind, &amount); err != nil {
				return err
			}
			x.BucketStart, x.Amount = start.UTC().Format(time.RFC3339Nano), fmt.Sprint(amount)
			exposures = append(exposures, x)
		}
		if err := rows.Close(); err != nil {
			return err
		}
		var m bindingModelCall
		var held, billable int64
		var estimated, confirmed sql.NullInt64
		var usage []byte
		err = tx.QueryRow(`SELECT state, currency_code, held_micros, estimated_micros, confirmed_micros, billable_micros, usage
			FROM authority_model_calls WHERE attempt_id = $1`, attemptID).Scan(&m.State, &m.CurrencyCode, &held, &estimated, &confirmed, &billable, &usage)
		if err == sql.ErrNoRows {
			return nil
		}
		if err != nil {
			return err
		}
		m.HeldMicros, m.BillableMicros = fmt.Sprint(held), fmt.Sprint(billable)
		if estimated.Valid {
			m.EstimatedMicros = fmt.Sprint(estimated.Int64)
		}
		if confirmed.Valid {
			m.ConfirmedMicros = fmt.Sprint(confirmed.Int64)
		}
		if usage != nil {
			// The reference RFC 8785 implementation over the row as stored.
			canonical, err := jsoncanonicalizer.Transform(usage)
			if err != nil {
				return err
			}
			m.UsageDigest = hex.EncodeToString(sha(canonical))
		}
		modelCall = &m
		return nil
	})
	if len(b.Exposures) != len(exposures) {
		f.t.Fatalf("attempt %s binds exposures %+v, the ledger holds %+v", attemptID, b.Exposures, exposures)
	}
	for i, x := range exposures {
		if b.Exposures[i] != x || x.Kind != b.Reservation {
			f.t.Fatalf("attempt %s binds exposure %+v and reservation %s, the ledger holds %+v", attemptID, b.Exposures[i], b.Reservation, x)
		}
	}
	switch {
	case (b.SettledBy == settledByModelCall) != (modelCall != nil):
		f.t.Fatalf("attempt %s settled by %s binds model call %+v, the ledger holds %+v", attemptID, b.SettledBy, b.ModelCall, modelCall)
	case modelCall != nil && (b.ModelCall == nil || *b.ModelCall != *modelCall):
		f.t.Fatalf("attempt %s binds model call %+v, the ledger holds %+v", attemptID, b.ModelCall, modelCall)
	case modelCall == nil && b.ModelCall != nil:
		f.t.Fatalf("attempt %s binds a model call it does not have: %+v", attemptID, b.ModelCall)
	}
}

func TestPostgresEveryEffectOutcomeCommitsWithItsSignedReceipt(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.notesLimit(10)
	fake := &scripted{}
	svc := f.withAdapter(fake)
	get := func(id string) Attempt {
		t.Helper()
		a, err := svc.Get(ctx, human, id)
		must(t, err)
		return a
	}
	notSent := func(adapters.Effect) adapters.DispatchResult {
		return adapters.DispatchResult{Status: adapters.DispatchNotSent, Reason: contracts.ReasonPreconditionFailed, Detail: "head moved"}
	}
	indefinite := func(adapters.Effect) adapters.DispatchResult {
		return adapters.DispatchResult{Status: adapters.DispatchIndefinite, Reason: contracts.ReasonProviderError, Detail: "502"}
	}
	inconclusive := func(adapters.Effect) adapters.ObserveResult {
		return adapters.ObserveResult{Outcome: adapters.OutcomeUnknown, Reason: contracts.ReasonProviderError}
	}

	// Success: dispatched and read back in one call.
	ok, _, err := svc.Dispatch(ctx, workload, f.propose(human, quotaNote("outcome-ok")).ID)
	must(t, err)
	wantOutcome(t, "success", ok, "OBSERVED", "SUCCEEDED", "")
	b := f.wantReceipted(ok, "ADMITTED", "OBSERVED")[1]
	if b.FromState != "DISPATCHED" || b.Observation.Source != "fake.readback" || b.Observation.EvidenceDigest != hex.EncodeToString(sha([]byte("provider bytes"))) {
		t.Fatalf("the success binding = %+v", b)
	}

	// An adapter failure: the read-back finds an object that contradicts it.
	fake.set(nil, contradicted)
	failed, _, err := svc.Dispatch(ctx, workload, f.propose(human, quotaNote("outcome-contradicted")).ID)
	must(t, err)
	wantOutcome(t, "a contradicted read-back", failed, "OBSERVED", "FAILED", contracts.ReasonReadbackMismatch)
	if b := f.wantReceipted(failed, "ADMITTED", "OBSERVED")[1]; b.ReasonCode != string(contracts.ReasonReadbackMismatch) || b.Observation.Outcome != "FAILED" {
		t.Fatalf("the failure binding = %+v", b)
	}

	// NOT_SENT: the adapter's own answer is the outcome.
	fake.set(notSent, nil)
	refused, _, err := svc.Dispatch(ctx, workload, f.propose(human, quotaNote("outcome-not-sent")).ID)
	must(t, err)
	wantOutcome(t, "NOT_SENT", refused, "OBSERVED", "FAILED", contracts.ReasonPreconditionFailed)
	if b := f.wantReceipted(refused, "ADMITTED", "OBSERVED")[1]; b.FromState != "DISPATCHING" || b.Observation.Source != dispatchSource ||
		b.Observation.TrustClass != dispatchTrustClass || b.Observation.EvidenceDigest != "" {
		t.Fatalf("the NOT_SENT binding = %+v", b)
	}

	// UNKNOWN is not an outcome; Observe reconciles it once it is known.
	fake.set(indefinite, inconclusive)
	unknown, _, err := svc.Dispatch(ctx, workload, f.propose(human, quotaNote("outcome-unknown")).ID)
	must(t, err)
	wantOutcome(t, "an indefinite dispatch", unknown, "UNKNOWN", "", contracts.ReasonProviderError)
	f.wantReceipted(unknown, "ADMITTED")
	still, _, err := svc.Observe(ctx, workload, unknown.ID)
	must(t, err)
	f.wantReceipted(still, "ADMITTED")
	fake.set(indefinite, nil)
	reconciled, _, err := svc.Observe(ctx, workload, unknown.ID)
	must(t, err)
	wantOutcome(t, "reconciled by Observe", reconciled, "RECONCILED", "SUCCEEDED", "")
	if b := f.wantReceipted(reconciled, "ADMITTED", "RECONCILED")[1]; b.FromState != "UNKNOWN" || b.OutcomeBasis != "RECONCILED" {
		t.Fatalf("the reconciled binding = %+v", b)
	}

	// The reconciliation job reconciles the same way, past the fence: the
	// write never landed.
	fake.set(indefinite, inconclusive)
	byJob, _, err := svc.Dispatch(ctx, workload, f.propose(human, quotaNote("outcome-job")).ID)
	must(t, err)
	f.passFence(byJob.ID)
	fake.set(indefinite, absent)
	resolved, _, err := svc.Reconcile(ctx, tenantA, workspace, byJob.ID, false)
	must(t, err)
	byJob = get(byJob.ID)
	if !resolved {
		t.Fatal("the reconciliation job did not resolve an established absence")
	}
	wantOutcome(t, "reconciled by the job", byJob, "RECONCILED", "FAILED", contracts.ReasonReadbackMismatch)
	f.wantReceipted(byJob, "ADMITTED", "RECONCILED")

	// A gateway that died after its claim: UNKNOWN past the fence, then
	// reconciled; only the outcome is receipted.
	fake.set(nil, nil)
	crashed := f.propose(human, quotaNote("outcome-crash"))
	f.claimOnly(svc, crashed.ID)
	f.passFence(crashed.ID)
	landed, _, err := svc.Observe(ctx, workload, crashed.ID)
	must(t, err)
	wantOutcome(t, "a crashed dispatch that landed", landed, "RECONCILED", "SUCCEEDED", "")
	if b := f.wantReceipted(landed, "ADMITTED", "RECONCILED")[1]; b.FromState != "UNKNOWN" {
		t.Fatalf("the crashed dispatch's binding = %+v", b)
	}

	// A human handoff is not an outcome: no receipt, the reservation held.
	fake.set(indefinite, inconclusive)
	handoff, _, err := svc.Dispatch(ctx, workload, f.propose(human, quotaNote("outcome-handoff")).ID)
	must(t, err)
	if _, _, err := svc.Reconcile(ctx, tenantA, workspace, handoff.ID, true); err != nil {
		t.Fatal(err)
	}
	handoff = get(handoff.ID)
	if handoff.State != "ESCALATED_TO_HUMAN" {
		t.Fatalf("the final reconciliation left %s", handoff.State)
	}
	f.wantReceipted(handoff, "ADMITTED")

	// Seven decisions and six outcomes, in one contiguous chain.
	f.wantContiguousChain(tenantA, workspace, 13)
	if n := fake.dispatched.Load(); n != 6 {
		t.Fatalf("%d provider calls, want 6", n)
	}
	f.ledgerBalances()
}

func TestPostgresModelCallOutcomesCarryReceipts(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.modelFixture(1_000_000)
	get := func(id string) Attempt {
		t.Helper()
		a, err := f.svc.Get(ctx, worker, id)
		must(t, err)
		return a
	}
	body := []byte("event: message_stop\n\n")

	// Confirmed: OBSERVED and SETTLED in one transaction, each receipted at
	// its own version, both on the one observation of the response.
	claim, _ := f.claimModel("mi:receipt:confirmed", 3_000)
	confirmed, err := f.svc.SettleModelCall(ctx, claim, ModelCallOutcome{Result: ModelCallConfirmed, ConfirmedMicros: 1_200,
		Usage: []byte(`{"output_tokens":40, "cost":1.50, "rate":1e-7, "input_tokens":100}`), EvidenceDigest: sha(body)})
	must(t, err)
	wantOutcome(t, "confirmed", confirmed, "SETTLED", "SUCCEEDED", "")
	bs := f.wantReceipted(confirmed, "ADMITTED", "OBSERVED", "SETTLED")
	// The RFC 8785 form of the usage, whatever the provider and JSONB wrote:
	// 1.50 is 1.5 and 1e-7 stays 1e-7, though JSONB renders it 0.0000001.
	usage := hex.EncodeToString(sha([]byte(`{"cost":1.5,"input_tokens":100,"output_tokens":40,"rate":1e-7}`)))
	if bs[1].AttemptVersion != confirmed.Version-1 || bs[2].FromState != "OBSERVED" || bs[1].Observation.ID != bs[2].Observation.ID ||
		bs[2].Observation.Source != modelObservationSource || bs[2].Observation.EvidenceDigest != hex.EncodeToString(sha(body)) ||
		bs[2].SettledBy != settledByModelCall || bs[2].Reservation != "confirmed" ||
		*bs[2].ModelCall != (bindingModelCall{State: SettlementConfirmed, CurrencyCode: "USD", HeldMicros: "3000", ConfirmedMicros: "1200", BillableMicros: "1200", UsageDigest: usage}) ||
		*bs[1].ModelCall != *bs[2].ModelCall || len(bs[2].Exposures) != 1 || bs[2].Exposures[0].Amount != "1200" {
		t.Fatalf("the confirmed call's bindings = %+v %+v", bs[1], bs[2])
	}
	// Settling it again changes nothing and appends nothing.
	again, err := f.svc.SettleModelCall(ctx, claim, ModelCallOutcome{Result: ModelCallConfirmed, ConfirmedMicros: 9_999})
	must(t, err)
	f.wantReceipted(again, "ADMITTED", "OBSERVED", "SETTLED")

	// Estimated, then confirmed late: the estimate is OBSERVED, and the late
	// usage re-settles it (OBSERVED again, at a new version) and SETTLES it.
	claim, _ = f.claimModel("mi:receipt:estimated", 2_000)
	estimated, err := f.svc.SettleModelCall(ctx, claim, ModelCallOutcome{Result: ModelCallEstimated, EvidenceDigest: sha(body)})
	must(t, err)
	wantOutcome(t, "estimated", estimated, "OBSERVED", "SUCCEEDED", "")
	if b := f.wantReceipted(estimated, "ADMITTED", "OBSERVED")[1]; b.Reservation != "estimated" ||
		*b.ModelCall != (bindingModelCall{State: SettlementEstimated, CurrencyCode: "USD", HeldMicros: "2000", EstimatedMicros: "2000", BillableMicros: "0"}) {
		t.Fatalf("the estimate's binding = %+v %+v", b, b.ModelCall)
	}
	late, err := f.svc.SettleModelCall(ctx, claim, ModelCallOutcome{Result: ModelCallConfirmed, ConfirmedMicros: 800,
		Usage: []byte(`{"input_tokens":10,"output_tokens":5}`), EvidenceDigest: sha([]byte("usage"))})
	must(t, err)
	wantOutcome(t, "confirmed late", late, "SETTLED", "SUCCEEDED", "")
	bs = f.wantReceipted(late, "ADMITTED", "OBSERVED", "OBSERVED", "SETTLED")
	// The re-settlement signs what changed: the confirmed and billable
	// amounts, the usage and the confirmed reservation, not only a version.
	if bs[2].FromState != "OBSERVED" || bs[2].Observation.ID == bs[1].Observation.ID || bs[3].Observation.ID != bs[2].Observation.ID ||
		bs[1].ModelCall.State != SettlementEstimated || bs[1].ModelCall.ConfirmedMicros != "" || bs[1].Reservation != "estimated" ||
		*bs[2].ModelCall != (bindingModelCall{State: SettlementConfirmed, CurrencyCode: "USD", HeldMicros: "2000", ConfirmedMicros: "800",
			BillableMicros: "800", UsageDigest: hex.EncodeToString(sha([]byte(`{"input_tokens":10,"output_tokens":5}`)))}) ||
		bs[2].Reservation != "confirmed" || bs[2].Exposures[0].Amount != "800" || bs[2].Exposures[0].Kind != "confirmed" {
		t.Fatalf("the late confirmation's bindings = %+v %+v %+v", bs[1].ModelCall, bs[2].ModelCall, bs[2])
	}

	// Refused by the provider: OBSERVED(FAILED) on the adapter's refusal.
	claim, _ = f.claimModel("mi:receipt:refused", 1_000)
	refused, err := f.svc.SettleModelCall(ctx, claim, ModelCallOutcome{Result: ModelCallNotSent, Reason: contracts.ReasonProviderError})
	must(t, err)
	wantOutcome(t, "not sent", refused, "OBSERVED", "FAILED", contracts.ReasonProviderError)
	if b := f.wantReceipted(refused, "ADMITTED", "OBSERVED")[1]; b.Observation.TrustClass != "adapter_refusal" || b.Observation.EvidenceDigest != "" {
		t.Fatalf("the refused call's binding = %+v", b)
	}

	// Cut: UNKNOWN, no outcome yet; the provider's confirmation reconciles and
	// settles it.
	claim, _ = f.claimModel("mi:receipt:cut", 1_500)
	cut, err := f.svc.SettleModelCall(ctx, claim, ModelCallOutcome{Result: ModelCallCut, Reason: contracts.ReasonProviderError})
	must(t, err)
	if cut.State != "UNKNOWN" {
		t.Fatalf("a cut call is %s", cut.State)
	}
	// Not an outcome, so not receipted, though the hold is already spent as
	// an estimate (CTL-059 bypass assumptions).
	f.wantReceipted(cut, "ADMITTED")
	if cut.ModelCall == nil || cut.ModelCall.State != SettlementEstimated || len(cut.Exposures) != 1 || cut.Exposures[0].Kind != "estimated" {
		t.Fatalf("a cut call's money: %+v %+v", cut.ModelCall, cut.Exposures)
	}
	reconciled, err := f.svc.SettleModelCall(ctx, claim, ModelCallOutcome{Result: ModelCallConfirmed, ConfirmedMicros: 700})
	must(t, err)
	wantOutcome(t, "a cut call confirmed", reconciled, "SETTLED", "SUCCEEDED", "")
	if bs := f.wantReceipted(get(cut.ID), "ADMITTED", "RECONCILED", "SETTLED"); bs[1].FromState != "UNKNOWN" || bs[2].OutcomeBasis != "RECONCILED" {
		t.Fatalf("the reconciled call's bindings = %+v", bs)
	}

	f.wantContiguousChain(tenantA, workspace, 12)
	f.ledgerBalances()
}

// TestPostgresAnOutcomeWithoutItsReceiptFailsAtCommit: the ledger refuses an
// outcome that commits without its receipt, whoever writes it: the
// statements a schema-15 gateway runs during an upgrade, or the owner; a
// re-settlement at a new version is refused the same way. A signing failure
// rolls the outcome back and leaves the attempt for a later read-back.
// Transitions that are not outcomes need none.
func TestPostgresAnOutcomeWithoutItsReceiptFailsAtCommit(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	var fail atomic.Bool
	fake := &scripted{}
	svc, err := New(f.runtime, Config{ReceiptSigner: switchSigner{testReceiptSigner, &fail}, Adapters: []adapters.Adapter{fake}, Credentials: fakeCredentials{}})
	must(t, err)
	inTx := func(db *sql.DB, statement string, args ...any) error {
		tx, err := db.BeginTx(ctx, nil)
		must(t, err)
		defer func() { _ = tx.Rollback() }()
		if _, err := tx.Exec(`SELECT set_config('app.current_tenant', $1, true)`, tenantA); err != nil {
			return err
		}
		if _, err := tx.Exec(statement, args...); err != nil {
			return err
		}
		return tx.Commit()
	}
	stateOf := func(id string) (state string, version int64) {
		f.ownerTx(tenantA, func(tx *sql.Tx) error {
			return tx.QueryRow(`SELECT state, version FROM authority_effect_attempts WHERE attempt_id = $1`, id).Scan(&state, &version)
		})
		return state, version
	}
	// The exact statements a schema-15 gateway ran: settleState and the
	// model call's SETTLED transition.
	const legacySettle = `UPDATE authority_effect_attempts
		SET state = $4, outcome = $5, outcome_basis = $6, reason_code = $7, version = version + 1, updated_at = now()
		WHERE tenant_id = $1 AND attempt_id = $2 AND state = $3`
	const legacyTransition = `UPDATE authority_effect_attempts SET state = $4, reason_code = $5, version = version + 1, updated_at = now()
		WHERE tenant_id = $1 AND attempt_id = $2 AND state = $3`

	claimed := f.propose(human, note("unreceipted-outcome"))
	f.claimOnly(svc, claimed.ID)
	for name, db := range map[string]*sql.DB{"the runtime role": f.runtime, "the owner": f.owner} {
		for _, to := range []string{"OBSERVED", "RECONCILED"} {
			err := inTx(db, legacySettle, tenantA, claimed.ID, "DISPATCHING", to, "SUCCEEDED", to, "")
			if err == nil || !strings.Contains(err.Error(), "outcome_receipt_missing") {
				t.Fatalf("%s wrote %s without a receipt: err = %v", name, to, err)
			}
		}
	}
	if state, _ := stateOf(claimed.ID); state != "DISPATCHING" {
		t.Fatalf("an unreceipted outcome committed: the attempt is %s", state)
	}
	// A transition that is not an outcome commits without one.
	must(t, inTx(f.runtime, legacyTransition, tenantA, claimed.ID, "DISPATCHING", "UNKNOWN", ""))

	// A receipted outcome; then an unreceipted SETTLED, and an unreceipted
	// re-settlement at a new version, are refused. Rewriting a column that is
	// neither the state nor the version is not an outcome write.
	observed, _, err := svc.Observe(ctx, workload, claimed.ID)
	must(t, err)
	wantOutcome(t, "a receipted outcome", observed, "RECONCILED", "SUCCEEDED", "")
	for name, write := range map[string]func() error{
		"SETTLED": func() error {
			return inTx(f.runtime, legacyTransition, tenantA, claimed.ID, "RECONCILED", "SETTLED", "")
		},
		"a new version": func() error {
			return inTx(f.runtime, `UPDATE authority_effect_attempts SET version = version + 1 WHERE tenant_id = $1 AND attempt_id = $2`, tenantA, claimed.ID)
		},
	} {
		if err := write(); err == nil || !strings.Contains(err.Error(), "outcome_receipt_missing") {
			t.Fatalf("%s without a receipt: err = %v", name, err)
		}
	}
	must(t, inTx(f.runtime, `UPDATE authority_effect_attempts SET dispatch_deadline = now() WHERE attempt_id = $1`, claimed.ID))
	if state, version := stateOf(claimed.ID); state != "RECONCILED" || version != observed.Version {
		t.Fatalf("after the refused writes the attempt is %s at %d, want RECONCILED at %d", state, version, observed.Version)
	}
	// An attempt inserted with an outcome is refused the same way.
	err = inTx(f.owner, `INSERT INTO authority_effect_attempts (tenant_id, attempt_id, workspace_id, idempotency_key, request_digest,
			requester_principal_id, effect_type, target, target_digest, argument_digest, state, outcome, outcome_basis)
		VALUES ($1, gen_random_uuid(), $2, 'born-observed', $3, 'human-a', $4, 'ops', $3, $3, 'OBSERVED', 'SUCCEEDED', 'OBSERVED')`,
		tenantA, workspace, sum256("born-observed"), noteType)
	if err == nil || !strings.Contains(err.Error(), "outcome_receipt_missing") {
		t.Fatalf("an attempt inserted OBSERVED without a receipt: err = %v", err)
	}

	// A read-back whose receipt cannot be signed records nothing: the attempt
	// stays DISPATCHED, with no observation, and a later read-back settles it.
	a := f.propose(human, note("unsigned-outcome"))
	fail.Store(true)
	dispatched, _, err := svc.Dispatch(ctx, workload, a.ID)
	must(t, err)
	if dispatched.State != "DISPATCHED" || dispatched.LatestObservation != nil {
		t.Fatalf("a read-back with no signer left %+v", dispatched)
	}
	f.wantReceipted(dispatched, "ADMITTED")
	fail.Store(false)
	settled, _, err := svc.Observe(ctx, workload, a.ID)
	must(t, err)
	wantOutcome(t, "after the signer recovers", settled, "OBSERVED", "SUCCEEDED", "")
	f.wantReceipted(settled, "ADMITTED", "OBSERVED")
	f.wantContiguousChain(tenantA, workspace, 4)
}

func TestPostgresOutcomeReceiptChainStaysContiguousUnderConcurrentSettles(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	fake := &scripted{}
	svc := f.withAdapter(fake)
	const n = 8
	admitted := make([]Attempt, n)
	for i := range admitted {
		admitted[i] = f.propose(human, note(fmt.Sprintf("concurrent-outcome-%d", i)))
	}
	// Unknown attempts, for read-backs that race to reconcile each one.
	fake.set(func(adapters.Effect) adapters.DispatchResult {
		return adapters.DispatchResult{Status: adapters.DispatchIndefinite, Reason: contracts.ReasonProviderError}
	}, func(adapters.Effect) adapters.ObserveResult {
		return adapters.ObserveResult{Outcome: adapters.OutcomeUnknown}
	})
	unknown := make([]Attempt, n/2)
	for i := range unknown {
		a := f.propose(human, note(fmt.Sprintf("concurrent-unknown-%d", i)))
		var err error
		unknown[i], _, err = svc.Dispatch(ctx, workload, a.ID)
		must(t, err)
	}
	fake.set(nil, nil)

	// Dispatches settling, read-backs racing over the unknown ones, the
	// reconciliation job, and new decisions, all in one workspace.
	var wg sync.WaitGroup
	errs := make(chan error, 4*n)
	run := func(fn func() error) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := fn(); err != nil {
				errs <- err
			}
		}()
	}
	for i, a := range admitted {
		run(func() error { _, _, err := svc.Dispatch(ctx, workload, a.ID); return err })
		run(func() error {
			_, _, err := svc.Propose(ctx, human, note(fmt.Sprintf("concurrent-decision-%d", i)))
			return err
		})
	}
	for _, a := range unknown {
		run(func() error { _, _, err := svc.Observe(ctx, workload, a.ID); return err })
		run(func() error { _, _, err := svc.Observe(ctx, workload, a.ID); return err })
		run(func() error { _, _, err := svc.Reconcile(ctx, tenantA, workspace, a.ID, false); return err })
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	// Decisions: n admitted, n/2 unknown, n new; outcomes: n observed and n/2
	// reconciled, each exactly once.
	f.wantContiguousChain(tenantA, workspace, n+n/2+n+n+n/2)
	for _, a := range admitted {
		got, err := svc.Get(ctx, human, a.ID)
		must(t, err)
		wantOutcome(t, "a concurrent dispatch", got, "OBSERVED", "SUCCEEDED", "")
		f.wantReceipted(got, "ADMITTED", "OBSERVED")
	}
	for _, a := range unknown {
		got, err := svc.Get(ctx, human, a.ID)
		must(t, err)
		wantOutcome(t, "a raced reconciliation", got, "RECONCILED", "SUCCEEDED", "")
		f.wantReceipted(got, "ADMITTED", "RECONCILED")
	}
	if d := fake.dispatched.Load(); d != n+n/2 {
		t.Fatalf("%d provider calls, want %d", d, n+n/2)
	}
}

func TestPostgresOutcomeReceiptSchemaUpgradesFrom15(t *testing.T) {
	f := newFixtureAtVersionWithoutReceipts(t, 15)
	ctx := context.Background()
	fake := &scripted{}
	svc := f.withAdapter(fake)
	// On schema 15 decisions are receipted; an outcome a schema-15 gateway
	// recorded carries none, and the receipt table cannot hold one yet.
	legacy := f.propose(human, note("legacy-15"))
	f.claimOnly(svc, legacy.ID)
	f.exec(tenantA, `UPDATE authority_effect_attempts SET state = 'OBSERVED', outcome = 'SUCCEEDED', outcome_basis = 'OBSERVED',
		version = version + 1 WHERE attempt_id = $1`, legacy.ID)
	var fences int
	countFences := func() {
		must(t, f.owner.QueryRow(`SELECT count(*) FROM pg_trigger WHERE tgrelid = to_regclass('authority_effect_attempts')
			AND tgname IN ('authority_outcome_receipt_insert', 'authority_outcome_receipt_update') AND tgdeferrable AND tginitdeferred`).Scan(&fences))
	}
	countFences()
	if fences != 0 {
		t.Fatal("schema 15 already has the outcome fence")
	}

	must(t, Migrate(ctx, f.owner))
	must(t, Migrate(ctx, f.owner))
	version, err := SchemaVersion(ctx, f.owner)
	must(t, err)
	if version != HeadVersion() || HeadVersion() != 16 {
		t.Fatalf("schema at %d after migrating, head %d", version, HeadVersion())
	}
	countFences()
	if fences != 2 {
		t.Fatalf("%d deferred outcome fences after the upgrade, want 2", fences)
	}
	var schema string
	must(t, f.owner.QueryRow(`SELECT current_schema()`).Scan(&schema))
	grantRuntime(t, f.owner, schema, f.role)
	// Both fences resolve authority_receipts in the gateway schema only,
	// migration 15's decision fence included.
	for _, fn := range []string{"authority_require_decision_receipt", "authority_require_outcome_receipt"} {
		var config []byte
		must(t, f.owner.QueryRow(`SELECT array_to_string(proconfig, ';') FROM pg_proc WHERE proname = $1 AND pronamespace = to_regnamespace($2)`,
			fn, schema).Scan(&config))
		if string(config) != "search_path="+schema+", pg_temp" {
			t.Fatalf("%s runs with %q, want its search_path pinned to %s, pg_temp", fn, config, schema)
		}
	}

	// The legacy outcome stays as it was, without a receipt; the next outcome
	// is receipted and chains after every decision before it.
	old, err := svc.Get(ctx, human, legacy.ID)
	must(t, err)
	if old.State != "OBSERVED" || len(old.Receipts) != 1 || old.Receipts[0].State != "ADMITTED" {
		t.Fatalf("the legacy outcome after the upgrade: %+v", old)
	}
	next, _, err := svc.Dispatch(ctx, workload, f.propose(human, note("after-upgrade-16")).ID)
	must(t, err)
	wantOutcome(t, "the first outcome after the upgrade", next, "OBSERVED", "SUCCEEDED", "")
	f.wantReceipted(next, "ADMITTED", "OBSERVED")
	f.wantContiguousChain(tenantA, workspace, 3)
	// The statement that wrote the legacy outcome is refused now.
	claimed := f.propose(human, note("legacy-after-16"))
	f.claimOnly(svc, claimed.ID)
	tx, err := f.runtime.BeginTx(ctx, nil)
	must(t, err)
	defer func() { _ = tx.Rollback() }()
	_, err = tx.Exec(`SELECT set_config('app.current_tenant', $1, true)`, tenantA)
	must(t, err)
	_, err = tx.Exec(`UPDATE authority_effect_attempts SET state = 'OBSERVED', outcome = 'SUCCEEDED', outcome_basis = 'OBSERVED',
		version = version + 1 WHERE attempt_id = $1`, claimed.ID)
	must(t, err)
	if err := tx.Commit(); err == nil || !strings.Contains(err.Error(), "outcome_receipt_missing") {
		t.Fatalf("a schema-15 outcome after the upgrade: err = %v", err)
	}
}

// TestPostgresOutcomeReceiptsVerifyOfflineAsAChain: an exported chain of
// decisions and outcomes verifies under the gateway key alone, and a rewritten
// outcome, a dropped outcome or another key fails it.
func TestPostgresOutcomeReceiptsVerifyOfflineAsAChain(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	fake := &scripted{}
	svc := f.withAdapter(fake)
	_, _, err := svc.Dispatch(ctx, workload, f.propose(human, note("offline-outcome-1")).ID)
	must(t, err)
	fake.set(nil, contradicted)
	_, _, err = svc.Dispatch(ctx, workload, f.propose(human, note("offline-outcome-2")).ID)
	must(t, err)
	rows := f.wantContiguousChain(tenantA, workspace, 4)
	raw := bundleOf(t, rows)
	if result := verifyBundle(t, raw, trustTestKey()); !result.Valid {
		t.Fatalf("the exported chain: %+v", result)
	}
	tampered := strings.Replace(string(raw), `"status":"OBSERVED"`, `"status":"RECONCILED"`, 1)
	if tampered == string(raw) {
		t.Fatalf("the exported chain carries no OBSERVED status to tamper with: %s", raw)
	}
	other := otherSigner(t, testReceiptSigner.GetKeyID())
	for name, test := range map[string]struct {
		raw   []byte
		trust receiptverify.TrustRoot
	}{
		"a rewritten outcome": {[]byte(tampered), trustTestKey()},
		"a dropped outcome":   {bundleOf(t, append(append([]storedReceipt{}, rows[:1]...), rows[2:]...)), trustTestKey()},
		"another key":         {raw, receiptverify.TrustRoot{Keys: map[string]string{other.GetKeyID(): other.PublicKey()}}},
	} {
		if result := verifyBundle(t, test.raw, test.trust); result.Valid {
			t.Errorf("%s: the chain verified", name)
		}
	}
	// The binding an outcome commits to is the one stored beside it.
	for _, r := range rows[1:2] {
		var b outcomeBinding
		must(t, json.Unmarshal(r.binding, &b))
		if b.Outcome != "SUCCEEDED" || mustReceipt(t, r.envelope).OutputHash != hex.EncodeToString(sha(r.binding)) {
			t.Fatalf("outcome binding %+v", b)
		}
	}
}

// TestPostgresFencesIgnoreALookAlikeReceiptTable: both fences find receipts
// only in the gateway schema. A temporary authority_receipts the runtime role
// creates, or one in a schema the writer puts first on its search_path,
// holding the row a fence looks for, satisfies neither the decision fence nor
// the outcome fence (CTL-059, migration 16).
func TestPostgresFencesIgnoreALookAlikeReceiptTable(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	fake := &scripted{}
	svc := f.withAdapter(fake)
	var schema string
	must(t, f.owner.QueryRow(`SELECT current_schema()`).Scan(&schema))
	lookalike := schema + "_lookalike"
	_, err := f.owner.Exec(`CREATE SCHEMA ` + lookalike)
	must(t, err)
	t.Cleanup(func() { _, _ = f.owner.Exec(`DROP SCHEMA ` + lookalike + ` CASCADE`) })
	const table = ` (tenant_id TEXT, attempt_id UUID, attempt_version BIGINT, state TEXT)`
	// The chart's bootstrap revokes TEMPORARY from PUBLIC; a deployment that
	// does not is the case to prove, so the runtime role gets it here.
	var database string
	must(t, f.owner.QueryRow(`SELECT current_database()`).Scan(&database))
	t.Cleanup(func() { _, _ = f.owner.Exec(`REVOKE TEMPORARY ON DATABASE ` + database + ` FROM ` + f.role) })
	for _, statement := range []string{
		`GRANT TEMPORARY ON DATABASE ` + database + ` TO ` + f.role,
		`CREATE TABLE ` + lookalike + `.authority_receipts` + table,
		`GRANT USAGE ON SCHEMA ` + lookalike + ` TO ` + f.role,
		`GRANT SELECT, INSERT ON ` + lookalike + `.authority_receipts TO ` + f.role,
	} {
		_, err := f.owner.Exec(statement)
		must(t, err)
	}

	// A claimed attempt for the outcome fence, a proposed one for the
	// decision fence.
	claimed := f.propose(human, note("lookalike-outcome"))
	f.claimOnly(svc, claimed.ID)
	var proposed string
	f.ownerTx(tenantA, func(tx *sql.Tx) error {
		return tx.QueryRow(`INSERT INTO authority_effect_attempts (tenant_id, attempt_id, workspace_id, idempotency_key, request_digest,
				requester_principal_id, effect_type, target, target_digest, argument_digest, state)
			VALUES ($1, gen_random_uuid(), $2, 'lookalike-decision', $3, 'human-a', $4, 'ops', $3, $3, 'PROPOSED') RETURNING attempt_id`,
			tenantA, workspace, sum256("lookalike-decision"), noteType).Scan(&proposed)
	})
	writes := []struct {
		name, attempt, state, statement, refusal string
		version                                  int64
		args                                     []any
	}{
		{"an outcome", claimed.ID, "OBSERVED", `UPDATE authority_effect_attempts
			SET state = 'OBSERVED', outcome = 'SUCCEEDED', outcome_basis = 'OBSERVED', version = version + 1 WHERE attempt_id = $1`,
			"outcome_receipt_missing", claimed.Version + 2, nil},
		{"a decision", proposed, "DENIED", `UPDATE authority_effect_attempts SET state = 'DENIED', version = version + 1 WHERE attempt_id = $1`,
			"decision_receipt_missing", 2, nil},
	}
	for _, w := range writes {
		for name, setup := range map[string][]string{
			"a temporary table":                 {`CREATE TEMP TABLE authority_receipts` + table},
			"a schema first on the search_path": {`SET LOCAL search_path = ` + lookalike + `, ` + schema},
		} {
			conn, err := f.runtime.Conn(ctx)
			must(t, err)
			tx, err := conn.BeginTx(ctx, nil)
			must(t, err)
			_, err = tx.Exec(`SELECT set_config('app.current_tenant', $1, true)`, tenantA)
			must(t, err)
			for _, statement := range setup {
				_, err := tx.Exec(statement)
				must(t, err)
			}
			// The look-alike holds exactly the row the fence asks for.
			_, err = tx.Exec(`INSERT INTO authority_receipts (tenant_id, attempt_id, attempt_version, state) VALUES ($1, $2, $3, $4)`,
				tenantA, w.attempt, w.version, w.state)
			must(t, err)
			_, err = tx.Exec(w.statement, w.attempt)
			must(t, err)
			err = tx.Commit()
			_ = conn.Close()
			if err == nil || !strings.Contains(err.Error(), w.refusal) {
				t.Fatalf("%s with %s holding its receipt: err = %v, want %s", w.name, name, err, w.refusal)
			}
		}
	}
	// Nothing committed: the attempts are where they were.
	for id, want := range map[string]string{claimed.ID: "DISPATCHING", proposed: "PROPOSED"} {
		var state string
		f.ownerTx(tenantA, func(tx *sql.Tx) error {
			return tx.QueryRow(`SELECT state FROM authority_effect_attempts WHERE attempt_id = $1`, id).Scan(&state)
		})
		if state != want {
			t.Fatalf("attempt %s is %s after the refused writes, want %s", id, state, want)
		}
	}
}
