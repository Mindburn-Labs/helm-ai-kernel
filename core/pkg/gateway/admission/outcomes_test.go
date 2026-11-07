package admission

// quantum_posture: signs and verifies classical Ed25519 test receipts and
// recomputes SHA-256 digests; no post-quantum claim.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/adapters"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/receiptverify"
)

const sampleObservation = int64(41)

var sampleSettledAt = time.Date(2030, 1, 2, 3, 9, 0, 250000000, time.UTC)

// sampleOutcome is the OBSERVED(SUCCEEDED) row a read-back of sampleDecision's
// attempt leaves: two versions later (DISPATCHING, then this write), under
// the permit the decision issued.
func sampleOutcome() storedOutcome {
	d := sampleDecision()
	d.Version, d.FromState, d.State, d.DecidedAt = 4, "DISPATCHED", "OBSERVED", time.Time{}
	return storedOutcome{storedDecision: d, Outcome: "SUCCEEDED", OutcomeBasis: "OBSERVED",
		Observation: boundObservation{ID: sampleObservation, Source: "fake.readback", TrustClass: "provider_readback", Outcome: "SUCCEEDED",
			EvidenceDigest: sum256("provider bytes"), ResultKind: "github_branch", ResultRef: "sha256:" + hex.EncodeToString(sum256("result")),
			ObservedAt: time.Date(2030, 1, 2, 3, 8, 59, 0, time.UTC)},
		SettledAt: sampleSettledAt}
}

// TestOutcomeReceiptBindsTheStoredOutcome: the pure builder maps a stored
// outcome to a receipt.v5 whose status is the outcome state and whose verdict
// is empty, under the permit's policy_hash, and commits the outcome, the
// observation it rests on and its settlement time through output_hash, the
// SHA-256 of the closed binding document (CTL-059).
func TestOutcomeReceiptBindsTheStoredOutcome(t *testing.T) {
	o := sampleOutcome()
	r, binding, err := buildOutcomeReceipt(o, "0190a5b4-0000-7000-8000-0000000000dd", 9, sampleHead)
	must(t, err)
	decision, _, err := buildDecisionReceipt(sampleDecision(), "0190a5b4-0000-7000-8000-0000000000cc", 7, sampleHead)
	must(t, err)
	output := sha256.Sum256(binding)
	for field, pair := range map[string][2]string{
		"decision_id": {r.DecisionID, sampleAttempt + ":4"},
		"effect_id":   {r.EffectID, sampleAttempt},
		"status":      {r.Status, "OBSERVED"},
		"verdict":     {r.Verdict, ""},
		"session_id":  {r.SessionID, receiptChainID(tenantA, workspace)},
		"prev_hash":   {r.PrevHash, sampleHead},
		"args_hash":   {r.ArgsHash, hex.EncodeToString(sum256(`{"text":"hi"}`))},
		"output_hash": {r.OutputHash, hex.EncodeToString(output[:])},
		// The outcome is signed under the authority its permit was issued
		// under: the decision receipt's policy_hash.
		"policy_hash": {r.PolicyHash, decision.PolicyHash},
	} {
		if pair[0] != pair[1] {
			t.Errorf("%s = %q, want %q", field, pair[0], pair[1])
		}
	}
	if r.LamportClock != 9 || !r.Timestamp.Equal(sampleSettledAt) {
		t.Fatalf("lamport %d, timestamp %v", r.LamportClock, r.Timestamp)
	}

	var doc map[string]any
	must(t, json.Unmarshal(binding, &doc))
	canonical, err := canonicalize.JCS(doc)
	must(t, err)
	if !bytes.Equal(canonical, binding) {
		t.Fatal("the stored binding bytes are not their own JCS form")
	}
	for field, value := range map[string]any{
		"binding_version": ReceiptBindingVersion, "state": "OBSERVED", "from_state": "DISPATCHED", "verdict": "",
		"attempt_version": float64(4), "outcome": "SUCCEEDED", "outcome_basis": "OBSERVED",
		"observation_id": float64(sampleObservation), "observation_source": "fake.readback", "observation_trust_class": "provider_readback",
		"observation_outcome": "SUCCEEDED", "evidence_digest": hex.EncodeToString(sum256("provider bytes")),
		"result_kind": "github_branch", "result_ref": o.Observation.ResultRef, "observed_at": "2030-01-02T03:08:59Z",
		"settled_at": "2030-01-02T03:09:00.25Z", "decided_at": "", "permit_id": samplePermit, "policy_hash": decision.PolicyHash,
		"argument_digest": r.ArgsHash, "approver_principal_id": "", "step_up_jti": "",
	} {
		if doc[field] != value {
			t.Errorf("binding %s = %v, want %v", field, doc[field], value)
		}
	}
	schema := bindingSchema(t)
	if err := schema.Validate(doc); err != nil {
		t.Fatalf("the outcome binding does not match its schema: %v", err)
	}
	// The closed schema keeps the two kinds apart: an outcome with a verdict
	// or a decision time, or OBSERVED on a reconciled basis, is refused, and
	// so is a decision that carries an outcome.
	for name, mutate := range map[string]func(map[string]any){
		"a verdict":           func(d map[string]any) { d["verdict"] = "ALLOW" },
		"a decision time":     func(d map[string]any) { d["decided_at"] = "2030-01-02T03:04:05Z" },
		"no observation":      func(d map[string]any) { d["observation_id"] = float64(0) },
		"a reconciled basis":  func(d map[string]any) { d["outcome_basis"] = "RECONCILED" },
		"no settlement time":  func(d map[string]any) { d["settled_at"] = "" },
		"a decision's source": func(d map[string]any) { d["from_state"] = "PROPOSED" },
		"an extra member":     func(d map[string]any) { d["grant"] = "all" },
	} {
		changed := map[string]any{}
		for k, v := range doc {
			changed[k] = v
		}
		mutate(changed)
		if err := schema.Validate(changed); err == nil {
			t.Errorf("the binding schema accepted an outcome with %s", name)
		}
	}
	_, decisionBinding, err := buildDecisionReceipt(sampleDecision(), r.ReceiptID, 7, sampleHead)
	must(t, err)
	var decisionDoc map[string]any
	must(t, json.Unmarshal(decisionBinding, &decisionDoc))
	for _, member := range []string{"outcome", "outcome_basis", "observation_source", "evidence_digest", "result_ref", "settled_at"} {
		if decisionDoc[member] != "" {
			t.Errorf("a decision binds %s = %v", member, decisionDoc[member])
		}
	}
	decisionDoc["outcome"] = "SUCCEEDED"
	if err := schema.Validate(decisionDoc); err == nil {
		t.Error("the binding schema accepted a decision that carries an outcome")
	}

	// Any change to the stored outcome changes what the receipt signs.
	for name, mutate := range map[string]func(*storedOutcome){
		"outcome": func(o *storedOutcome) {
			o.Outcome, o.Observation.Outcome, o.ReasonCode = "FAILED", "FAILED", "READBACK_MISMATCH"
		},
		"state":        func(o *storedOutcome) { o.State, o.OutcomeBasis, o.FromState = "RECONCILED", "RECONCILED", "UNKNOWN" },
		"version":      func(o *storedOutcome) { o.Version = 5 },
		"observation":  func(o *storedOutcome) { o.Observation.ID = 42 },
		"evidence":     func(o *storedOutcome) { o.Observation.EvidenceDigest = sum256("other bytes") },
		"result":       func(o *storedOutcome) { o.Observation.ResultRef = "sha256:" + hex.EncodeToString(sum256("other")) },
		"observed at":  func(o *storedOutcome) { o.Observation.ObservedAt = o.Observation.ObservedAt.Add(time.Second) },
		"settled at":   func(o *storedOutcome) { o.SettledAt = o.SettledAt.Add(time.Microsecond) },
		"permit":       func(o *storedOutcome) { o.PermitID = "0190a5b4-0000-7000-8000-0000000000ee" },
		"source trust": func(o *storedOutcome) { o.Observation.TrustClass = "adapter_refusal" },
	} {
		changed := sampleOutcome()
		mutate(&changed)
		other, _, err := buildOutcomeReceipt(changed, r.ReceiptID, 9, sampleHead)
		must(t, err)
		if other.OutputHash == r.OutputHash && other.DecisionID == r.DecisionID && other.Status == r.Status {
			t.Errorf("changing the %s left the signed fields unchanged", name)
		}
	}

	// What is not an outcome of an admitted effect is refused.
	for name, mutate := range map[string]func(*storedOutcome){
		"a decision state":              func(o *storedOutcome) { o.State = "ADMITTED" },
		"a state that is not receipted": func(o *storedOutcome) { o.State = "UNKNOWN" },
		"no outcome":                    func(o *storedOutcome) { o.Outcome = "" },
		"an unknown outcome":            func(o *storedOutcome) { o.Outcome = "UNKNOWN" },
		"a basis the state denies":      func(o *storedOutcome) { o.OutcomeBasis = "RECONCILED" },
		"no permit":                     func(o *storedOutcome) { o.PermitID = "" },
		"no settlement time":            func(o *storedOutcome) { o.SettledAt = time.Time{} },
		"an approver":                   func(o *storedOutcome) { o.ApproverPrincipalID = "human-b" },
		"a decision time":               func(o *storedOutcome) { o.DecidedAt = sampleSettledAt },
		"no observation":                func(o *storedOutcome) { o.Observation = boundObservation{} },
		"a short evidence digest":       func(o *storedOutcome) { o.Observation.EvidenceDigest = []byte{1, 2, 3} },
	} {
		changed := sampleOutcome()
		mutate(&changed)
		if _, _, err := buildOutcomeReceipt(changed, r.ReceiptID, 9, sampleHead); err == nil {
			t.Errorf("%s: an outcome receipt was built", name)
		}
	}
	settled := sampleOutcome()
	settled.State, settled.FromState = "SETTLED", "OBSERVED"
	if _, _, err := buildOutcomeReceipt(settled, r.ReceiptID, 9, sampleHead); err != nil {
		t.Fatalf("SETTLED on an observed basis: %v", err)
	}
	asDecision := sampleDecision()
	asDecision.State = "SETTLED"
	if _, _, err := buildDecisionReceipt(asDecision, r.ReceiptID, 7, sampleHead); err == nil {
		t.Fatal("a decision receipt was built for an outcome state")
	}

	// Signed, the stored bytes verify offline under the gateway key alone,
	// and chain after the decision receipt.
	decisionEnvelope, decisionDigest, err := sealReceipt(testReceiptSigner, decision)
	must(t, err)
	r.PrevHash = decisionDigest
	r.LamportClock = decision.LamportClock + 1
	envelope, _, err := sealReceipt(testReceiptSigner, r)
	must(t, err)
	bundle, err := receiptverify.ParseBundle([]byte("[" + string(decisionEnvelope) + "," + string(envelope) + "]"))
	must(t, err)
	if result := receiptverify.Verify(bundle.Receipts, trustTestKey()); !result.Valid {
		t.Fatalf("the decision and its outcome do not verify as a chain: %+v", result)
	}
}

// outcomeRows is the attempt row an outcome write returns.
func outcomeRows(o storedOutcome) *sqlmock.Rows {
	return sqlmock.NewRows([]string{"workspace_id", "version", "updated_at", "state", "reason_code", "outcome", "outcome_basis",
		"effect_type", "requester_principal_id", "requester_actor_id", "mandate_id", "risk_class", "request_digest", "target_digest",
		"argument_digest", "approval_digest", "approval_expires_at", "quote", "episode_id", "organization_version_id"}).
		AddRow(o.WorkspaceID, o.Version, o.SettledAt, o.State, o.ReasonCode, o.Outcome, o.OutcomeBasis, o.EffectType,
			o.RequesterPrincipalID, o.RequesterActorID, o.MandateID, o.RiskClass, o.RequestDigest, o.TargetDigest,
			o.ArgumentDigest, nil, nil, []byte(`[{"unit":"count","amount":1}]`), nil, nil)
}

// expectOutcomeReceipt expects what recordOutcome runs after its UPDATE:
// the permit and the observation it binds, then the chain row (locked last),
// the signed receipt and the head's compare-and-set.
func expectOutcomeReceipt(mock sqlmock.Sqlmock, o storedOutcome, envelope, binding *[]byte) {
	chain := receiptChainID(tenantA, workspace)
	versions, _ := json.Marshal(o.AuthorityVersions)
	mock.ExpectQuery(`SELECT permit_id::text, authority_versions FROM authority_permits`).WithArgs(tenantA, sampleAttempt).
		WillReturnRows(sqlmock.NewRows([]string{"permit_id", "authority_versions"}).AddRow(o.PermitID, versions))
	ob := o.Observation
	mock.ExpectQuery(`SELECT observation_id, source, trust_class, outcome, evidence_digest, result_kind, result_ref, observed_at\s+FROM authority_observations`).
		WithArgs(tenantA, sampleAttempt, ob.ID).
		WillReturnRows(sqlmock.NewRows([]string{"observation_id", "source", "trust_class", "outcome", "evidence_digest", "result_kind", "result_ref", "observed_at"}).
			AddRow(ob.ID, ob.Source, ob.TrustClass, ob.Outcome, ob.EvidenceDigest, ob.ResultKind, ob.ResultRef, ob.ObservedAt))
	mock.ExpectExec(`INSERT INTO authority_receipt_chains`).WithArgs(tenantA, chain, ReceiptFormat).WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(`SELECT seq, head_digest, format FROM authority_receipt_chains\s+WHERE tenant_id = \$1 AND chain_id = \$2 FOR UPDATE`).
		WithArgs(tenantA, chain).
		WillReturnRows(sqlmock.NewRows([]string{"seq", "head_digest", "format"}).AddRow(int64(8), sampleHead, ReceiptFormat))
	mock.ExpectExec(`INSERT INTO authority_receipts`).
		WithArgs(tenantA, chain, int64(9), sqlmock.AnyArg(), ReceiptFormat, sampleHead, sqlmock.AnyArg(), sampleAttempt,
			o.Version, workspace, o.State, testReceiptSigner.GetKeyID(), bytesArg{envelope}, bytesArg{binding}).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`UPDATE authority_receipt_chains SET seq = \$3, head_digest = \$4`).
		WithArgs(tenantA, chain, int64(9), sqlmock.AnyArg(), int64(8), sampleHead).
		WillReturnResult(sqlmock.NewResult(0, 1))
}

// wantOutcomeEnvelope checks a captured receipt verifies offline and signs
// the outcome as stored.
func wantOutcomeEnvelope(t *testing.T, name string, envelope, binding []byte, o storedOutcome) {
	t.Helper()
	bundle, err := receiptverify.ParseBundle(envelope)
	if err != nil {
		t.Fatalf("%s: no receipt was inserted: %v", name, err)
	}
	r := bundle.Receipts[0]
	if result := receiptverify.Verify(bundle.Receipts, trustTestKey()); !result.Valid {
		t.Fatalf("%s: the inserted receipt does not verify: %+v", name, result)
	}
	var doc receiptBinding
	must(t, json.Unmarshal(binding, &doc))
	output := sha256.Sum256(binding)
	if r.Status != o.State || r.Verdict != "" || r.OutputHash != hex.EncodeToString(output[:]) || r.PrevHash != sampleHead ||
		doc.Outcome != o.Outcome || doc.OutcomeBasis != o.OutcomeBasis || doc.ObservationID != o.Observation.ID ||
		doc.FromState != o.FromState || doc.AttemptVersion != o.Version || doc.PermitID != o.PermitID {
		t.Fatalf("%s: the inserted receipt %+v binds %+v, not the stored outcome", name, r, doc)
	}
}

// TestEveryOutcomeWriteAppendsItsSignedReceiptLast: a read-back that
// establishes an outcome (OBSERVED or RECONCILED), and an adapter's NOT_SENT
// answer, each write the observation, move the exposures, write the attempt
// row, and then lock the workspace's chain head, insert the signed receipt
// of the row the UPDATE returned and move the head by compare-and-set, in
// that order and in the outcome's own transaction (CTL-059).
func TestEveryOutcomeWriteAppendsItsSignedReceiptLast(t *testing.T) {
	db, mock, err := sqlmock.New()
	must(t, err)
	t.Cleanup(func() { _ = db.Close() })
	svc, err := New(db, Config{ReceiptSigner: testReceiptSigner})
	must(t, err)
	ctx := context.Background()
	claimID := uuid.MustParse("0190a5b4-0000-7000-8000-0000000000ff")
	readBackFrom := func(state string) observeTarget {
		return observeTarget{tenantID: tenantA, workspaceID: workspace, attemptID: sampleAttempt, from: state,
			effect: adapters.Effect{EffectType: noteType, Target: "ops"}}
	}
	noExposures := sqlmock.NewRows([]string{"limit_id", "bucket_start", "amount"})
	evidence := sum256("provider bytes")
	readBack := func(outcome adapters.Outcome, absent bool) adapters.ObserveResult {
		r := adapters.ObserveResult{Outcome: outcome, Absent: absent,
			Observation: &adapters.Observation{Source: "fake.readback", TrustClass: "provider_readback", EvidenceDigest: evidence}}
		if outcome == adapters.OutcomeFailed {
			r.Reason = contracts.ReasonReadbackMismatch
		}
		return r
	}
	for _, test := range []struct {
		name  string
		from  string
		want  func(o *storedOutcome)
		write func(tx *sql.Tx) error
	}{
		{
			name: "a read-back that observes SUCCEEDED", from: "DISPATCHED",
			want: func(o *storedOutcome) {},
			write: func(tx *sql.Tx) error {
				return svc.recordObservation(ctx, tx, readBackFrom("DISPATCHED"), readBack(adapters.OutcomeSucceeded, false), true)
			},
		},
		{
			name: "a read-back that reconciles an absent effect as FAILED", from: "UNKNOWN",
			want: func(o *storedOutcome) {
				o.State, o.OutcomeBasis, o.Outcome, o.ReasonCode = "RECONCILED", "RECONCILED", "FAILED", string(contracts.ReasonReadbackMismatch)
				o.Observation.Outcome = "FAILED"
			},
			write: func(tx *sql.Tx) error {
				return svc.recordObservation(ctx, tx, readBackFrom("UNKNOWN"), readBack(adapters.OutcomeFailed, true), false)
			},
		},
		{
			name: "a NOT_SENT answer", from: "DISPATCHING",
			want: func(o *storedOutcome) {
				o.Outcome, o.ReasonCode = "FAILED", string(contracts.ReasonPreconditionFailed)
				o.Observation = boundObservation{ID: sampleObservation, Source: dispatchSource, TrustClass: dispatchTrustClass, Outcome: "FAILED",
					ObservedAt: sampleSettledAt}
			},
			write: func(tx *sql.Tx) error {
				_, err := svc.recordDispatch(ctx, tx, &claimed{tenantID: tenantA, workspaceID: workspace, attemptID: sampleAttempt, claimID: claimID},
					adapters.DispatchResult{Status: adapters.DispatchNotSent, Reason: contracts.ReasonPreconditionFailed})
				return err
			},
		},
	} {
		o := sampleOutcome()
		o.FromState = test.from
		o.Observation.ResultKind, o.Observation.ResultRef = "", ""
		test.want(&o)
		var envelope, binding []byte
		mock.ExpectBegin()
		if test.from == "DISPATCHING" {
			mock.ExpectQuery(`SELECT a.state, p.claim_id FROM authority_effect_attempts a`).WithArgs(tenantA, sampleAttempt).
				WillReturnRows(sqlmock.NewRows([]string{"state", "claim_id"}).AddRow("DISPATCHING", claimID.String()))
			mock.ExpectQuery(`INSERT INTO authority_observations \(tenant_id, attempt_id, source, trust_class, outcome\)\s+VALUES \(\$1, \$2, \$3, \$4, 'FAILED'\) RETURNING observation_id`).
				WithArgs(tenantA, sampleAttempt, dispatchSource, dispatchTrustClass).
				WillReturnRows(sqlmock.NewRows([]string{"observation_id"}).AddRow(sampleObservation))
		} else {
			mock.ExpectQuery(`INSERT INTO authority_observations`).
				WillReturnRows(sqlmock.NewRows([]string{"observation_id"}).AddRow(sampleObservation))
		}
		mock.ExpectQuery(`SELECT limit_id::text, bucket_start, amount FROM authority_exposures`).WillReturnRows(noExposures)
		mock.ExpectQuery(`UPDATE authority_effect_attempts\s+SET state = \$4, outcome = \$5, outcome_basis = \$4`).
			WithArgs(tenantA, sampleAttempt, o.FromState, o.State, o.Outcome, o.ReasonCode).
			WillReturnRows(outcomeRows(o))
		expectOutcomeReceipt(mock, o, &envelope, &binding)
		mock.ExpectCommit()
		tx, err := db.BeginTx(ctx, nil)
		must(t, err)
		if err := test.write(tx); err != nil {
			t.Fatalf("%s: %v", test.name, err)
		}
		must(t, tx.Commit())
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Fatalf("%s: %v", test.name, err)
		}
		wantOutcomeEnvelope(t, test.name, envelope, binding, o)
	}

	// A model call's SETTLED write keeps the outcome its transaction recorded
	// and is receipted at its own version.
	settled := sampleOutcome()
	settled.FromState, settled.State, settled.Version = "OBSERVED", "SETTLED", 5
	var envelope, binding []byte
	mock.ExpectBegin()
	mock.ExpectQuery(`UPDATE authority_effect_attempts\s+SET state = 'SETTLED', reason_code = \$4`).
		WithArgs(tenantA, sampleAttempt, "OBSERVED", "").WillReturnRows(outcomeRows(settled))
	expectOutcomeReceipt(mock, settled, &envelope, &binding)
	mock.ExpectCommit()
	tx, err := db.BeginTx(ctx, nil)
	must(t, err)
	must(t, recordOutcome(ctx, tx, testReceiptSigner, outcomeWrite{tenantID: tenantA, attemptID: sampleAttempt, from: "OBSERVED", to: "SETTLED",
		observationID: sampleObservation}))
	must(t, tx.Commit())
	must(t, mock.ExpectationsWereMet())
	wantOutcomeEnvelope(t, "SETTLED", envelope, binding, settled)

	// A write that is not an outcome is refused before it touches the row.
	for _, w := range []outcomeWrite{
		{tenantID: tenantA, attemptID: sampleAttempt, from: "DISPATCHED", to: "UNKNOWN"},
		{tenantID: tenantA, attemptID: sampleAttempt, from: "DISPATCHED", to: "OBSERVED"},
		{tenantID: tenantA, attemptID: sampleAttempt, from: "OBSERVED", to: "SETTLED", outcome: adapters.OutcomeFailed},
	} {
		mock.ExpectBegin()
		mock.ExpectRollback()
		tx, err := db.BeginTx(ctx, nil)
		must(t, err)
		if err := recordOutcome(ctx, tx, testReceiptSigner, w); err == nil {
			t.Errorf("%s to %s(%q) was recorded", w.from, w.to, w.outcome)
		}
		must(t, tx.Rollback())
	}
	must(t, mock.ExpectationsWereMet())
}

// TestAnOutcomeWhoseReceiptCannotBeSignedFailsTheTransaction: a signing
// failure, or an observation that cannot be found, fails the outcome before
// or instead of the receipt insert, so the caller's transaction rolls back
// and the attempt keeps its state for the reconciliation job (CTL-059).
func TestAnOutcomeWhoseReceiptCannotBeSignedFailsTheTransaction(t *testing.T) {
	var fail atomic.Bool
	db, mock, err := sqlmock.New()
	must(t, err)
	t.Cleanup(func() { _ = db.Close() })
	signer := switchSigner{testReceiptSigner, &fail}
	ctx := context.Background()
	o := sampleOutcome()
	w := outcomeWrite{tenantID: tenantA, attemptID: sampleAttempt, from: "DISPATCHED", to: "OBSERVED", outcome: adapters.OutcomeSucceeded,
		observationID: sampleObservation}
	versions, _ := json.Marshal(o.AuthorityVersions)

	// The signer fails.
	fail.Store(true)
	mock.ExpectBegin()
	mock.ExpectQuery(`UPDATE authority_effect_attempts`).WillReturnRows(outcomeRows(o))
	mock.ExpectQuery(`SELECT permit_id::text, authority_versions FROM authority_permits`).
		WillReturnRows(sqlmock.NewRows([]string{"permit_id", "authority_versions"}).AddRow(o.PermitID, versions))
	mock.ExpectQuery(`SELECT observation_id, source`).WillReturnRows(sqlmock.NewRows([]string{"observation_id", "source", "trust_class", "outcome",
		"evidence_digest", "result_kind", "result_ref", "observed_at"}).AddRow(sampleObservation, "fake.readback", "provider_readback", "SUCCEEDED",
		nil, "", "", sampleSettledAt))
	mock.ExpectExec(`INSERT INTO authority_receipt_chains`).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery(`SELECT seq, head_digest, format FROM authority_receipt_chains`).
		WillReturnRows(sqlmock.NewRows([]string{"seq", "head_digest", "format"}).AddRow(int64(0), "", ReceiptFormat))
	mock.ExpectRollback()
	tx, err := db.BeginTx(ctx, nil)
	must(t, err)
	if err := recordOutcome(ctx, tx, signer, w); err == nil || !strings.Contains(err.Error(), "sign receipt") {
		t.Fatalf("an unsigned outcome: err = %v", err)
	}
	must(t, tx.Rollback())
	must(t, mock.ExpectationsWereMet())

	// The observation the outcome rests on is not there.
	fail.Store(false)
	mock.ExpectBegin()
	mock.ExpectQuery(`UPDATE authority_effect_attempts`).WillReturnRows(outcomeRows(o))
	mock.ExpectQuery(`SELECT permit_id::text, authority_versions FROM authority_permits`).
		WillReturnRows(sqlmock.NewRows([]string{"permit_id", "authority_versions"}).AddRow(o.PermitID, versions))
	mock.ExpectQuery(`SELECT observation_id, source`).WillReturnRows(sqlmock.NewRows([]string{"observation_id"}))
	mock.ExpectRollback()
	tx, err = db.BeginTx(ctx, nil)
	must(t, err)
	if err := recordOutcome(ctx, tx, signer, w); err == nil {
		t.Fatal("an outcome was recorded without the observation it rests on")
	}
	must(t, tx.Rollback())
	must(t, mock.ExpectationsWereMet())

	// No signer at all.
	mock.ExpectBegin()
	mock.ExpectQuery(`UPDATE authority_effect_attempts`).WillReturnRows(outcomeRows(o))
	mock.ExpectQuery(`SELECT permit_id::text, authority_versions FROM authority_permits`).
		WillReturnRows(sqlmock.NewRows([]string{"permit_id", "authority_versions"}).AddRow(o.PermitID, versions))
	mock.ExpectQuery(`SELECT observation_id, source`).WillReturnRows(sqlmock.NewRows([]string{"observation_id", "source", "trust_class", "outcome",
		"evidence_digest", "result_kind", "result_ref", "observed_at"}).AddRow(sampleObservation, "fake.readback", "provider_readback", "SUCCEEDED",
		nil, "", "", sampleSettledAt))
	mock.ExpectRollback()
	tx, err = db.BeginTx(ctx, nil)
	must(t, err)
	if err := recordOutcome(ctx, tx, nil, w); err == nil {
		t.Fatal("an outcome was recorded without a signer")
	}
	must(t, tx.Rollback())
	must(t, mock.ExpectationsWereMet())
}

// TestOutcomeFenceIsADeferredCheckOnEveryOutcomeWrite: migration 16 widens
// the receipt states to the outcomes and holds the outcome fence, a deferred
// constraint trigger on every insert into, and every state or version change
// into, OBSERVED, RECONCILED or SETTLED, requiring the receipt of that
// attempt version at commit. This is the shape a run without PostgreSQL can
// check; TestPostgresAnOutcomeWithoutItsReceiptFailsAtCommit proves the
// behaviour (CTL-059).
func TestOutcomeFenceIsADeferredCheckOnEveryOutcomeWrite(t *testing.T) {
	var ddl string
	for _, m := range migrations {
		if m.version == 16 {
			var err error
			ddl, err = m.ddl()
			must(t, err)
		}
	}
	normalized := strings.Join(strings.Fields(ddl), " ")
	for _, want := range []string{
		"ALTER TABLE authority_receipts ADD CONSTRAINT authority_receipts_state_check CHECK (state IN ('ADMITTED', 'DENIED', 'ESCALATED', 'OBSERVED', 'RECONCILED', 'SETTLED'));",
		"CREATE CONSTRAINT TRIGGER authority_outcome_receipt_insert AFTER INSERT ON authority_effect_attempts DEFERRABLE INITIALLY DEFERRED FOR EACH ROW WHEN (NEW.state IN ('OBSERVED', 'RECONCILED', 'SETTLED')) EXECUTE FUNCTION authority_require_outcome_receipt();",
		"CREATE CONSTRAINT TRIGGER authority_outcome_receipt_update AFTER UPDATE OF state, version ON authority_effect_attempts DEFERRABLE INITIALLY DEFERRED FOR EACH ROW WHEN (NEW.state IN ('OBSERVED', 'RECONCILED', 'SETTLED') AND (OLD.state IS DISTINCT FROM NEW.state OR OLD.version IS DISTINCT FROM NEW.version)) EXECUTE FUNCTION authority_require_outcome_receipt();",
		"WHERE tenant_id = NEW.tenant_id AND attempt_id = NEW.attempt_id AND attempt_version = NEW.version AND state = NEW.state ) THEN RAISE EXCEPTION 'outcome_receipt_missing'",
	} {
		if !strings.Contains(normalized, want) {
			t.Errorf("migration 16 lacks the outcome fence clause %q", want)
		}
	}
	if HeadVersion() < 16 {
		t.Fatalf("the binary serves schema %d, without the outcome fence", HeadVersion())
	}
}
