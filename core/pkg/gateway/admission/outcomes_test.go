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
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
	"github.com/santhosh-tekuri/jsonschema/v5"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/adapters"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/receiptverify"
)

const (
	sampleObservation = int64(41)
	sampleLimit       = "0190a5b4-0000-7000-8000-0000000000a1"
)

var sampleSettledAt = time.Date(2030, 1, 2, 3, 9, 0, 250000000, time.UTC)

// sampleOutcome is the OBSERVED(SUCCEEDED) row a read-back of sampleDecision's
// attempt leaves: two versions later (DISPATCHING, then this write), under
// the permit the decision issued, its count reservation confirmed.
func sampleOutcome() storedOutcome {
	d := sampleDecision()
	core := storedDecision{TenantID: d.TenantID, WorkspaceID: d.WorkspaceID, AttemptID: d.AttemptID, Version: 4,
		FromState: "DISPATCHED", State: "OBSERVED", EffectType: d.EffectType, RequestDigest: d.RequestDigest,
		TargetDigest: d.TargetDigest, ArgumentDigest: d.ArgumentDigest, PermitID: d.PermitID, AuthorityVersions: d.AuthorityVersions}
	bucket := time.Date(2030, 1, 2, 0, 0, 0, 0, time.UTC)
	return storedOutcome{storedDecision: core, Outcome: "SUCCEEDED", OutcomeBasis: "OBSERVED",
		SettledBy: settledByReadback, Reservation: "confirmed",
		Exposures: []Exposure{{LimitID: sampleLimit, BucketStart: &bucket, Kind: "confirmed", Amount: 1}},
		Observation: boundObservation{ID: sampleObservation, Source: "fake.readback", TrustClass: "provider_readback", Outcome: "SUCCEEDED",
			EvidenceDigest: sum256("provider bytes"), ResultKind: "github_branch", ResultRef: "sha256:" + hex.EncodeToString(sum256("result")),
			ObservedAt: time.Date(2030, 1, 2, 3, 8, 59, 0, time.UTC)},
		SettledAt: sampleSettledAt}
}

// sampleModelOutcome is a confirmed model call's SETTLED row.
func sampleModelOutcome() storedOutcome {
	o := sampleOutcome()
	confirmed := int64(1200)
	o.FromState, o.State, o.Version, o.SettledBy = "OBSERVED", "SETTLED", 5, settledByModelCall
	o.Exposures[0].Amount = 1200
	o.Observation = boundObservation{ID: sampleObservation, Source: modelObservationSource, TrustClass: modelProviderTrust, Outcome: "SUCCEEDED",
		EvidenceDigest: sum256("event: message_stop"), ObservedAt: sampleSettledAt}
	o.ModelCall = &settledModelCall{State: SettlementConfirmed, CurrencyCode: "USD", HeldMicros: 3000, ConfirmedMicros: &confirmed, BillableMicros: 1200,
		UsageDigest: sum256(`{"input_tokens":100,"output_tokens":40}`)}
	return o
}

func outcomeSchema(t *testing.T) *jsonschema.Schema {
	t.Helper()
	path, err := filepath.Abs(filepath.Join("..", "..", "..", "..", "protocols", "json-schemas", "gateway", "outcome-binding.v1.schema.json"))
	must(t, err)
	raw, err := os.ReadFile(path) // #nosec G304 -- repository schema path
	must(t, err)
	compiler := jsonschema.NewCompiler()
	compiler.Draft = jsonschema.Draft2020
	compiler.AssertFormat = true
	url := "file:///" + strings.ReplaceAll(path, string(filepath.Separator), "/")
	must(t, compiler.AddResource(url, bytes.NewReader(raw)))
	schema, err := compiler.Compile(url)
	must(t, err)
	return schema
}

// TestDecisionBindingIsUnchangedByOutcomeReceipts: outcome receipts sign
// their own document, so a decision receipt's binding stays
// helm.gateway.receipt-binding.v1 byte for byte. The digests are those PR
// #1216's builder produced for the same decisions (R12).
func TestDecisionBindingIsUnchangedByOutcomeReceipts(t *testing.T) {
	_, plain, err := buildDecisionReceipt(sampleDecision(), "0190a5b4-0000-7000-8000-0000000000cc", 7, sampleHead)
	must(t, err)
	e := sampleDecision()
	expires := time.Date(2030, 1, 3, 0, 0, 0, 0, time.UTC)
	e.FromState, e.ApprovalDigest, e.ApprovalExpiresAt = "ESCALATED", sum256("approval"), &expires
	e.ApproverPrincipalID, e.ApproverActorID, e.StepUpIssuer, e.StepUpJTI = "human-b", "spiffe://helm/control-plane", "https://issuer.test", "jti-1"
	e.EpisodeID, e.OrganizationVersionID = "ep-1", "ver-1"
	_, readmission, err := buildDecisionReceipt(e, "0190a5b4-0000-7000-8000-0000000000cc", 1, "")
	must(t, err)
	for name, pair := range map[string]struct {
		binding []byte
		want    string
	}{
		"a decision":     {plain, "18c179c85baa413455a39c63044208ff2079a1285e0bd2063e2a1033ea5a306b"},
		"a re-admission": {readmission, "d12d692a6e3972ef8a0ab999db9f187d6538e2dd0bcbbf5c87c595fdad3d6c08"},
	} {
		if sum := sha256.Sum256(pair.binding); hex.EncodeToString(sum[:]) != pair.want {
			t.Errorf("%s: receipt-binding.v1 bytes changed: %s", name, pair.binding)
		}
	}
}

// TestOutcomeReceiptBindsTheStoredOutcome: the pure builder maps a stored
// outcome to a receipt.v5 whose status is the outcome state and whose verdict
// is empty, under the permit's policy_hash, and commits the attempt core, the
// outcome, the observation it rests on and the settlement through
// output_hash, the SHA-256 of the closed outcome-binding.v1 document
// (CTL-059).
func TestOutcomeReceiptBindsTheStoredOutcome(t *testing.T) {
	o := sampleOutcome()
	r, binding, err := buildOutcomeReceipt(o, "0190a5b4-0000-7000-8000-0000000000dd", 9, sampleHead)
	must(t, err)
	decision, decisionBinding, err := buildDecisionReceipt(sampleDecision(), "0190a5b4-0000-7000-8000-0000000000cc", 7, sampleHead)
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
	if r.LamportClock != 9 || !r.Timestamp.Equal(sampleSettledAt) || r.Signature != "" {
		t.Fatalf("lamport %d, timestamp %v, signature %q", r.LamportClock, r.Timestamp, r.Signature)
	}

	var doc map[string]any
	must(t, json.Unmarshal(binding, &doc))
	canonical, err := canonicalize.JCS(doc)
	must(t, err)
	if !bytes.Equal(canonical, binding) {
		t.Fatal("the stored binding bytes are not their own JCS form")
	}
	for field, value := range map[string]any{
		"binding_version": OutcomeBindingVersion, "state": "OBSERVED", "from_state": "DISPATCHED", "attempt_version": float64(4),
		"outcome": "SUCCEEDED", "outcome_basis": "OBSERVED", "settled_by": "readback", "reservation": "confirmed",
		"readback_absent": false, "settled_at": "2030-01-02T03:09:00.25Z", "permit_id": samplePermit,
		"policy_hash": decision.PolicyHash, "argument_digest": r.ArgsHash, "model_call": nil,
	} {
		if doc[field] != value {
			t.Errorf("binding %s = %v, want %v", field, doc[field], value)
		}
	}
	observation := doc["observation"].(map[string]any)
	if observation["id"] != float64(sampleObservation) || observation["evidence_digest"] != hex.EncodeToString(sum256("provider bytes")) ||
		observation["result_kind"] != "github_branch" || observation["observed_at"] != "2030-01-02T03:08:59Z" {
		t.Errorf("binding observation = %v", observation)
	}
	if x := doc["exposures"].([]any); len(x) != 1 || x[0].(map[string]any)["amount"] != "1" || x[0].(map[string]any)["kind"] != "confirmed" ||
		x[0].(map[string]any)["bucket_start"] != "2030-01-02T00:00:00Z" {
		t.Errorf("binding exposures = %v", doc["exposures"])
	}
	schema := outcomeSchema(t)
	if err := schema.Validate(doc); err != nil {
		t.Fatalf("the outcome binding does not match its schema: %v", err)
	}
	// The two documents are distinct closed types: neither schema accepts
	// the other's binding.
	var decisionDoc map[string]any
	must(t, json.Unmarshal(decisionBinding, &decisionDoc))
	if err := schema.Validate(decisionDoc); err == nil {
		t.Error("the outcome schema accepted a decision binding")
	}
	if err := bindingSchema(t).Validate(doc); err == nil {
		t.Error("the decision schema accepted an outcome binding")
	}
	for name, mutate := range map[string]func(map[string]any){
		"a verdict":              func(d map[string]any) { d["verdict"] = "ALLOW" },
		"a reconciled basis":     func(d map[string]any) { d["outcome_basis"] = "RECONCILED" },
		"a decision's source":    func(d map[string]any) { d["from_state"] = "PROPOSED" },
		"no observation":         func(d map[string]any) { delete(d, "observation") },
		"a read-back money row":  func(d map[string]any) { d["model_call"] = map[string]any{} },
		"an estimated read-back": func(d map[string]any) { d["reservation"] = "estimated" },
		"absent but confirmed":   func(d map[string]any) { d["readback_absent"] = true },
		"an unsettled SETTLED":   func(d map[string]any) { d["state"], d["from_state"] = "SETTLED", "OBSERVED" },
		"a numeric amount": func(d map[string]any) {
			d["exposures"] = []any{map[string]any{"limit_id": sampleLimit, "bucket_start": "x", "kind": "confirmed", "amount": 1}}
		},
	} {
		changed := map[string]any{}
		for k, v := range doc {
			changed[k] = v
		}
		mutate(changed)
		if err := schema.Validate(changed); err == nil {
			t.Errorf("the outcome schema accepted a binding with %s", name)
		}
	}

	// A model call's settlement binds its money row, which its schema checks.
	m := sampleModelOutcome()
	_, modelBinding, err := buildOutcomeReceipt(m, r.ReceiptID, 9, sampleHead)
	must(t, err)
	var modelDoc map[string]any
	must(t, json.Unmarshal(modelBinding, &modelDoc))
	if err := schema.Validate(modelDoc); err != nil {
		t.Fatalf("the model call's binding does not match its schema: %v", err)
	}
	call := modelDoc["model_call"].(map[string]any)
	if call["state"] != "CONFIRMED" || call["currency_code"] != "USD" || call["held_micros"] != "3000" || call["confirmed_micros"] != "1200" || call["estimated_micros"] != "" ||
		call["billable_micros"] != "1200" || call["usage_digest"] != hex.EncodeToString(sum256(`{"input_tokens":100,"output_tokens":40}`)) {
		t.Fatalf("binding model_call = %v", call)
	}

	// Any change to the stored outcome or its settlement changes what the
	// receipt signs.
	for name, mutate := range map[string]func(*storedOutcome){
		"outcome": func(o *storedOutcome) {
			o.Outcome, o.Observation.Outcome, o.ReasonCode = "FAILED", "FAILED", "READBACK_MISMATCH"
		},
		"state":       func(o *storedOutcome) { o.State, o.OutcomeBasis, o.FromState = "RECONCILED", "RECONCILED", "UNKNOWN" },
		"version":     func(o *storedOutcome) { o.Version = 5 },
		"observation": func(o *storedOutcome) { o.Observation.ID = 42 },
		"evidence":    func(o *storedOutcome) { o.Observation.EvidenceDigest = sum256("other bytes") },
		"result":      func(o *storedOutcome) { o.Observation.ResultRef = "sha256:" + hex.EncodeToString(sum256("other")) },
		"observed at": func(o *storedOutcome) { o.Observation.ObservedAt = o.Observation.ObservedAt.Add(time.Second) },
		"settled at":  func(o *storedOutcome) { o.SettledAt = o.SettledAt.Add(time.Microsecond) },
		"permit":      func(o *storedOutcome) { o.PermitID = "0190a5b4-0000-7000-8000-0000000000ee" },
		"reservation": func(o *storedOutcome) { o.Reservation, o.Exposures[0].Kind = "released", "released" },
		"exposure":    func(o *storedOutcome) { o.Exposures[0].Amount = 2 },
		"absence": func(o *storedOutcome) {
			o.Outcome, o.Observation.Outcome, o.Reservation, o.Exposures[0].Kind, o.ReadbackAbsent = "FAILED", "FAILED", "released", "released", true
		},
	} {
		changed := sampleOutcome()
		changed.Exposures = append([]Exposure(nil), changed.Exposures...)
		mutate(&changed)
		other, _, err := buildOutcomeReceipt(changed, r.ReceiptID, 9, sampleHead)
		must(t, err)
		if other.OutputHash == r.OutputHash && other.DecisionID == r.DecisionID && other.Status == r.Status {
			t.Errorf("changing the %s left the signed fields unchanged", name)
		}
	}
	// A late usage report re-settles at a new version and signs what changed.
	_, settledBinding, err := buildOutcomeReceipt(sampleModelOutcome(), r.ReceiptID, 9, sampleHead)
	must(t, err)
	for name, mutate := range map[string]func(*settledModelCall){
		"confirmed micros": func(m *settledModelCall) { v := int64(800); m.ConfirmedMicros = &v },
		"billable micros":  func(m *settledModelCall) { m.BillableMicros = 800 },
		"usage":            func(m *settledModelCall) { m.UsageDigest = sum256(`{"output_tokens":1}`) },
		"estimate":         func(m *settledModelCall) { v := int64(3000); m.EstimatedMicros = &v },
		"currency":         func(m *settledModelCall) { m.CurrencyCode = "EUR" },
	} {
		changed := sampleModelOutcome()
		mutate(changed.ModelCall)
		_, other, err := buildOutcomeReceipt(changed, r.ReceiptID, 9, sampleHead)
		must(t, err)
		if bytes.Equal(other, settledBinding) {
			t.Errorf("changing the model call's %s left the binding unchanged", name)
		}
	}

	// What is not an outcome of an admitted effect, or not one the ledger
	// can hold, is refused.
	for name, mutate := range map[string]func(*storedOutcome){
		"a decision state":              func(o *storedOutcome) { o.State = "ADMITTED" },
		"a state that is not receipted": func(o *storedOutcome) { o.State = "UNKNOWN" },
		"OBSERVED from UNKNOWN":         func(o *storedOutcome) { o.FromState = "UNKNOWN" },
		"RECONCILED from DISPATCHED":    func(o *storedOutcome) { o.State, o.OutcomeBasis = "RECONCILED", "RECONCILED" },
		"SETTLED from SETTLED":          func(o *storedOutcome) { *o = sampleModelOutcome(); o.FromState = "SETTLED" },
		"OBSERVED from SETTLED":         func(o *storedOutcome) { o.FromState = "SETTLED" },
		"no outcome":                    func(o *storedOutcome) { o.Outcome = "" },
		"an unknown outcome":            func(o *storedOutcome) { o.Outcome = "UNKNOWN" },
		"an observation of another outcome": func(o *storedOutcome) {
			o.Observation.Outcome = "FAILED"
		},
		"a basis the state denies":    func(o *storedOutcome) { o.OutcomeBasis = "RECONCILED" },
		"no permit":                   func(o *storedOutcome) { o.PermitID = "" },
		"no settlement time":          func(o *storedOutcome) { o.SettledAt = time.Time{} },
		"no observation":              func(o *storedOutcome) { o.Observation = boundObservation{} },
		"a short evidence digest":     func(o *storedOutcome) { o.Observation.EvidenceDigest = []byte{1, 2, 3} },
		"an exposure it did not move": func(o *storedOutcome) { o.Exposures[0].Kind = "held" },
		"an unknown settlement":       func(o *storedOutcome) { o.SettledBy = "operator" },
		"a read-back that re-settles": func(o *storedOutcome) {
			o.FromState = "OBSERVED"
		},
		"a read-back money row": func(o *storedOutcome) { o.ModelCall = sampleModelOutcome().ModelCall },
		"absent but consumed":   func(o *storedOutcome) { o.ReadbackAbsent = true },
		"a NOT_SENT read-back": func(o *storedOutcome) {
			o.SettledBy = settledByNotSent
		},
		"a model call without its row": func(o *storedOutcome) { *o = sampleModelOutcome(); o.ModelCall = nil },
		"a model call without its currency": func(o *storedOutcome) {
			*o = sampleModelOutcome()
			o.ModelCall.CurrencyCode = ""
		},
		"an estimate that is SETTLED": func(o *storedOutcome) {
			*o = sampleModelOutcome()
			o.ModelCall.State, o.Reservation, o.Exposures[0].Kind = SettlementEstimated, "estimated", "estimated"
		},
		"a refused call that succeeded": func(o *storedOutcome) {
			*o = sampleModelOutcome()
			o.State, o.FromState, o.ModelCall.State, o.Reservation, o.Exposures[0].Kind = "OBSERVED", "DISPATCHING", SettlementReleased, "released", "released"
		},
	} {
		changed := sampleOutcome()
		changed.Exposures = append([]Exposure(nil), changed.Exposures...)
		mutate(&changed)
		if _, _, err := buildOutcomeReceipt(changed, r.ReceiptID, 9, sampleHead); err == nil {
			t.Errorf("%s: an outcome receipt was built", name)
		}
	}
	for _, ok := range []func(*storedOutcome){
		func(o *storedOutcome) { *o = sampleModelOutcome() },
		func(o *storedOutcome) {
			*o = sampleModelOutcome()
			o.State, o.FromState, o.Version = "OBSERVED", "OBSERVED", 4
		},
		func(o *storedOutcome) {
			o.State, o.OutcomeBasis, o.FromState, o.Outcome, o.Observation.Outcome = "RECONCILED", "RECONCILED", "UNKNOWN", "FAILED", "FAILED"
			o.Reservation, o.Exposures[0].Kind, o.ReadbackAbsent = "released", "released", true
		},
		func(o *storedOutcome) {
			o.SettledBy, o.FromState, o.Outcome, o.Observation.Outcome, o.Reservation, o.Exposures = settledByNotSent, "DISPATCHING", "FAILED", "FAILED", "released", nil
		},
	} {
		changed := sampleOutcome()
		changed.Exposures = append([]Exposure(nil), changed.Exposures...)
		ok(&changed)
		if _, _, err := buildOutcomeReceipt(changed, r.ReceiptID, 9, sampleHead); err != nil {
			t.Errorf("%s from %s by %s: %v", changed.State, changed.FromState, changed.SettledBy, err)
		}
	}
	if _, _, err := buildDecisionReceipt(storedDecision{State: "SETTLED"}, r.ReceiptID, 7, sampleHead); err == nil {
		t.Fatal("a decision receipt was built for an outcome state")
	}

	// Signed, the stored bytes verify offline under the gateway key alone,
	// and chain after the decision receipt.
	decisionEnvelope, decisionDigest, err := sealReceipt(testReceiptSigner, decision)
	must(t, err)
	r.PrevHash, r.LamportClock = decisionDigest, decision.LamportClock+1
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
		"effect_type", "request_digest", "target_digest", "argument_digest"}).
		AddRow(o.WorkspaceID, o.Version, o.SettledAt, o.State, o.ReasonCode, o.Outcome, o.OutcomeBasis, o.EffectType,
			o.RequestDigest, o.TargetDigest, o.ArgumentDigest)
}

// expectOutcomeReceipt expects what recordOutcome runs after its UPDATE: the
// permit, the observation, the exposures and (for a model call) the money
// row it binds, then the chain row (locked last), the signed receipt and the
// head's compare-and-set at seq.
func expectOutcomeReceipt(mock sqlmock.Sqlmock, o storedOutcome, seq int64, prev string, envelope, binding *[]byte, digest *string) {
	chain := receiptChainID(tenantA, workspace)
	versions, _ := json.Marshal(o.AuthorityVersions)
	mock.ExpectQuery(`SELECT permit_id::text, authority_versions FROM authority_permits`).WithArgs(tenantA, sampleAttempt).
		WillReturnRows(sqlmock.NewRows([]string{"permit_id", "authority_versions"}).AddRow(o.PermitID, versions))
	ob := o.Observation
	mock.ExpectQuery(`SELECT observation_id, source, trust_class, outcome, evidence_digest, result_kind, result_ref, observed_at\s+FROM authority_observations`).
		WithArgs(tenantA, sampleAttempt, ob.ID).
		WillReturnRows(sqlmock.NewRows([]string{"observation_id", "source", "trust_class", "outcome", "evidence_digest", "result_kind", "result_ref", "observed_at"}).
			AddRow(ob.ID, ob.Source, ob.TrustClass, ob.Outcome, ob.EvidenceDigest, ob.ResultKind, ob.ResultRef, ob.ObservedAt))
	exposures := sqlmock.NewRows([]string{"limit_id", "bucket_start", "kind", "amount"})
	for _, x := range o.Exposures {
		exposures.AddRow(x.LimitID, *x.BucketStart, x.Kind, x.Amount)
	}
	mock.ExpectQuery(`SELECT limit_id::text, bucket_start, kind, amount FROM authority_exposures`).WithArgs(tenantA, sampleAttempt).WillReturnRows(exposures)
	if m := o.ModelCall; m != nil {
		mock.ExpectQuery(`SELECT state, currency_code, held_micros, estimated_micros, confirmed_micros, billable_micros, usage\s+FROM authority_model_calls`).
			WithArgs(tenantA, sampleAttempt).
			WillReturnRows(sqlmock.NewRows([]string{"state", "currency_code", "held_micros", "estimated_micros", "confirmed_micros", "billable_micros", "usage"}).
				AddRow(m.State, m.CurrencyCode, m.HeldMicros, nullInt(m.EstimatedMicros), nullInt(m.ConfirmedMicros), m.BillableMicros, []byte(`{"output_tokens": 40, "input_tokens": 100}`)))
	}
	mock.ExpectExec(`INSERT INTO authority_receipt_chains`).WithArgs(tenantA, chain, ReceiptFormat).WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(`SELECT seq, head_digest, format FROM authority_receipt_chains\s+WHERE tenant_id = \$1 AND chain_id = \$2 FOR UPDATE`).
		WithArgs(tenantA, chain).
		WillReturnRows(sqlmock.NewRows([]string{"seq", "head_digest", "format"}).AddRow(seq-1, prev, ReceiptFormat))
	mock.ExpectExec(`INSERT INTO authority_receipts`).
		WithArgs(tenantA, chain, seq, sqlmock.AnyArg(), ReceiptFormat, prev, stringArg{digest}, sampleAttempt,
			o.Version, workspace, o.State, testReceiptSigner.GetKeyID(), bytesArg{envelope}, bytesArg{binding}).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`UPDATE authority_receipt_chains SET seq = \$3, head_digest = \$4`).
		WithArgs(tenantA, chain, seq, sqlmock.AnyArg(), seq-1, prev).
		WillReturnResult(sqlmock.NewResult(0, 1))
}

// wantOutcomeEnvelope checks a captured receipt verifies offline and signs
// the outcome as stored.
func wantOutcomeEnvelope(t *testing.T, name string, envelope, binding []byte, o storedOutcome, prev string) {
	t.Helper()
	bundle, err := receiptverify.ParseBundle(envelope)
	if err != nil {
		t.Fatalf("%s: no receipt was inserted: %v", name, err)
	}
	r := bundle.Receipts[0]
	if result := receiptverify.Verify(bundle.Receipts, trustTestKey()); !result.Valid {
		t.Fatalf("%s: the inserted receipt does not verify: %+v", name, result)
	}
	var doc outcomeBinding
	decoder := json.NewDecoder(bytes.NewReader(binding))
	decoder.DisallowUnknownFields()
	must(t, decoder.Decode(&doc))
	output := sha256.Sum256(binding)
	if r.Status != o.State || r.Verdict != "" || r.OutputHash != hex.EncodeToString(output[:]) || r.PrevHash != prev ||
		doc.BindingVersion != OutcomeBindingVersion || doc.Outcome != o.Outcome || doc.OutcomeBasis != o.OutcomeBasis ||
		doc.Observation.ID != o.Observation.ID || doc.FromState != o.FromState || doc.AttemptVersion != o.Version ||
		doc.PermitID != o.PermitID || doc.SettledBy != o.SettledBy || doc.Reservation != o.Reservation || doc.ReadbackAbsent != o.ReadbackAbsent ||
		len(doc.Exposures) != len(o.Exposures) || (doc.ModelCall == nil) != (o.ModelCall == nil) {
		t.Fatalf("%s: the inserted receipt %+v binds %+v, not the stored outcome", name, r, doc)
	}
	if m := doc.ModelCall; m != nil && (m.ConfirmedMicros != decimal(o.ModelCall.ConfirmedMicros) || m.UsageDigest != hex.EncodeToString(o.ModelCall.UsageDigest) ||
		m.CurrencyCode != o.ModelCall.CurrencyCode) {
		t.Fatalf("%s: the model call binds %+v", name, m)
	}
}

// TestEveryOutcomeWriteAppendsItsSignedReceiptLast: a read-back that
// establishes an outcome (OBSERVED or RECONCILED), an adapter's NOT_SENT
// answer and a model call's SETTLED write each write the observation, move
// the exposures, write the attempt row, and then lock the workspace's chain
// head, insert the signed receipt of the row the UPDATE returned and move the
// head by compare-and-set, in that order and in the outcome's own
// transaction (CTL-059).
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
				o.Observation.Outcome, o.Reservation, o.Exposures, o.ReadbackAbsent = "FAILED", "released", nil, true
			},
			write: func(tx *sql.Tx) error {
				return svc.recordObservation(ctx, tx, readBackFrom("UNKNOWN"), readBack(adapters.OutcomeFailed, true), false)
			},
		},
		{
			name: "a NOT_SENT answer", from: "DISPATCHING",
			want: func(o *storedOutcome) {
				o.Outcome, o.ReasonCode, o.SettledBy, o.Reservation, o.Exposures = "FAILED", string(contracts.ReasonPreconditionFailed), settledByNotSent, "released", nil
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
		var digest string
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
		mock.ExpectQuery(`SELECT limit_id::text, bucket_start, amount FROM authority_exposures`).
			WillReturnRows(sqlmock.NewRows([]string{"limit_id", "bucket_start", "amount"}))
		mock.ExpectQuery(`UPDATE authority_effect_attempts\s+SET state = \$4, outcome = \$5, outcome_basis = \$4`).
			WithArgs(tenantA, sampleAttempt, o.FromState, o.State, o.Outcome, o.ReasonCode).
			WillReturnRows(outcomeRows(o))
		expectOutcomeReceipt(mock, o, 9, sampleHead, &envelope, &binding, &digest)
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
		wantOutcomeEnvelope(t, test.name, envelope, binding, o, sampleHead)
	}

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

// TestModelCallSettlementAppendsItsSignedReceiptsLast: a model call's
// settlement moves its money and records its observation and replay first,
// then writes each outcome with its signed receipt: a refused call is
// OBSERVED(FAILED) on its released row; a confirmed call is OBSERVED and then
// SETTLED, each receipt chained after the other and binding the confirmed and
// billable amounts and the usage digest the row holds (CTL-059).
func TestModelCallSettlementAppendsItsSignedReceiptsLast(t *testing.T) {
	db, mock, err := sqlmock.New()
	must(t, err)
	t.Cleanup(func() { _ = db.Close() })
	svc, err := New(db, Config{ReceiptSigner: testReceiptSigner})
	must(t, err)
	ctx := context.Background()
	call := lockedAttempt{tenantID: tenantA, id: sampleAttempt, workspaceID: workspace, state: "DISPATCHED"}
	usage := sum256(`{"input_tokens":100,"output_tokens":40}`)

	refused := sampleModelOutcome()
	refused.State, refused.FromState, refused.Version, refused.Outcome, refused.ReasonCode = "OBSERVED", "DISPATCHED", 4, "FAILED", string(contracts.ReasonProviderError)
	refused.Reservation, refused.Exposures = "released", nil
	refused.Observation = boundObservation{ID: sampleObservation, Source: modelObservationSource, TrustClass: "adapter_refusal", Outcome: "FAILED",
		ObservedAt: sampleSettledAt}
	refused.ModelCall = &settledModelCall{State: SettlementReleased, CurrencyCode: "USD", HeldMicros: 3000, UsageDigest: usage}

	observed := sampleModelOutcome()
	observed.State, observed.Version, observed.FromState = "OBSERVED", 4, "DISPATCHED"
	observed.Exposures = nil
	settled := sampleModelOutcome()
	settled.Exposures = nil
	settled.ModelCall.UsageDigest, observed.ModelCall.UsageDigest = usage, usage

	for _, test := range []struct {
		name     string
		out      ModelCallOutcome
		money    func()
		outcomes []storedOutcome
	}{
		{
			name: "refused",
			out:  ModelCallOutcome{Result: ModelCallNotSent, Reason: contracts.ReasonProviderError},
			money: func() {
				mock.ExpectQuery(`SELECT limit_id::text, bucket_start, amount FROM authority_exposures`).
					WillReturnRows(sqlmock.NewRows([]string{"limit_id", "bucket_start", "amount"}))
				mock.ExpectExec(`UPDATE authority_model_calls`).WillReturnResult(sqlmock.NewResult(0, 1))
			},
			outcomes: []storedOutcome{refused},
		},
		{
			name: "confirmed",
			out:  ModelCallOutcome{Result: ModelCallConfirmed, ConfirmedMicros: 1200, EvidenceDigest: sum256("event: message_stop")},
			money: func() {
				mock.ExpectQuery(`SELECT e.limit_id::text, e.bucket_start, e.amount, l.unit, l.measure`).
					WillReturnRows(sqlmock.NewRows([]string{"limit_id", "bucket_start", "amount", "unit", "measure"}))
				mock.ExpectExec(`UPDATE authority_model_calls`).WillReturnResult(sqlmock.NewResult(0, 1))
			},
			outcomes: []storedOutcome{observed, settled},
		},
	} {
		mock.ExpectBegin()
		test.money()
		mock.ExpectQuery(`INSERT INTO authority_observations`).WillReturnRows(sqlmock.NewRows([]string{"observation_id"}).AddRow(sampleObservation))
		mock.ExpectExec(`UPDATE authority_model_replays SET body = NULL`).WillReturnResult(sqlmock.NewResult(0, 0))
		envelopes, bindings := make([][]byte, len(test.outcomes)), make([][]byte, len(test.outcomes))
		digests := make([]string, len(test.outcomes))
		// The chain row the mock returns for each append; that each receipt
		// links to the one before is proven against PostgreSQL.
		heads := []string{sampleHead, strings.Repeat("c", 64)}
		for i, o := range test.outcomes {
			if o.State == "SETTLED" {
				mock.ExpectQuery(`UPDATE authority_effect_attempts\s+SET state = 'SETTLED'`).WithArgs(tenantA, sampleAttempt, o.FromState, "").
					WillReturnRows(outcomeRows(o))
			} else {
				mock.ExpectQuery(`UPDATE authority_effect_attempts\s+SET state = \$4, outcome = \$5`).
					WithArgs(tenantA, sampleAttempt, o.FromState, o.State, o.Outcome, o.ReasonCode).WillReturnRows(outcomeRows(o))
			}
			expectOutcomeReceipt(mock, o, int64(9+i), heads[i], &envelopes[i], &bindings[i], &digests[i])
		}
		mock.ExpectCommit()
		tx, err := db.BeginTx(ctx, nil)
		must(t, err)
		if err := svc.settleModelCallTx(ctx, tx, call, 3000, "held", test.out); err != nil {
			t.Fatalf("%s: %v", test.name, err)
		}
		must(t, tx.Commit())
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Fatalf("%s: %v", test.name, err)
		}
		for i, o := range test.outcomes {
			wantOutcomeEnvelope(t, test.name+" "+o.State, envelopes[i], bindings[i], o, heads[i])
		}
	}
}

// TestAnOutcomeWhoseReceiptCannotBeSignedFailsTheTransaction: a signing
// failure, an observation that cannot be found, or no signer fails the
// outcome before or instead of the receipt insert, so the caller's
// transaction rolls back and the attempt keeps its state for the
// reconciliation job (CTL-059).
func TestAnOutcomeWhoseReceiptCannotBeSignedFailsTheTransaction(t *testing.T) {
	var fail atomic.Bool
	db, mock, err := sqlmock.New()
	must(t, err)
	t.Cleanup(func() { _ = db.Close() })
	signer := switchSigner{testReceiptSigner, &fail}
	ctx := context.Background()
	o := sampleOutcome()
	w := outcomeWrite{tenantID: tenantA, attemptID: sampleAttempt, from: "DISPATCHED", to: "OBSERVED", outcome: adapters.OutcomeSucceeded,
		observationID: sampleObservation, settledBy: settledByReadback, reservation: "confirmed"}
	versions, _ := json.Marshal(o.AuthorityVersions)
	observation := func() *sqlmock.Rows {
		return sqlmock.NewRows([]string{"observation_id", "source", "trust_class", "outcome", "evidence_digest", "result_kind", "result_ref", "observed_at"}).
			AddRow(sampleObservation, "fake.readback", "provider_readback", "SUCCEEDED", nil, "", "", sampleSettledAt)
	}
	prefix := func(found bool) {
		mock.ExpectBegin()
		mock.ExpectQuery(`UPDATE authority_effect_attempts`).WillReturnRows(outcomeRows(o))
		mock.ExpectQuery(`SELECT permit_id::text, authority_versions FROM authority_permits`).
			WillReturnRows(sqlmock.NewRows([]string{"permit_id", "authority_versions"}).AddRow(o.PermitID, versions))
		if !found {
			mock.ExpectQuery(`SELECT observation_id, source`).WillReturnRows(sqlmock.NewRows([]string{"observation_id"}))
			return
		}
		mock.ExpectQuery(`SELECT observation_id, source`).WillReturnRows(observation())
		mock.ExpectQuery(`SELECT limit_id::text, bucket_start, kind, amount FROM authority_exposures`).
			WillReturnRows(sqlmock.NewRows([]string{"limit_id", "bucket_start", "kind", "amount"}))
	}
	for name, test := range map[string]struct {
		signer ReceiptSigner
		fail   bool
		found  bool
		chain  bool
		want   string
	}{
		"the signer fails":        {signer: signer, fail: true, found: true, chain: true, want: "sign receipt"},
		"the observation is gone": {signer: signer, found: false, want: "observation"},
		"there is no signer":      {signer: nil, found: true, want: "no receipt signer"},
	} {
		fail.Store(test.fail)
		prefix(test.found)
		if test.chain {
			mock.ExpectExec(`INSERT INTO authority_receipt_chains`).WillReturnResult(sqlmock.NewResult(0, 1))
			mock.ExpectQuery(`SELECT seq, head_digest, format FROM authority_receipt_chains`).
				WillReturnRows(sqlmock.NewRows([]string{"seq", "head_digest", "format"}).AddRow(int64(0), "", ReceiptFormat))
		}
		mock.ExpectRollback()
		tx, err := db.BeginTx(ctx, nil)
		must(t, err)
		if err := recordOutcome(ctx, tx, test.signer, w); err == nil || !strings.Contains(err.Error(), test.want) {
			t.Fatalf("%s: err = %v, want %q", name, err, test.want)
		}
		must(t, tx.Rollback())
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}
}

// TestOutcomeFenceIsADeferredCheckOnEveryOutcomeWrite: migration 16 widens
// the receipt states to the outcomes and holds the outcome fence, a deferred
// constraint trigger on every insert into, and every state or version change
// into, OBSERVED, RECONCILED or SETTLED, requiring the receipt of that
// attempt version at commit. It locks authority_effect_attempts before it
// alters authority_receipts, and pins both fences' search_path to the
// migration's schema. This is the shape a run without PostgreSQL can check;
// TestPostgresAnOutcomeWithoutItsReceiptFailsAtCommit and
// TestPostgresFencesIgnoreALookAlikeReceiptTable prove the behaviour
// (CTL-059).
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
		"FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace WHERE c.oid = 'authority_receipts'::regclass;",
		"EXECUTE format('ALTER FUNCTION authority_require_decision_receipt() SET search_path = %I, pg_temp', receipts_schema);",
		"EXECUTE format('ALTER FUNCTION authority_require_outcome_receipt() SET search_path = %I, pg_temp', receipts_schema);",
	} {
		if !strings.Contains(normalized, want) {
			t.Errorf("migration 16 lacks the outcome fence clause %q", want)
		}
	}
	lock := strings.Index(normalized, "LOCK TABLE authority_effect_attempts IN SHARE ROW EXCLUSIVE MODE;")
	alter := strings.Index(normalized, "ALTER TABLE authority_receipts")
	if lock < 0 || alter < 0 || lock > alter {
		t.Errorf("migration 16 must lock authority_effect_attempts (at %d) before it alters authority_receipts (at %d)", lock, alter)
	}
	if HeadVersion() < 16 {
		t.Fatalf("the binary serves schema %d, without the outcome fence", HeadVersion())
	}
}

// TestUsageDigestIsTheRFC8785Form: a model call's usage digest is the SHA-256
// of the usage's RFC 8785 form, numbers serialized as ECMAScript does, so the
// usage a provider sent and the JSONB rendering of it the call row returns
// have one digest. HELM's number-literal canonical form would give two, and
// its interoperable form refuses these numbers outright.
func TestUsageDigestIsTheRFC8785Form(t *testing.T) {
	const canonical = `{"cost":1.5,"input_tokens":100,"output_tokens":40,"rate":1e-7}`
	sent := []byte(`{"output_tokens":40, "cost":1.50, "rate":1e-7, "input_tokens":100}`)
	stored := []byte(`{"rate": 0.0000001, "cost": 1.50, "input_tokens": 100, "output_tokens": 40}`)
	for name, usage := range map[string][]byte{"as sent": sent, "as JSONB renders it": stored} {
		digest, err := usageDigest(usage)
		must(t, err)
		if !bytes.Equal(digest, sum256(canonical)) {
			t.Errorf("%s: usage digest %x, want SHA-256 of %s", name, digest, canonical)
		}
	}
	literalSent, err := canonicalize.JCS(json.RawMessage(sent))
	must(t, err)
	literalStored, err := canonicalize.JCS(json.RawMessage(stored))
	must(t, err)
	if bytes.Equal(literalSent, literalStored) {
		t.Fatal("number-literal JCS already agrees on these numbers; the test no longer shows why RFC 8785 numbers are needed")
	}
	if _, err := canonicalize.InteroperableJCS(json.RawMessage(sent)); err == nil {
		t.Fatal("the interoperable form accepted a fractional usage")
	}
	if _, err := usageDigest([]byte(`{"input_tokens":`)); err == nil {
		t.Fatal("a usage that is not JSON was digested")
	}
}
