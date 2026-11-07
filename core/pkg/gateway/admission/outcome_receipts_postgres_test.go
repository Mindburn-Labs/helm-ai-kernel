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
// permit, the attempt's outcome and an observation the ledger holds, and the
// last receipt describes the attempt's current version. It returns the
// bindings, in the same order.
func (f *fixture) wantReceipted(a Attempt, states ...string) []receiptBinding {
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
	bindings := make([]receiptBinding, len(rows))
	var decision *contracts.Receipt
	for i, r := range rows {
		receipt := mustReceipt(f.t, r.envelope)
		if result := verifyBundle(f.t, r.envelope, trustTestKey()); !result.Valid {
			f.t.Fatalf("receipt %d of %s does not verify alone: %+v", r.seq, a.ID, result)
		}
		must(f.t, json.Unmarshal(r.binding, &bindings[i]))
		b := bindings[i]
		if ref := a.Receipts[i]; ref.ReceiptID != r.receiptID || ref.Seq != uint64(r.seq) || ref.State != r.state || ref.Digest != r.digest {
			f.t.Fatalf("receipt ref %d of %s = %+v, the chain holds %+v", i, a.ID, ref, r)
		}
		if i > 0 && r.seq <= rows[i-1].seq {
			f.t.Fatalf("receipt %d of %s does not follow its predecessor in the chain", i, a.ID)
		}
		switch r.state {
		case "ADMITTED", "DENIED", "ESCALATED":
			decision = receipt
			if b.Outcome != "" || b.ObservationID != 0 || b.SettledAt != "" || receipt.Verdict == "" {
				f.t.Fatalf("decision receipt of %s binds an outcome: %+v", a.ID, b)
			}
			continue
		}
		var source, trust string
		var observed sql.NullString
		f.ownerTx(tenantA, func(tx *sql.Tx) error {
			return tx.QueryRow(`SELECT source, trust_class, outcome FROM authority_observations WHERE attempt_id = $1 AND observation_id = $2`,
				a.ID, b.ObservationID).Scan(&source, &trust, &observed)
		})
		if decision == nil || receipt.PolicyHash != decision.PolicyHash || receipt.Verdict != "" || receipt.ArgsHash != decision.ArgsHash ||
			a.Permit == nil || b.PermitID != a.Permit.ID || b.Outcome != a.Outcome || b.OutcomeBasis != a.OutcomeBasis ||
			b.ObservationSource != source || b.ObservationTrustClass != trust || b.ObservationOutcome != observed.String ||
			b.SettledAt == "" || b.DecidedAt != "" {
			f.t.Fatalf("outcome receipt %d of %s binds %+v (receipt %+v), not the stored outcome %+v", r.seq, a.ID, b, receipt, a)
		}
	}
	// An attempt in a receipted state was last written with its receipt;
	// UNKNOWN, ESCALATED_TO_HUMAN and the lifecycle in between carry none.
	if _, _, err := receiptVerdict(a.State); err == nil {
		if last := rows[len(rows)-1]; last.version != a.Version || last.state != a.State {
			f.t.Fatalf("the last receipt of %s describes %s at %d, the attempt is %s at %d", a.ID, last.state, last.version, a.State, a.Version)
		}
	}
	return bindings
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
	if b.FromState != "DISPATCHED" || b.ObservationSource != "fake.readback" || b.EvidenceDigest != hex.EncodeToString(sha([]byte("provider bytes"))) {
		t.Fatalf("the success binding = %+v", b)
	}

	// An adapter failure: the read-back finds an object that contradicts it.
	fake.set(nil, contradicted)
	failed, _, err := svc.Dispatch(ctx, workload, f.propose(human, quotaNote("outcome-contradicted")).ID)
	must(t, err)
	wantOutcome(t, "a contradicted read-back", failed, "OBSERVED", "FAILED", contracts.ReasonReadbackMismatch)
	if b := f.wantReceipted(failed, "ADMITTED", "OBSERVED")[1]; b.ReasonCode != string(contracts.ReasonReadbackMismatch) || b.ObservationOutcome != "FAILED" {
		t.Fatalf("the failure binding = %+v", b)
	}

	// NOT_SENT: the adapter's own answer is the outcome.
	fake.set(notSent, nil)
	refused, _, err := svc.Dispatch(ctx, workload, f.propose(human, quotaNote("outcome-not-sent")).ID)
	must(t, err)
	wantOutcome(t, "NOT_SENT", refused, "OBSERVED", "FAILED", contracts.ReasonPreconditionFailed)
	if b := f.wantReceipted(refused, "ADMITTED", "OBSERVED")[1]; b.FromState != "DISPATCHING" || b.ObservationSource != dispatchSource ||
		b.ObservationTrustClass != dispatchTrustClass || b.EvidenceDigest != "" {
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
	confirmed, err := f.svc.SettleModelCall(ctx, claim, ModelCallOutcome{Result: ModelCallConfirmed, ConfirmedMicros: 1_200, EvidenceDigest: sha(body)})
	must(t, err)
	wantOutcome(t, "confirmed", confirmed, "SETTLED", "SUCCEEDED", "")
	bs := f.wantReceipted(confirmed, "ADMITTED", "OBSERVED", "SETTLED")
	if bs[1].AttemptVersion != confirmed.Version-1 || bs[2].FromState != "OBSERVED" || bs[1].ObservationID != bs[2].ObservationID ||
		bs[2].ObservationSource != modelObservationSource || bs[2].EvidenceDigest != hex.EncodeToString(sha(body)) {
		t.Fatalf("the confirmed call's bindings = %+v", bs)
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
	f.wantReceipted(estimated, "ADMITTED", "OBSERVED")
	late, err := f.svc.SettleModelCall(ctx, claim, ModelCallOutcome{Result: ModelCallConfirmed, ConfirmedMicros: 800, EvidenceDigest: sha([]byte("usage"))})
	must(t, err)
	wantOutcome(t, "confirmed late", late, "SETTLED", "SUCCEEDED", "")
	bs = f.wantReceipted(late, "ADMITTED", "OBSERVED", "OBSERVED", "SETTLED")
	if bs[2].FromState != "OBSERVED" || bs[2].ObservationID == bs[1].ObservationID || bs[3].ObservationID != bs[2].ObservationID {
		t.Fatalf("the late confirmation's bindings = %+v", bs)
	}

	// Refused by the provider: OBSERVED(FAILED) on the adapter's refusal.
	claim, _ = f.claimModel("mi:receipt:refused", 1_000)
	refused, err := f.svc.SettleModelCall(ctx, claim, ModelCallOutcome{Result: ModelCallNotSent, Reason: contracts.ReasonProviderError})
	must(t, err)
	wantOutcome(t, "not sent", refused, "OBSERVED", "FAILED", contracts.ReasonProviderError)
	if b := f.wantReceipted(refused, "ADMITTED", "OBSERVED")[1]; b.ObservationTrustClass != "adapter_refusal" || b.EvidenceDigest != "" {
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
	f.wantReceipted(cut, "ADMITTED")
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
		var b receiptBinding
		must(t, json.Unmarshal(r.binding, &b))
		if b.Outcome != "SUCCEEDED" || mustReceipt(t, r.envelope).OutputHash != hex.EncodeToString(sha(r.binding)) {
			t.Fatalf("outcome binding %+v", b)
		}
	}
}
