package admission

// HELM-752 K6 against real PostgreSQL 16 (listed in
// scripts/ci/postgres-proofs.txt): the model-call ledger. A model call is an
// attempt of type model.inference that is claimed without an adapter and
// settled from what the provider reported (ADR-0003).
//
// quantum_posture: computes SHA-256 digests to compare with stored ones;
// signs nothing.

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/effectargs"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/kernel/authority/authorityrows"
)

const modelRoute = "anthropic/claude-sonnet-5-5"

// worker is a model-calling agent: agent-a, carried by the Control Plane.
var worker = Caller{TenantID: tenantA, WorkspaceID: workspace, PrincipalID: "agent-a", ActorID: actor}

// modelFixture gives agent-a a root mandate over model.inference on modelRoute
// with a daily usd_micros limit, and returns the mandate and the limit.
func (f *fixture) modelFixture(limit int64) (authorityrows.Mandate, authorityrows.Limit) {
	f.t.Helper()
	ctx := context.Background()
	must(f.t, f.rows.CreateEffectType(ctx, tenantA, effectargs.ModelInference, authorityrows.RiskLow))
	m := f.rootMandate(tenantA, "agent-a", authorityrows.Terms{
		EffectTypes: []string{effectargs.ModelInference},
		ValidFrom:   f.now.Add(-time.Hour), ValidUntil: f.now.Add(24 * time.Hour),
		Targets: []string{modelRoute},
	})
	l, err := f.rows.CreateLimit(ctx, tenantA, authorityrows.LimitSpec{MandateID: &m.ID, Unit: UnitUSDMicros, Measure: "sum", Window: "day", Value: limit, Span: 1})
	must(f.t, err)
	return m, l
}

func modelProposal(key, route string, held int64) ProposeInput {
	digest := sha256.Sum256([]byte(key))
	args := fmt.Sprintf(`{"schema":"model.inference.v1","api":"anthropic-messages","route":%q,"request_sha256":%q,"input_bytes":1000,"max_output_tokens":512,"stream":true}`,
		route, hex.EncodeToString(digest[:]))
	return ProposeInput{IdempotencyKey: key, CaseID: "work-1", EffectType: effectargs.ModelInference, Target: route,
		Arguments: []byte(args), Quote: []Amount{{Unit: UnitUSDMicros, Amount: held}}}
}

// claimModel proposes and claims one call of held micros.
func (f *fixture) claimModel(key string, held int64) (*ModelCallClaim, Attempt) {
	f.t.Helper()
	a, _, err := f.svc.Propose(context.Background(), worker, modelProposal(key, modelRoute, held))
	must(f.t, err)
	wantState(f.t, "model call admitted", a, "ADMITTED", "")
	claim, claimed, err := f.svc.ClaimModelCall(context.Background(), worker, a.ID, 15*time.Minute)
	must(f.t, err)
	if claim == nil {
		f.t.Fatalf("the claim was refused: %+v", claimed)
	}
	return claim, claimed
}

func (f *fixture) counter(limitID string) (used, reserved int64) {
	f.t.Helper()
	f.ownerTx(tenantA, func(tx *sql.Tx) error {
		return tx.QueryRow(`SELECT COALESCE(sum(used), 0), COALESCE(sum(reserved), 0) FROM authority_counters WHERE limit_id = $1`, limitID).Scan(&used, &reserved)
	})
	return used, reserved
}

func sha(b []byte) []byte {
	sum := sha256.Sum256(b)
	return sum[:]
}

func TestPostgresModelCallConfirmedSettlesTheReportedUsage(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	_, limit := f.modelFixture(10_000)

	claim, claimed := f.claimModel("mi:e1:d1:0", 3_000)
	if claimed.State != "DISPATCHING" || claimed.Permit.ConsumedAt == nil {
		t.Fatalf("after the claim: %+v", claimed)
	}
	if mc := claimed.ModelCall; mc == nil || mc.State != SettlementHeld || mc.HeldMicros != 3_000 || mc.Route != modelRoute ||
		mc.API != effectargs.APIAnthropicMessages || mc.ConfirmedMicros != nil || mc.EstimatedMicros != nil || mc.BillableMicros != 0 || mc.CurrencyCode != "USD" {
		t.Fatalf("held model call = %+v", claimed.ModelCall)
	}
	if used, reserved := f.counter(limit.ID.String()); used != 0 || reserved != 3_000 {
		t.Fatalf("held: used %d reserved %d, want 0 and 3000", used, reserved)
	}
	f.ledgerBalances()

	body := []byte("event: message_stop\n\n")
	settled, err := f.svc.SettleModelCall(ctx, claim, ModelCallOutcome{
		Result: ModelCallConfirmed, ConfirmedMicros: 1_200, Usage: []byte(`{"input_tokens":100,"output_tokens":40}`),
		EvidenceDigest: sha(body),
		Replay: &ModelCallReplay{StatusCode: 200, Headers: map[string]string{"Content-Type": "text/event-stream"}, Body: body,
			BodySHA256: sha(body), TTL: time.Hour},
	})
	must(t, err)
	wantOutcome(t, "confirmed", settled, "SETTLED", "SUCCEEDED", "")
	if settled.OutcomeBasis != "OBSERVED" {
		t.Fatalf("outcome basis = %q, want OBSERVED", settled.OutcomeBasis)
	}
	mc := settled.ModelCall
	if mc.State != SettlementConfirmed || mc.HeldMicros != 3_000 || mc.ConfirmedMicros == nil || *mc.ConfirmedMicros != 1_200 ||
		mc.BillableMicros != 1_200 || mc.EstimatedMicros != nil || string(mc.Usage) != `{"input_tokens": 100, "output_tokens": 40}` {
		t.Fatalf("confirmed model call = %+v (usage %s)", mc, mc.Usage)
	}
	if x := settled.Exposures; len(x) != 1 || x[0].Kind != "confirmed" || x[0].Amount != 1_200 {
		t.Fatalf("exposures = %+v, want one confirmed 1200", x)
	}
	if o := settled.LatestObservation; o == nil || o.Source != "gateway.model" || o.Outcome != "SUCCEEDED" || len(o.EvidenceDigest) != 32 {
		t.Fatalf("observation = %+v", o)
	}
	// The remainder of the hold is released: used 1200, reserved 0.
	if used, reserved := f.counter(limit.ID.String()); used != 1_200 || reserved != 0 {
		t.Fatalf("settled: used %d reserved %d, want 1200 and 0", used, reserved)
	}
	f.ledgerBalances()

	replay, err := f.svc.ModelCallReplay(ctx, worker, settled.ID)
	must(t, err)
	if replay == nil || string(replay.Body) != string(body) || replay.StatusCode != 200 || replay.Headers["Content-Type"] != "text/event-stream" {
		t.Fatalf("replay = %+v", replay)
	}
	// Another workspace of the tenant, and another tenant, cannot read it.
	other := worker
	other.WorkspaceID = "ws-b"
	if r, err := f.svc.ModelCallReplay(ctx, other, settled.ID); err != nil || r != nil {
		t.Fatalf("a replay read from another workspace = %+v, %v", r, err)
	}
	if r, err := f.svc.ModelCallReplay(ctx, Caller{TenantID: tenantB, WorkspaceID: workspace, PrincipalID: "agent-a"}, settled.ID); err != nil || r != nil {
		t.Fatalf("a replay read from another tenant = %+v, %v", r, err)
	}

	// Settling again changes nothing and never writes twice.
	again, err := f.svc.SettleModelCall(ctx, claim, ModelCallOutcome{Result: ModelCallConfirmed, ConfirmedMicros: 9_999})
	must(t, err)
	if again.Version != settled.Version || *again.ModelCall.ConfirmedMicros != 1_200 {
		t.Fatalf("a second settlement changed the call: %+v", again.ModelCall)
	}
	if used, _ := f.counter(limit.ID.String()); used != 1_200 {
		t.Fatalf("used = %d after a repeated settlement", used)
	}
	f.ledgerBalances()
}

func TestPostgresModelCallOverageIsRecordedAsReportedAndNeverBilledPastTheHold(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	_, limit := f.modelFixture(5_000)

	claim, _ := f.claimModel("mi:e1:d2:0", 3_000)
	settled, err := f.svc.SettleModelCall(ctx, claim, ModelCallOutcome{Result: ModelCallConfirmed, ConfirmedMicros: 4_200})
	must(t, err)
	mc := settled.ModelCall
	if mc.State != SettlementConfirmed || *mc.ConfirmedMicros != 4_200 || mc.BillableMicros != 3_000 || mc.HeldMicros != 3_000 {
		t.Fatalf("overage call = %+v: confirmed must be the reported 4200, billable at most the hold", mc)
	}
	if used, reserved := f.counter(limit.ID.String()); used != 4_200 || reserved != 0 {
		t.Fatalf("used %d reserved %d, want the reported 4200 on the counter and nothing held", used, reserved)
	}
	f.ledgerBalances()

	// The counter shows the overrun, so a call that no longer fits is refused
	// (ADR-0003 S7): 4200 used of 5000 leaves 800.
	denied, _, err := f.svc.Propose(ctx, worker, modelProposal("mi:e1:d3:0", modelRoute, 900))
	must(t, err)
	wantState(t, "the next call after an overage", denied, "DENIED", contracts.ReasonBudgetExceeded)
}

func TestPostgresModelCallEstimatedAndCutKeepTheHoldAsEstimated(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	_, limit := f.modelFixture(10_000)

	// A response that completed and was delivered, with no usage in it.
	body := []byte(`{"id":"msg"}`)
	claim, _ := f.claimModel("mi:e1:d4:0", 2_000)
	est, err := f.svc.SettleModelCall(ctx, claim, ModelCallOutcome{Result: ModelCallEstimated, EvidenceDigest: sha(body),
		Replay: &ModelCallReplay{StatusCode: 200, Body: body, BodySHA256: sha(body), TTL: time.Hour}})
	must(t, err)
	wantOutcome(t, "estimated", est, "OBSERVED", "SUCCEEDED", "")
	if mc := est.ModelCall; mc.State != SettlementEstimated || mc.EstimatedMicros == nil || *mc.EstimatedMicros != 2_000 || mc.ConfirmedMicros != nil || mc.BillableMicros != 0 {
		t.Fatalf("estimated call = %+v", mc)
	}
	if x := est.Exposures; len(x) != 1 || x[0].Kind != "estimated" || x[0].Amount != 2_000 {
		t.Fatalf("estimated exposures = %+v", x)
	}
	if used, reserved := f.counter(limit.ID.String()); used != 2_000 || reserved != 0 {
		t.Fatalf("estimated: used %d reserved %d, want the hold counted as used", used, reserved)
	}
	if r, err := f.svc.ModelCallReplay(ctx, worker, est.ID); err != nil || r == nil {
		t.Fatalf("a delivered response is kept for replay: %+v, %v", r, err)
	}
	f.ledgerBalances()

	// A cut response: the attempt is UNKNOWN and retains estimated exposure.
	// A duplicate cut report cannot change that exposure or release it.
	cutClaim, _ := f.claimModel("mi:e1:d5:0", 1_500)
	cut, err := f.svc.SettleModelCall(ctx, cutClaim, ModelCallOutcome{Result: ModelCallCut, Reason: contracts.ReasonProviderError})
	must(t, err)
	wantOutcome(t, "cut", cut, "UNKNOWN", "", contracts.ReasonProviderError)
	if mc := cut.ModelCall; mc.State != SettlementEstimated || *mc.EstimatedMicros != 1_500 {
		t.Fatalf("cut call = %+v", mc)
	}
	if r, err := f.svc.ModelCallReplay(ctx, worker, cut.ID); err != nil || r != nil {
		t.Fatalf("a cut response has no replay: %+v, %v", r, err)
	}
	if used, reserved := f.counter(limit.ID.String()); used != 3_500 || reserved != 0 {
		t.Fatalf("after a cut: used %d reserved %d, want 3500 and 0", used, reserved)
	}
	late, err := f.svc.SettleModelCall(ctx, cutClaim, ModelCallOutcome{Result: ModelCallCut, Reason: contracts.ReasonProviderError})
	must(t, err)
	if late.State != "UNKNOWN" || late.ModelCall.State != SettlementEstimated {
		t.Fatalf("a duplicate cut changed the estimate: %s %+v", late.State, late.ModelCall)
	}
	f.ledgerBalances()
}

func TestPostgresModelCallNotSentReleasesTheHold(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	_, limit := f.modelFixture(10_000)
	claim, _ := f.claimModel("mi:e1:d6:0", 2_500)
	failed, err := f.svc.SettleModelCall(ctx, claim, ModelCallOutcome{Result: ModelCallNotSent, Reason: contracts.ReasonProviderCredentialRejected})
	must(t, err)
	wantOutcome(t, "not sent", failed, "OBSERVED", "FAILED", contracts.ReasonProviderCredentialRejected)
	if mc := failed.ModelCall; mc.State != SettlementReleased || mc.ConfirmedMicros != nil || mc.EstimatedMicros != nil || mc.BillableMicros != 0 {
		t.Fatalf("released call = %+v", mc)
	}
	if x := failed.Exposures; len(x) != 1 || x[0].Kind != "released" || x[0].Amount != 0 {
		t.Fatalf("exposures = %+v", x)
	}
	if used, reserved := f.counter(limit.ID.String()); used != 0 || reserved != 0 {
		t.Fatalf("not sent: used %d reserved %d, want everything given back", used, reserved)
	}
	f.ledgerBalances()
}

// A response that completes after the fence made the attempt UNKNOWN
// reconciles it: RECONCILED, then SETTLED.
func TestPostgresModelCallConfirmationReconcilesAnUnknownAttempt(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	_, limit := f.modelFixture(10_000)
	claim, _ := f.claimModel("mi:e1:d7:0", 3_000)
	f.exec(tenantA, `UPDATE authority_effect_attempts SET state = 'UNKNOWN' WHERE attempt_id = $1`, claim.AttemptID)
	settled, err := f.svc.SettleModelCall(ctx, claim, ModelCallOutcome{Result: ModelCallConfirmed, ConfirmedMicros: 700})
	must(t, err)
	wantOutcome(t, "reconciled", settled, "SETTLED", "SUCCEEDED", "")
	if settled.OutcomeBasis != "RECONCILED" || settled.ModelCall.State != SettlementConfirmed {
		t.Fatalf("basis %q call %+v, want RECONCILED and CONFIRMED", settled.OutcomeBasis, settled.ModelCall)
	}
	if used, reserved := f.counter(limit.ID.String()); used != 700 || reserved != 0 {
		t.Fatalf("used %d reserved %d", used, reserved)
	}
	f.ledgerBalances()
}

func TestPostgresModelCallClaimRefusalsAndScope(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	_, limit := f.modelFixture(10_000)

	// A stop committed after admission refuses the claim: the attempt is
	// CANCELLED, the hold released, and there is no money row (ADR-0001 §1).
	a, _, err := f.svc.Propose(ctx, worker, modelProposal("mi:e2:d1:0", modelRoute, 1_000))
	must(t, err)
	stop, err := f.rows.Stop(ctx, tenantA, authorityrows.StopSpec{Scope: authorityrows.Scope{Kind: authorityrows.ScopeTenant, Key: tenantA}, Reason: "test", IssuedBy: "human-a"})
	must(t, err)
	claim, refused, err := f.svc.ClaimModelCall(ctx, worker, a.ID, time.Minute)
	must(t, err)
	if claim != nil {
		t.Fatal("a stopped tenant's call was claimed")
	}
	wantState(t, "claim under a stop", refused, "CANCELLED", contracts.ReasonEmergencyStopFenced)
	if refused.ModelCall != nil {
		t.Fatalf("a refused claim wrote a money row: %+v", refused.ModelCall)
	}
	if used, reserved := f.counter(limit.ID.String()); used != 0 || reserved != 0 {
		t.Fatalf("a refused claim left used %d reserved %d", used, reserved)
	}
	must(t, f.rows.Lift(ctx, tenantA, stop.ID, authorityrows.WideningApproval{RequesterID: "human-a", ApproverID: "human-b"}))

	// Only the workload that proposed the call claims it.
	b, _, err := f.svc.Propose(ctx, worker, modelProposal("mi:e2:d2:0", modelRoute, 1_000))
	must(t, err)
	must(t, f.rows.CreatePrincipal(ctx, tenantA, "agent-b", authorityrows.PrincipalAgent))
	otherWorkload := Caller{TenantID: tenantA, WorkspaceID: workspace, PrincipalID: "agent-b", ActorID: actor}
	_, _, err = f.svc.ClaimModelCall(ctx, otherWorkload, b.ID, time.Minute)
	wantRefusal(t, "another workload's claim", err, CodePermissionDenied, contracts.ReasonInsufficientPrivilege)
	_, _, err = f.svc.ClaimModelCall(ctx, human, b.ID, time.Minute)
	wantRefusal(t, "a human's claim", err, CodePermissionDenied, contracts.ReasonInsufficientPrivilege)

	// It claims only a model call.
	n, _, err := f.svc.Propose(ctx, human, note("not-a-model-call"))
	must(t, err)
	_, _, err = f.svc.ClaimModelCall(ctx, worker, n.ID, time.Minute)
	if err == nil {
		t.Fatal("ClaimModelCall claimed an attempt that is not a model call")
	}

	// A claimed attempt is not claimed twice: eight concurrent claims, one
	// winner, and the others see the attempt as it is.
	var wg sync.WaitGroup
	var winners atomic.Int32
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c, _, err := f.svc.ClaimModelCall(ctx, worker, b.ID, time.Minute)
			if err != nil {
				t.Error(err)
				return
			}
			if c != nil {
				winners.Add(1)
			}
		}()
	}
	wg.Wait()
	if winners.Load() != 1 {
		t.Fatalf("%d concurrent claims of one permit succeeded, want 1", winners.Load())
	}
	f.ledgerBalances()
}

func TestPostgresModelGrantsReadTheChainNotTheRequest(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()

	// No mandate: the principal is known but grants nothing.
	g, err := f.svc.ModelGrants(ctx, worker, effectargs.ModelInference)
	must(t, err)
	if g.PrincipalKind != "agent" || !g.PrincipalActive || g.Allows(modelRoute) || len(g.Leaves) != 0 {
		t.Fatalf("grants without a mandate = %+v", g)
	}
	if g, err = f.svc.ModelGrants(ctx, Caller{TenantID: tenantA, WorkspaceID: workspace, PrincipalID: "nobody"}, effectargs.ModelInference); err != nil || g.PrincipalKind != "" || g.PrincipalActive {
		t.Fatalf("grants of an unknown principal = %+v, %v", g, err)
	}

	// A root over two routes and a delegated child over one: the chain's
	// intersection is what the leaf may use.
	must(t, f.rows.CreateEffectType(ctx, tenantA, effectargs.ModelInference, authorityrows.RiskLow))
	root := f.rootMandate(tenantA, "human-a", authorityrows.Terms{
		EffectTypes: []string{effectargs.ModelInference}, ValidFrom: f.now.Add(-time.Hour), ValidUntil: f.now.Add(24 * time.Hour),
		Targets: []string{modelRoute, "openai/gpt-6-sol"},
	})
	child, err := f.rows.Delegate(ctx, tenantA, root.ID, "human-a", "agent-a", authorityrows.Terms{
		EffectTypes: []string{effectargs.ModelInference}, ValidFrom: f.now.Add(-time.Hour), ValidUntil: f.now.Add(12 * time.Hour),
		Targets: []string{"openai/gpt-6-sol"},
	})
	must(t, err)
	// A chain limit in usd_micros, a tenant-level one in another unit, and a
	// count limit that needs no amount.
	_, err = f.rows.CreateLimit(ctx, tenantA, authorityrows.LimitSpec{MandateID: &child.ID, Unit: UnitUSDMicros, Measure: "sum", Window: "day", Value: 100, Span: 1})
	must(t, err)
	_, err = f.rows.CreateLimit(ctx, tenantA, authorityrows.LimitSpec{Unit: "tokens", Measure: "sum", Window: "day", Value: 1000, Span: 1})
	must(t, err)
	_, err = f.rows.CreateLimit(ctx, tenantA, authorityrows.LimitSpec{MandateID: &child.ID, Unit: "calls", Measure: "count", Window: "day", Value: 10, Span: 1})
	must(t, err)

	g, err = f.svc.ModelGrants(ctx, worker, effectargs.ModelInference)
	must(t, err)
	if len(g.Leaves) != 1 || g.Leaves[0].MandateID != child.ID.String() || !g.Leaves[0].Active || g.Leaves[0].AnyTarget ||
		len(g.Leaves[0].Targets) != 1 || g.Leaves[0].Targets[0] != "openai/gpt-6-sol" {
		t.Fatalf("grants = %+v, want the child's one route", g)
	}
	if id, ok := g.MandateFor("openai/gpt-6-sol"); !ok || id != child.ID.String() || g.Allows(modelRoute) {
		t.Fatalf("MandateFor follows the intersection: %+v", g)
	}
	if len(g.SumUnits) != 2 || g.SumUnits[0] != "tokens" || g.SumUnits[1] != UnitUSDMicros {
		t.Fatalf("sum units = %v, want tokens and usd_micros (tenant and chain limits; the count limit needs no amount)", g.SumUnits)
	}

	// A second mandate over another route: each route is covered by its own
	// mandate, and a request selects it.
	other, err := f.rows.Delegate(ctx, tenantA, root.ID, "human-a", "agent-a", authorityrows.Terms{
		EffectTypes: []string{effectargs.ModelInference}, ValidFrom: f.now.Add(-time.Hour), ValidUntil: f.now.Add(12 * time.Hour),
		Targets: []string{modelRoute},
	})
	must(t, err)
	g, err = f.svc.ModelGrants(ctx, worker, effectargs.ModelInference)
	must(t, err)
	if len(g.Leaves) != 2 {
		t.Fatalf("leaves = %+v, want both mandates", g.Leaves)
	}
	if id, ok := g.MandateFor(modelRoute); !ok || id != other.ID.String() {
		t.Fatalf("MandateFor(%s) = %q %v, want the second mandate", modelRoute, id, ok)
	}
	if id, ok := g.MandateFor("openai/gpt-6-sol"); !ok || id != child.ID.String() {
		t.Fatalf("MandateFor(gpt) = %q %v, want the first mandate", id, ok)
	}
	if g.Allows("anthropic/claude-opus-5-5") {
		t.Fatal("a route no mandate names is allowed")
	}

	// A revoked mandate is no longer a grant.
	must(t, f.rows.Revoke(ctx, tenantA, child.ID))
	if g, err = f.svc.ModelGrants(ctx, worker, effectargs.ModelInference); err != nil || g.Allows("openai/gpt-6-sol") || !g.Allows(modelRoute) {
		t.Fatalf("grants after a revocation = %+v, %v", g, err)
	}
}

func TestPostgresModelCallReplayExpiresAndClearsItsBody(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.modelFixture(10_000)
	body := []byte("stored")
	claim, _ := f.claimModel("mi:e3:d1:0", 100)
	_, err := f.svc.SettleModelCall(ctx, claim, ModelCallOutcome{Result: ModelCallConfirmed, ConfirmedMicros: 10,
		Replay: &ModelCallReplay{StatusCode: 200, Body: body, BodySHA256: sha(body), TTL: time.Hour}})
	must(t, err)
	if r, err := f.svc.ModelCallReplay(ctx, worker, claim.AttemptID); err != nil || r == nil {
		t.Fatalf("live replay = %+v, %v", r, err)
	}
	// Expired: not replayed, though the body is still there until a
	// settlement clears it.
	f.exec(tenantA, `UPDATE authority_model_replays SET expires_at = now() - interval '1 second' WHERE attempt_id = $1`, claim.AttemptID)
	if r, err := f.svc.ModelCallReplay(ctx, worker, claim.AttemptID); err != nil || r != nil {
		t.Fatalf("an expired replay was served: %+v, %v", r, err)
	}
	next, _ := f.claimModel("mi:e3:d2:0", 100)
	_, err = f.svc.SettleModelCall(ctx, next, ModelCallOutcome{Result: ModelCallConfirmed, ConfirmedMicros: 10})
	must(t, err)
	if n := f.count(tenantA, `SELECT count(*) FROM authority_model_replays WHERE attempt_id = $1 AND body IS NULL AND purged_at IS NOT NULL AND length(body_sha256) = 32`, claim.AttemptID); n != 1 {
		t.Fatalf("the expired body was not cleared with its digest kept (%d rows)", n)
	}
}

func TestPostgresModelCallOutcomesAreValidated(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.modelFixture(10_000)
	claim, _ := f.claimModel("mi:e4:d1:0", 100)
	body := []byte("x")
	for name, out := range map[string]ModelCallOutcome{
		"no result":                     {},
		"negative consumption":          {Result: ModelCallConfirmed, ConfirmedMicros: -1},
		"not sent without a reason":     {Result: ModelCallNotSent},
		"a short evidence digest":       {Result: ModelCallConfirmed, EvidenceDigest: []byte("short")},
		"a replay of a cut call":        {Result: ModelCallCut, Replay: &ModelCallReplay{StatusCode: 200, Body: body, BodySHA256: sha(body), TTL: time.Hour}},
		"a replay that is not success":  {Result: ModelCallConfirmed, Replay: &ModelCallReplay{StatusCode: 500, Body: body, BodySHA256: sha(body), TTL: time.Hour}},
		"a replay without a digest":     {Result: ModelCallConfirmed, Replay: &ModelCallReplay{StatusCode: 200, Body: body, TTL: time.Hour}},
		"a replay without a lifetime":   {Result: ModelCallConfirmed, Replay: &ModelCallReplay{StatusCode: 200, Body: body, BodySHA256: sha(body)}},
		"a settlement without a claim":  {Result: ModelCallConfirmed},
		"a settlement of another claim": {Result: ModelCallConfirmed},
	} {
		c := claim
		switch name {
		case "a settlement without a claim":
			c = nil
		case "a settlement of another claim":
			forged := *claim
			forged.ClaimID = "00000000-0000-7000-8000-000000000000"
			c = &forged
		}
		if _, err := f.svc.SettleModelCall(ctx, c, out); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// Nothing above settled it.
	got, err := f.svc.Get(ctx, worker, claim.AttemptID)
	must(t, err)
	if got.State != "DISPATCHING" || got.ModelCall.State != SettlementHeld {
		t.Fatalf("a refused settlement moved the call: %s %+v", got.State, got.ModelCall)
	}
}

func TestPostgresModelCallSettlementsOfManyCallsKeepTheLedgerBalanced(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	_, limit := f.modelFixture(1_000_000)
	var wg sync.WaitGroup
	results := []ModelCallResult{ModelCallConfirmed, ModelCallEstimated, ModelCallCut, ModelCallNotSent}
	for i := 0; i < 24; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			key := fmt.Sprintf("mi:e5:d%d:0", i)
			a, _, err := f.svc.Propose(ctx, worker, modelProposal(key, modelRoute, 1_000))
			if err != nil || a.State != "ADMITTED" {
				t.Errorf("%s: %v %s", key, err, a.State)
				return
			}
			claim, _, err := f.svc.ClaimModelCall(ctx, worker, a.ID, time.Minute)
			if err != nil || claim == nil {
				t.Errorf("%s: claim %v", key, err)
				return
			}
			out := ModelCallOutcome{Result: results[i%len(results)], Reason: contracts.ReasonProviderError, ConfirmedMicros: int64(100 * (i + 1))}
			if _, err := f.svc.SettleModelCall(ctx, claim, out); err != nil {
				t.Errorf("%s: settle %v", key, err)
			}
		}()
	}
	wg.Wait()
	f.ledgerBalances()
	// Every counter unit is accounted for: confirmed calls consume what they
	// reported, estimated and cut calls their hold, the rest nothing.
	var want int64
	for i := 0; i < 24; i++ {
		switch results[i%len(results)] {
		case ModelCallConfirmed:
			want += int64(100 * (i + 1))
		case ModelCallEstimated, ModelCallCut:
			want += 1_000
		}
	}
	if used, reserved := f.counter(limit.ID.String()); used != want || reserved != 0 {
		t.Fatalf("used %d reserved %d, want %d and 0", used, reserved, want)
	}
}
