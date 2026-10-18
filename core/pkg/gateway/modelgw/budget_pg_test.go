package modelgw

// Trial budget behavior through the real PostgreSQL gateway and a loopback
// provider. The provider is a boundary double; holds and settlements are not.

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/admission"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/effectargs"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/kernel/authority/authorityrows"
	"github.com/google/uuid"
	"github.com/lib/pq"
)

// legacyModelInsert uses the admission INSERT shape from a pre-fence gateway:
// it omits model_writer_protocol, so PostgreSQL supplies the legacy default.
// The other digests are valid placeholders because this tests the INSERT fence
// and ON CONFLICT path, not the old binary's request-digest calculation. It
// runs under the real gateway role and tenant RLS, not the migration owner.
func legacyModelInsert(ctx context.Context, e *env, caller admission.Caller, c *call, key string) error {
	args, err := json.Marshal(modelArgs{Schema: "model.inference.v1", API: c.API, Route: c.Route.ID,
		RequestSHA256: sha256hex(c.Body), InputBytes: int64(len(c.Body)), MaxOutputTokens: c.MaxOutputTokens, Stream: c.Stream})
	if err != nil {
		return err
	}
	amount, err := c.Route.Quote(int64(len(c.Body)), c.MaxOutputTokens, c.MayWriteCache)
	if err != nil {
		return err
	}
	quote, err := json.Marshal([]admission.Amount{{Unit: admission.UnitUSDMicros, Amount: amount}})
	if err != nil {
		return err
	}
	requestDigest := sha256.Sum256([]byte("legacy model proposal"))
	argumentDigest := sha256.Sum256(args)
	targetDigest := sha256.Sum256([]byte(c.Route.ID))
	tx, err := e.runtime.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `SELECT set_config('app.current_tenant', $1, true)`, caller.TenantID); err != nil {
		return err
	}
	episodeID, organizationVersionID, caseID := "", "", ""
	if caller.Episode != nil {
		episodeID, organizationVersionID, caseID = caller.Episode.EpisodeID, caller.Episode.OrganizationVersionID, caller.Episode.WorkItemID
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO authority_effect_attempts
		(tenant_id, attempt_id, workspace_id, idempotency_key, request_digest, requester_principal_id,
		 requester_actor_id, commitment_id, case_id, effect_type, target, target_digest, argument_digest, quote,
		 distinct_values, episode_id, organization_version_id, state)
		VALUES ($1, $2, $3, $4, $5, $6, $7, NULL, NULLIF($8, ''), $9, $10, $11, $12, $13, '[]',
			NULLIF($14, ''), NULLIF($15, ''), 'PROPOSED')
		ON CONFLICT (tenant_id, idempotency_key) DO NOTHING`,
		caller.TenantID, uuid.New(), caller.WorkspaceID, key, requestDigest[:], caller.PrincipalID, caller.ActorID,
		caseID, effectargs.ModelInference, c.Route.ID, targetDigest[:], argumentDigest[:], quote,
		episodeID, organizationVersionID)
	if err != nil {
		return err
	}
	return tx.Commit()
}

type pauseAfterLegacyRead struct {
	*admission.Service
	read   chan struct{}
	resume chan struct{}
}

func (l *pauseAfterLegacyRead) ModelCallAttemptsByKeys(ctx context.Context, caller admission.Caller, keys []string) ([]admission.Attempt, error) {
	attempts, err := l.Service.ModelCallAttemptsByKeys(ctx, caller, keys)
	close(l.read)
	select {
	case <-l.resume:
		return attempts, err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func TestPostgresLegacyWriterIsFencedBetweenLookupAndNewAdmission(t *testing.T) {
	e := newEnvWindow(t, 1_000_000, "none")
	bridge := &pauseAfterLegacyRead{Service: e.svc, read: make(chan struct{}), resume: make(chan struct{})}
	resume := func() {
		select {
		case <-bridge.resume:
		default:
			close(bridge.resume)
		}
	}
	defer resume()
	e.gw.Ledger = bridge
	e.anthropic.on(jsonHandler(budgetUsage(1)))
	body := budgetMessage("mixed-version-overlap", 0)
	c, refusal := inspect(e.cfg, effectargs.APIAnthropicMessages, []byte(body))
	if refusal != nil {
		t.Fatal(refusal)
	}
	caller := admission.Caller{TenantID: tenantA, WorkspaceID: workspace, PrincipalID: "agt:seat-1", ActorID: cpActor,
		Episode: &admission.Episode{EpisodeID: "ep-1", WorkItemID: "work-ep-1", OrganizationVersionID: "ver-1"}}
	legacyKey := "mi:ep-1:" + sha256hex(c.Body) + ":0"
	done := make(chan reply, 1)
	go func() { done <- post(t, e.worker.URL, "/v1/messages", workerHeaders(tokenAgent), body) }()
	select {
	case <-bridge.read:
	case <-time.After(10 * time.Second):
		t.Fatal("new gateway did not finish its legacy lookup")
	}
	// The old writer races after a negative compatibility read. PostgreSQL
	// rejects its new key before a hold or provider claim can be created.
	err := legacyModelInsert(context.Background(), e, caller, c, legacyKey)
	var pgErr *pq.Error
	if !errors.As(err, &pgErr) || pgErr.Code != "23514" || !strings.Contains(pgErr.Message, "legacy_model_writer_fenced") {
		t.Fatalf("legacy writer was not fenced: %v", err)
	}
	resume()
	select {
	case r := <-done:
		if r.Status != 200 {
			t.Fatalf("new gateway call: %s", r)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("new gateway did not complete")
	}
	if e.anthropic.calls.Load() != 1 || len(e.attempts()) != 1 {
		t.Fatalf("overlap created %d provider calls and %d attempts", e.anthropic.calls.Load(), len(e.attempts()))
	}
	if used, reserved := e.counters(); used <= 0 || used > 1_000_000 || reserved != 0 {
		t.Fatalf("overlap did not settle within the cap: used=%d reserved=%d", used, reserved)
	}
	e.ledgerBalances()
}

func TestPostgresDefaultRetryRecognizesLegacyInFlightAndSettledKeys(t *testing.T) {
	e := newEnvWindow(t, 1_000_000, "none")
	body := budgetMessage("legacy-key", 0)
	c, refusal := inspect(e.cfg, effectargs.APIAnthropicMessages, []byte(body))
	if refusal != nil {
		t.Fatal(refusal)
	}
	forwardDigest := sha256hex(c.Body)
	args, err := json.Marshal(modelArgs{Schema: "model.inference.v1", API: c.API, Route: c.Route.ID,
		RequestSHA256: forwardDigest, InputBytes: int64(len(c.Body)), MaxOutputTokens: c.MaxOutputTokens, Stream: c.Stream})
	must(t, err)
	quote, err := c.Route.Quote(int64(len(c.Body)), c.MaxOutputTokens, c.MayWriteCache)
	must(t, err)
	caller := admission.Caller{TenantID: tenantA, WorkspaceID: workspace, PrincipalID: "agt:seat-1", ActorID: cpActor,
		Episode: &admission.Episode{EpisodeID: "ep-1", WorkItemID: "work-ep-1", OrganizationVersionID: "ver-1"}}
	prior, existing, err := e.svc.Propose(context.Background(), caller, admission.ProposeInput{
		IdempotencyKey: "mi:ep-1:" + forwardDigest + ":0", CaseID: "work-ep-1", EffectType: effectargs.ModelInference,
		Target: c.Route.ID, Arguments: args, Quote: []admission.Amount{{Unit: admission.UnitUSDMicros, Amount: quote}},
	})
	must(t, err)
	if existing || prior.State != "ADMITTED" {
		t.Fatalf("legacy proposal = %+v existing=%t", prior, existing)
	}
	// Model an attempt that was committed before the migration. The fence
	// applies to INSERT only: this row must still claim, settle and replay.
	_, err = e.owner.Exec(`UPDATE authority_effect_attempts SET model_writer_protocol=1
		WHERE tenant_id=$1 AND attempt_id=$2`, tenantA, prior.ID)
	must(t, err)
	if err := legacyModelInsert(context.Background(), e, caller, c, prior.IdempotencyKey); err != nil {
		t.Fatalf("legacy writer could not reuse a pre-existing key: %v", err)
	}
	claim, _, err := e.svc.ClaimModelCall(context.Background(), caller, prior.ID, time.Minute)
	must(t, err)
	if claim == nil {
		t.Fatal("legacy call did not claim")
	}
	e.anthropic.on(jsonHandler(budgetUsage(1)))
	inFlight := post(t, e.worker.URL, "/v1/messages", workerHeaders(tokenAgent), body)
	if inFlight.Status != 409 || inFlight.Header.Get(headerAttemptID) != prior.ID || e.anthropic.calls.Load() != 0 || len(e.attempts()) != 1 {
		t.Fatalf("legacy in-flight call was duplicated: %s", inFlight)
	}
	responseBody := []byte(budgetUsage(1))
	responseDigest := sha256.Sum256(responseBody)
	cost, err := c.Route.Cost(Usage{InputTokens: 1, OutputTokens: 1})
	must(t, err)
	settled, err := e.svc.SettleModelCall(context.Background(), claim, admission.ModelCallOutcome{
		Result: admission.ModelCallConfirmed, ConfirmedMicros: cost, Usage: []byte(`{"input_tokens":1,"output_tokens":1}`),
		EvidenceDigest: responseDigest[:], Replay: &admission.ModelCallReplay{StatusCode: 200,
			Headers: map[string]string{"Content-Type": "application/json"}, Body: responseBody,
			BodySHA256: responseDigest[:], TTL: time.Hour},
	})
	must(t, err)
	if settled.State != "SETTLED" {
		t.Fatalf("legacy settlement = %+v", settled)
	}
	replay := post(t, e.worker.URL, "/v1/messages", workerHeaders(tokenAgent), body)
	if replay.Status != 200 || replay.Header.Get(headerReplayed) != "true" || replay.Header.Get(headerAttemptID) != prior.ID ||
		string(replay.Body) != string(responseBody) || e.anthropic.calls.Load() != 0 || len(e.attempts()) != 1 {
		t.Fatalf("legacy stored response was not replayed: %s", replay)
	}
	e.ledgerBalances()
}

type failFirstModelClaim struct {
	*admission.Service
	failed atomic.Bool
}

func (l *failFirstModelClaim) ClaimModelCall(ctx context.Context, caller admission.Caller, id string, fence time.Duration) (*admission.ModelCallClaim, admission.Attempt, error) {
	if l.failed.CompareAndSwap(false, true) {
		return nil, admission.Attempt{}, errors.New("injected pre-claim failure")
	}
	return l.Service.ClaimModelCall(ctx, caller, id, fence)
}

func TestPostgresDefaultRetryRepricesAfterReleasingItsOwnUnclaimedHold(t *testing.T) {
	e := newEnvWindow(t, 1_000, "none")
	e.gw.Ledger = &failFirstModelClaim{Service: e.svc}
	e.anthropic.on(jsonHandler(budgetUsage(1)))
	body := budgetMessage("retry-own-hold", 0)
	first := post(t, e.worker.URL, "/v1/messages", workerHeaders(tokenAgent), body)
	if first.Status != 503 || e.anthropic.calls.Load() != 0 {
		t.Fatalf("pre-claim failure: %s", first)
	}
	_, held := e.counters()
	if held <= 0 {
		t.Fatal("the first proposal did not leave a recoverable hold")
	}
	second := post(t, e.worker.URL, "/v1/messages", workerHeaders(tokenAgent), body)
	if second.Status != 200 || e.anthropic.calls.Load() != 1 {
		t.Fatalf("retry after release: first=%s second=%s", first, second)
	}
	attempts := e.attempts()
	if len(attempts) != 2 || attempts[0].State != "CANCELLED" || attempts[1].State != "SETTLED" {
		t.Fatalf("retry attempts = %+v", attempts)
	}
	if used, reserved := e.counters(); used <= 0 || used > 1_000 || reserved != 0 {
		t.Fatalf("retry budget: used=%d reserved=%d", used, reserved)
	}
	e.ledgerBalances()
}

func TestPostgresDefaultReplayDoesNotCrossCaseInOneScope(t *testing.T) {
	e := newEnvWindow(t, 1_000_000, "none")
	e.anthropic.on(jsonHandler(budgetUsage(1)))
	body := budgetMessage("same-body", 0)
	headers := map[string]string{"Authorization": "Bearer " + tokenService, "X-Helm-Idempotency-Scope": "same-scope", "X-Helm-Case-Id": "case-a"}
	first := post(t, e.main.URL, "/v1/messages", headers, body)
	headers["X-Helm-Case-Id"] = "case-b"
	second := post(t, e.main.URL, "/v1/messages", headers, body)
	if first.Status != 200 || second.Status != 200 || second.Header.Get(headerReplayed) != "" ||
		e.anthropic.calls.Load() != 2 || first.Header.Get(headerAttemptID) == second.Header.Get(headerAttemptID) {
		t.Fatalf("different cases shared a result: first=%s second=%s", first, second)
	}
	e.ledgerBalances()
}

func TestPostgresThinkingBudgetCannotBeLoweredBelowItsProviderMinimum(t *testing.T) {
	e := newEnvWindow(t, 1_000, "none")
	e.anthropic.on(jsonHandler(budgetUsage(1)))
	body := `{"model":"claude-sonnet-5-5","messages":[{"role":"user","content":"thinking"}],"thinking":{"type":"enabled","budget_tokens":200}}`
	response := post(t, e.worker.URL, "/v1/messages", workerHeaders(tokenAgent), body)
	if response.Status != 403 || response.Header.Get("X-Helm-Reason-Code") != string(contracts.ReasonBudgetExceeded) || e.anthropic.calls.Load() != 0 {
		t.Fatalf("unaffordable thinking request reached provider: %s", response)
	}
	if used, reserved := e.counters(); used != 0 || reserved != 0 {
		t.Fatalf("thinking refusal held budget: %d+%d", used, reserved)
	}
}

func budgetMessage(name string, maxTokens int64) string {
	cap := ""
	if maxTokens > 0 {
		cap = fmt.Sprintf(`,"max_tokens":%d`, maxTokens)
	}
	return fmt.Sprintf(`{"model":"claude-sonnet-5-5","messages":[{"role":"user","content":%q}]%s}`, name, cap)
}

func budgetUsage(outputTokens int64) string {
	return fmt.Sprintf(`{"id":"budget-test","type":"message","content":[],"usage":{"input_tokens":1,"output_tokens":%d}}`, outputTokens)
}

func budgetUsageWithCache(outputTokens, cachedTokens int64) string {
	return fmt.Sprintf(`{"id":"budget-test","type":"message","content":[],"usage":{"input_tokens":1,"cache_read_input_tokens":%d,"output_tokens":%d}}`, cachedTokens, outputTokens)
}

// teamBudget creates an actual mandate lineage. Both seats count against the
// same team limit; the child also has its own narrower link and counter.
func teamBudget(t *testing.T, e *env) uuid.UUID {
	t.Helper()
	ctx := context.Background()
	for _, p := range []struct {
		id   string
		kind authorityrows.PrincipalKind
	}{{"team:release_test", authorityrows.PrincipalService}, {"agt:budget-parent", authorityrows.PrincipalAgent}, {"agt:budget-child", authorityrows.PrincipalAgent}} {
		must(t, e.rows.CreatePrincipal(ctx, tenantA, p.id, p.kind))
	}
	terms := authorityrows.Terms{EffectTypes: []string{effectargs.ModelInference},
		Targets: []string{routeSonnet}, ValidFrom: e.now.Add(-time.Hour), ValidUntil: e.now.Add(6 * time.Hour)}
	team, err := e.rows.CreateMandate(ctx, tenantA, "team:release_test", terms,
		authorityrows.WideningApproval{RequesterID: "human-a", ApproverID: "human-b"})
	must(t, err)
	parent, err := e.rows.Delegate(ctx, tenantA, team.ID, "team:release_test", "agt:budget-parent", terms)
	must(t, err)
	child, err := e.rows.Delegate(ctx, tenantA, parent.ID, "agt:budget-parent", "agt:budget-child", terms)
	must(t, err)
	for _, m := range []uuid.UUID{team.ID, parent.ID, child.ID} {
		_, err := e.rows.CreateLimit(ctx, tenantA, authorityrows.LimitSpec{MandateID: &m,
			Unit: admission.UnitUSDMicros, Measure: "sum", Window: "none", Span: 1, Value: 10_000_000})
		must(t, err)
	}
	// The store refuses a child cap wider than its parent before it can be
	// used as an independent budget.
	_, err = e.rows.CreateLimit(ctx, tenantA, authorityrows.LimitSpec{MandateID: &child.ID,
		Unit: admission.UnitUSDMicros, Measure: "sum", Window: "none", Span: 1, Value: 10_000_001})
	if !errors.Is(err, authorityrows.ErrWidens) {
		t.Fatalf("overwide child delegation was not refused: %v", err)
	}
	var teamLimit uuid.UUID
	if err := e.owner.QueryRow(`SELECT limit_id FROM authority_limits WHERE tenant_id=$1 AND mandate_id=$2 AND unit='usd_micros'`, tenantA, team.ID).Scan(&teamLimit); err != nil {
		t.Fatal(err)
	}
	return teamLimit
}

func teamAmounts(t *testing.T, e *env, limit uuid.UUID) (used, reserved int64) {
	t.Helper()
	if err := e.owner.QueryRow(`SELECT COALESCE(sum(used),0), COALESCE(sum(reserved),0)
		FROM authority_counters WHERE tenant_id=$1 AND limit_id=$2`, tenantA, limit).Scan(&used, &reserved); err != nil {
		t.Fatal(err)
	}
	return used, reserved
}

func teamConserves(t *testing.T, e *env, limit uuid.UUID) {
	t.Helper()
	used, reserved := teamAmounts(t, e, limit)
	var spent, held int64
	var other int
	if err := e.owner.QueryRow(`SELECT COALESCE(sum(CASE WHEN x.kind IN ('estimated','confirmed') THEN x.amount ELSE 0 END),0),
		COALESCE(sum(CASE WHEN x.kind='held' THEN x.amount ELSE 0 END),0),
		count(*) FILTER (WHERE a.requester_principal_id NOT IN ('agt:budget-parent','agt:budget-child'))
		FROM authority_exposures x JOIN authority_effect_attempts a ON a.tenant_id=x.tenant_id AND a.attempt_id=x.attempt_id
		WHERE x.tenant_id=$1 AND x.limit_id=$2`, tenantA, limit).Scan(&spent, &held, &other); err != nil {
		t.Fatal(err)
	}
	if used != spent || reserved != held || other != 0 || used+reserved > 10_000_000 {
		t.Fatalf("team counter %d+%d differs from seat exposures %d+%d (other=%d)", used, reserved, spent, held, other)
	}
	e.ledgerBalances()
}

// fillTeam spends through the model gateway, using provider usage that leaves
// the exact requested remainder. The final provider response is independently
// priced from its token report, not injected into the ledger.
func fillTeam(t *testing.T, e *env, limit uuid.UUID, target int64) {
	t.Helper()
	route, _ := e.cfg.Resolve("anthropic-messages", "claude-sonnet-5-5")
	e.anthropic.on(jsonHandler(budgetUsage(60_000)))
	for i := range 9 {
		token, name := tokenBudgetParent, fmt.Sprintf("p%03d", i)
		if i == 0 {
			token, name = tokenBudgetChild, "c000"
		}
		if r := post(t, e.worker.URL, "/v1/messages", workerHeaders(token), budgetMessage(name, 64_000)); r.Status != 200 {
			t.Fatalf("team filler %d: %s", i, r)
		}
		teamConserves(t, e, limit)
	}
	used, _ := teamAmounts(t, e, limit)
	needed := target - used
	var output, cached int64
	found := false
	for out := needed / 15; out >= 0 && out >= needed/15-2 && !found; out-- {
		for cache := int64(0); cache <= 100; cache++ {
			cost, err := route.Cost(Usage{InputTokens: 1, CacheReadTokens: cache, OutputTokens: out})
			if err == nil && cost == needed {
				output, cached, found = out, cache, true
				break
			}
		}
	}
	if !found || output > 64_000 {
		t.Fatalf("cannot precondition exact target %d from used %d", target, used)
	}
	e.anthropic.on(jsonHandler(budgetUsageWithCache(output, cached)))
	if r := post(t, e.worker.URL, "/v1/messages", workerHeaders(tokenBudgetParent), budgetMessage("p009", 64_000)); r.Status != 200 {
		t.Fatalf("last team filler: %s", r)
	}
	if used, reserved := teamAmounts(t, e, limit); used != target || reserved != 0 {
		t.Fatalf("team precondition: used=%d reserved=%d, want %d,0", used, reserved, target)
	}
	teamConserves(t, e, limit)
}

func TestPostgresTeamAndChildShareTheLastModelQuote(t *testing.T) {
	const limit = int64(10_000_000)
	e := newEnvWindow(t, limit, "none")
	teamLimit := teamBudget(t, e)
	route, _ := e.cfg.Resolve("anthropic-messages", "claude-sonnet-5-5")
	parentBody, childBody := budgetMessage("p999", 64_000), budgetMessage("c999", 64_000)
	q, err := route.Quote(int64(len(childBody)), 64_000, false)
	must(t, err)
	if len(parentBody) != len(childBody) {
		t.Fatal("the parent and child quotes differ")
	}
	fillTeam(t, e, teamLimit, limit-q+1)
	before := e.anthropic.calls.Load()
	denied := post(t, e.worker.URL, "/v1/messages", workerHeaders(tokenBudgetChild), childBody)
	if denied.Status != 403 || denied.Header.Get("X-Helm-Reason-Code") != string(contracts.ReasonBudgetExceeded) || e.anthropic.calls.Load() != before {
		t.Fatalf("child crossed the team limit: %s", denied)
	}
	if used, reserved := teamAmounts(t, e, teamLimit); used != limit-q+1 || reserved != 0 {
		t.Fatalf("denied call wrote a hold: used=%d reserved=%d", used, reserved)
	}
	teamConserves(t, e, teamLimit)

	// The same child is permitted when its quote fits the remaining team cap.
	e.anthropic.on(jsonHandler(budgetUsage(1)))
	if r := post(t, e.worker.URL, "/v1/messages", workerHeaders(tokenBudgetChild), budgetMessage("cfit", 100)); r.Status != 200 {
		t.Fatalf("child fitting control: %s", r)
	}
	teamConserves(t, e, teamLimit)
}

func TestPostgresParentAndChildRaceForOneModelQuote(t *testing.T) {
	const limit = int64(10_000_000)
	e := newEnvWindow(t, limit, "none")
	teamLimit := teamBudget(t, e)
	route, _ := e.cfg.Resolve("anthropic-messages", "claude-sonnet-5-5")
	parentBody, childBody := budgetMessage("p999", 64_000), budgetMessage("c999", 64_000)
	q, err := route.Quote(int64(len(parentBody)), 64_000, false)
	must(t, err)
	fillTeam(t, e, teamLimit, limit-q)
	entered, release := make(chan struct{}, 2), make(chan struct{})
	e.anthropic.on(func(w http.ResponseWriter, r *http.Request) {
		entered <- struct{}{}
		<-release
		jsonHandler(budgetUsage(1))(w, r)
	})
	before := e.anthropic.calls.Load()
	start := make(chan struct{})
	results := make(chan reply, 2)
	for _, x := range []struct{ token, body string }{{tokenBudgetParent, parentBody}, {tokenBudgetChild, childBody}} {
		go func(token, body string) {
			<-start
			results <- post(t, e.worker.URL, "/v1/messages", workerHeaders(token), body)
		}(x.token, x.body)
	}
	close(start)
	select {
	case <-entered:
	case <-time.After(10 * time.Second):
		t.Fatal("no provider call won the last quote")
	}
	select {
	case denied := <-results:
		if denied.Status != 403 || denied.Header.Get("X-Helm-Reason-Code") != string(contracts.ReasonBudgetExceeded) {
			t.Fatalf("the losing racer was not denied: %s", denied)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the losing proposal did not finish while the winning hold was live")
	}
	if used, reserved := teamAmounts(t, e, teamLimit); used != limit-q || reserved != q {
		t.Fatalf("last-quote hold: used=%d reserved=%d, want %d,%d", used, reserved, limit-q, q)
	}
	teamConserves(t, e, teamLimit)
	close(release)
	select {
	case winner := <-results:
		if winner.Status != 200 {
			t.Fatalf("the winning model request failed: %s", winner)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the winning provider call did not finish")
	}
	if e.anthropic.calls.Load() != before+1 {
		t.Fatalf("race sent %d provider calls, want one", e.anthropic.calls.Load()-before)
	}
	teamConserves(t, e, teamLimit)
}

func TestPostgresTrialBudgetCapsDefaultOutputAndConservesSettlement(t *testing.T) {
	const trial = int64(5_000_000)
	e := newEnvWindow(t, trial, "none")
	route, ok := e.cfg.Resolve("anthropic-messages", "claude-sonnet-5-5")
	if !ok {
		t.Fatal("the platform route is unavailable")
	}
	e.anthropic.on(jsonHandler(budgetUsage(60_000)))
	for i := range 5 {
		body := budgetMessage(fmt.Sprintf("large-%d", i), 64_000)
		if r := post(t, e.worker.URL, "/v1/messages", workerHeaders(tokenAgent), body); r.Status != 200 {
			t.Fatalf("large request %d: %s", i, r)
		}
		used, reserved := e.counters()
		if reserved != 0 || used < 0 || used > trial {
			t.Fatalf("after large request %d: used=%d reserved=%d", i, used, reserved)
		}
		e.ledgerBalances()
	}
	e.anthropic.on(jsonHandler(budgetUsage(30_000)))
	if r := post(t, e.worker.URL, "/v1/messages", workerHeaders(tokenAgent), budgetMessage("last-large", 30_000)); r.Status != 200 {
		t.Fatalf("last large request: %s", r)
	}
	usedBefore, reserved := e.counters()
	if reserved != 0 || trial-usedBefore <= 0 {
		t.Fatalf("before the affordable default: used=%d reserved=%d", usedBefore, reserved)
	}
	defaultBody := budgetMessage("default-near-limit", 0)
	defaultCall, refusal := inspect(e.cfg, "anthropic-messages", []byte(defaultBody))
	if refusal != nil {
		t.Fatal(refusal)
	}
	defaultQuote, err := route.Quote(int64(len(defaultCall.Body)), defaultCall.MaxOutputTokens, false)
	must(t, err)
	if defaultQuote <= trial-usedBefore {
		t.Fatalf("fixture did not exhaust the next default quote: remainder=%d quote=%d", trial-usedBefore, defaultQuote)
	}

	// The explicit worst case is denied before provider I/O and holds nothing.
	beforeCalls := e.anthropic.calls.Load()
	denied := post(t, e.worker.URL, "/v1/messages", workerHeaders(tokenAgent), budgetMessage("over-limit", 8_192))
	if denied.Status != 403 || denied.Header.Get("X-Helm-Reason-Code") != string(contracts.ReasonBudgetExceeded) ||
		!strings.Contains(string(denied.Body), "BUDGET_EXCEEDED") || e.anthropic.calls.Load() != beforeCalls {
		t.Fatalf("explicit over-limit request reached the provider or was not denied: %s", denied)
	}
	if used, reserved := e.counters(); used != usedBefore || reserved != 0 {
		t.Fatalf("denial changed the budget: used=%d reserved=%d, wanted %d,0", used, reserved, usedBefore)
	}

	// A client with no maximum receives the largest maximum the current
	// remainder can cover. A small actual usage releases the rest of the hold.
	e.anthropic.on(jsonHandler(budgetUsage(1_000)))
	firstDefault := post(t, e.worker.URL, "/v1/messages", workerHeaders(tokenAgent), defaultBody)
	if firstDefault.Status != 200 {
		t.Fatalf("affordable default: %s", firstDefault)
	}
	forwarded := e.anthropic.last(t)
	var got struct {
		MaxTokens int64 `json:"max_tokens"`
	}
	if err := json.Unmarshal(forwarded.Body, &got); err != nil {
		t.Fatal(err)
	}
	if got.MaxTokens < 1 || got.MaxTokens >= route.DefaultMaxOutputTokens {
		t.Fatalf("forwarded maximum %d did not shrink to the remainder", got.MaxTokens)
	}
	quote, err := route.Quote(int64(len(forwarded.Body)), got.MaxTokens, false)
	must(t, err)
	if quote > trial-usedBefore {
		t.Fatalf("forwarded worst case %d exceeds remainder %d", quote, trial-usedBefore)
	}
	if body := strings.Replace(string(forwarded.Body), fmt.Sprintf(`"max_tokens":%d`, got.MaxTokens),
		fmt.Sprintf(`"max_tokens":%d`, got.MaxTokens+1), 1); body != string(forwarded.Body) {
		nextQuote, err := route.Quote(int64(len(body)), got.MaxTokens+1, false)
		must(t, err)
		if nextQuote <= trial-usedBefore {
			t.Fatalf("maximum %d still fits: %d <= %d", got.MaxTokens+1, nextQuote, trial-usedBefore)
		}
	}
	usedAfter, reserved := e.counters()
	actual, err := route.Cost(Usage{InputTokens: 1, OutputTokens: 1_000})
	must(t, err)
	if usedAfter != usedBefore+actual || reserved != 0 || usedAfter >= usedBefore+quote || usedAfter > trial {
		t.Fatalf("settlement did not release unused hold: before=%d after=%d quote=%d actual=%d reserved=%d", usedBefore, usedAfter, quote, actual, reserved)
	}
	e.ledgerBalances()
	// Repricing after settlement must not make the identical client request a
	// second provider call. The original response is replayed by stable intent.
	beforeReplay := e.anthropic.calls.Load()
	retry := post(t, e.worker.URL, "/v1/messages", workerHeaders(tokenAgent), defaultBody)
	if retry.Status != 200 || retry.Header.Get("X-Helm-Replayed") != "true" ||
		retry.Header.Get("X-Helm-Attempt-Id") != firstDefault.Header.Get("X-Helm-Attempt-Id") ||
		string(retry.Body) != string(firstDefault.Body) || e.anthropic.calls.Load() != beforeReplay {
		t.Fatalf("changed affordable cap defeated replay: first=%s retry=%s", firstDefault, retry)
	}
	if used, reserved := e.counters(); used != usedAfter || reserved != 0 {
		t.Fatalf("replay changed budget: used=%d reserved=%d", used, reserved)
	}

	// The remaining money still admits a fitting explicit request.
	if r := post(t, e.worker.URL, "/v1/messages", workerHeaders(tokenAgent), budgetMessage("fitting-control", 1_000)); r.Status != 200 {
		t.Fatalf("fitting control: %s", r)
	}
	if used, reserved := e.counters(); used < usedAfter || used > trial || reserved != 0 {
		t.Fatalf("after the fitting control: used=%d reserved=%d", used, reserved)
	}
	e.ledgerBalances()
}
