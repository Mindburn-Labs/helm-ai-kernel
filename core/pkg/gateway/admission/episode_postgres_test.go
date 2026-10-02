package admission

// Worker episodes on attempts (HELM-752 K7, HELM-751 N1) against real
// PostgreSQL 16 (listed in scripts/ci/postgres-proofs.txt): what an attempt
// records of the token that proposed it, what a token with an episode claim may
// read, and which effect types a principal's live mandates name.
//
// quantum_posture: computes no digests of its own and signs nothing.

import (
	"context"
	"database/sql"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/effectargs"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/kernel/authority/authorityrows"
)

// episodeWorker is the seat's agent, carried by the Control Plane, under the token of
// one episode: the claim is the only place an episode comes from.
func episodeWorker(episode, version string) Caller {
	return Caller{TenantID: tenantA, WorkspaceID: workspace, PrincipalID: "agent-a", ActorID: actor,
		Episode: &Episode{EpisodeID: episode, WorkItemID: "work-" + episode, OrganizationVersionID: version}}
}

// controlPlane is the Control Plane reading: a service principal with no episode.
var controlPlane = Caller{TenantID: tenantA, WorkspaceID: workspace, PrincipalID: actor}

func workerNote(key string) ProposeInput {
	return ProposeInput{IdempotencyKey: key, EffectType: noteType, Target: "ops", Arguments: []byte(`{"text":"hi"}`)}
}

func (f *fixture) episodeRow(id string) (episode, version, caseID, commitment sql.NullString) {
	f.t.Helper()
	f.ownerTx(tenantA, func(tx *sql.Tx) error {
		return tx.QueryRow(`SELECT episode_id, organization_version_id, case_id, commitment_id FROM authority_effect_attempts
			WHERE tenant_id = $1 AND attempt_id = $2`, tenantA, id).Scan(&episode, &version, &caseID, &commitment)
	})
	return
}

func TestPostgresEpisodeAttemptsRecordTheClaimAndNothingElse(t *testing.T) {
	f := newFixture(t)
	f.rootMandate(tenantA, "agent-a", skeletonTerms(f.now))
	ctx := context.Background()

	// An attempt proposed under an episode token records the claim, and its work
	// item is the attempt's case.
	a := f.propose(episodeWorker("ep-1", "ver-1"), workerNote("k1"))
	wantState(t, "the worker's note", a, "ADMITTED", "")
	if want := (&Episode{EpisodeID: "ep-1", WorkItemID: "work-ep-1", OrganizationVersionID: "ver-1"}); !reflect.DeepEqual(a.Episode, want) ||
		a.CaseID != "work-ep-1" || a.CommitmentID != "" {
		t.Fatalf("attempt = episode %+v case %q commitment %q", a.Episode, a.CaseID, a.CommitmentID)
	}
	episode, version, caseID, commitment := f.episodeRow(a.ID)
	if episode.String != "ep-1" || version.String != "ver-1" || caseID.String != "work-ep-1" || commitment.Valid {
		t.Fatalf("row = %v %v %v %v", episode, version, caseID, commitment)
	}

	// A claim with no organization version records none.
	bare := f.propose(episodeWorker("ep-3", ""), workerNote("k3"))
	if bare.Episode == nil || bare.Episode.OrganizationVersionID != "" {
		t.Fatalf("episode = %+v", bare.Episode)
	}
	if _, version, _, _ := f.episodeRow(bare.ID); version.Valid {
		t.Fatalf("organization_version_id = %v, want NULL", version)
	}

	// Every other attempt records no episode, however it names its work.
	plain := f.propose(human, note("k2"))
	if plain.Episode != nil {
		t.Fatalf("an attempt with no episode claim has %+v", plain.Episode)
	}
	if episode, version, _, _ := f.episodeRow(plain.ID); episode.Valid || version.Valid {
		t.Fatalf("row = %v %v, want NULL", episode, version)
	}

	// The claim's work item is the work reference, so a request cannot name
	// another: a commitment, or a different case, is refused, and its own case
	// is what it already is.
	commitmentIn := workerNote("k4")
	commitmentIn.CommitmentID = "commitment-1"
	_, _, err := f.svc.Propose(ctx, episodeWorker("ep-1", "ver-1"), commitmentIn)
	wantRefusal(t, "a commitment under an episode", err, CodeInvalidArgument, contracts.ReasonSchemaViolation)
	foreign := workerNote("k5")
	foreign.CaseID = "work-ep-2"
	_, _, err = f.svc.Propose(ctx, episodeWorker("ep-1", "ver-1"), foreign)
	wantRefusal(t, "another case under an episode", err, CodePermissionDenied, contracts.ReasonInsufficientPrivilege)
	own := workerNote("k6")
	own.CaseID = "work-ep-1"
	wantState(t, "its own case named", f.propose(episodeWorker("ep-1", "ver-1"), own), "ADMITTED", "")
	if n := f.count(tenantA, `SELECT count(*) FROM authority_effect_attempts WHERE idempotency_key IN ('k4', 'k5')`); n != 0 {
		t.Fatalf("a refused request left %d attempts", n)
	}

	// A claim the token layer could not have produced is refused before
	// anything is written.
	for _, e := range []*Episode{
		{EpisodeID: "bad id", WorkItemID: "work-1"}, {EpisodeID: "", WorkItemID: "work-1"}, {EpisodeID: "ep-1", WorkItemID: ""},
		{EpisodeID: "ep-1", WorkItemID: "work-1", OrganizationVersionID: "bad version"}, {EpisodeID: strings.Repeat("e", 129), WorkItemID: "work-1"},
	} {
		c := episodeWorker("ep-1", "")
		c.Episode = e
		_, _, err := f.svc.Propose(ctx, c, workerNote("k7"))
		wantRefusal(t, "a malformed claim", err, CodePermissionDenied, contracts.ReasonInsufficientPrivilege)
	}
	if n := f.count(tenantA, `SELECT count(*) FROM authority_effect_attempts WHERE idempotency_key = 'k7'`); n != 0 {
		t.Fatalf("a malformed claim left %d attempts", n)
	}

	// The row holds the same line: an episode needs a well-formed id and a case.
	for name, statement := range map[string]string{
		"an episode on an attempt with no case": `UPDATE authority_effect_attempts SET episode_id = 'ep-9' WHERE attempt_id = '` + plain.ID + `'`,
		"a malformed episode id":                `UPDATE authority_effect_attempts SET episode_id = 'has space' WHERE attempt_id = '` + a.ID + `'`,
		"a version with no episode":             `UPDATE authority_effect_attempts SET episode_id = NULL WHERE attempt_id = '` + a.ID + `'`,
		"a malformed version":                   `UPDATE authority_effect_attempts SET organization_version_id = 'has space' WHERE attempt_id = '` + a.ID + `'`,
	} {
		tx, err := f.owner.Begin()
		must(t, err)
		_, err = tx.Exec(`SELECT set_config('app.current_tenant', $1, true)`, tenantA)
		must(t, err)
		_, err = tx.Exec(statement)
		_ = tx.Rollback()
		if err == nil || !strings.Contains(err.Error(), "authority_effect_attempts_episode") {
			t.Errorf("%s: err = %v, want the episode constraint", name, err)
		}
	}

	// The same key and request is the same call: from its own episode it finds
	// its attempt, from another episode it is a conflict, never a replay of the
	// first episode's attempt.
	again, existing, err := f.svc.Propose(ctx, episodeWorker("ep-1", "ver-1"), workerNote("k1"))
	must(t, err)
	if !existing || again.ID != a.ID {
		t.Fatalf("replay = %s existing %v, want %s", again.ID, existing, a.ID)
	}
	_, _, err = f.svc.Propose(ctx, episodeWorker("ep-2", "ver-1"), workerNote("k1"))
	wantRefusal(t, "the same key from another episode", err, CodeAlreadyExists, contracts.ReasonIdempotencyConflict)
	_, _, err = f.svc.Propose(ctx, episodeWorker("ep-1", "ver-2"), workerNote("k1"))
	wantRefusal(t, "the same key under another organization version", err, CodeAlreadyExists, contracts.ReasonIdempotencyConflict)
}

func TestPostgresAnEpisodeReadsOnlyItsOwnAttempts(t *testing.T) {
	f := newFixture(t)
	f.rootMandate(tenantA, "agent-a", skeletonTerms(f.now))
	svc := f.withAdapter(&scripted{})
	ctx := context.Background()

	first := f.propose(episodeWorker("ep-1", "v"), workerNote("a1"))
	second := f.propose(episodeWorker("ep-1", "v"), workerNote("a2"))
	third := f.propose(episodeWorker("ep-1", "v"), workerNote("a3"))
	other := f.propose(episodeWorker("ep-2", "v"), workerNote("b1"))
	plain := f.propose(human, note("c1"))
	ids := func(attempts []Attempt) []string {
		var out []string
		for _, a := range attempts {
			out = append(out, a.ID)
		}
		return out
	}
	set := func(ids ...string) map[string]bool {
		out := map[string]bool{}
		for _, id := range ids {
			out[id] = true
		}
		return out
	}
	listed := func(c Caller, in ListInput) map[string]bool {
		in.PageSize = 200
		return set(ids(f.list(c, in).Attempts)...)
	}

	// The Control Plane's service principal reads every attempt of its tenant
	// and workspace, and may filter by episode like by anything else.
	for _, a := range []Attempt{first, other, plain} {
		got, err := svc.Get(ctx, controlPlane, a.ID)
		must(t, err)
		if got.ID != a.ID {
			t.Fatalf("the control plane read %s", got.ID)
		}
	}
	if got := listed(controlPlane, ListInput{}); !reflect.DeepEqual(got, set(first.ID, second.ID, third.ID, other.ID, plain.ID)) {
		t.Fatalf("the control plane lists %v", got)
	}
	if got := listed(controlPlane, ListInput{EpisodeID: "ep-2"}); !reflect.DeepEqual(got, set(other.ID)) {
		t.Fatalf("the control plane lists episode ep-2 as %v", got)
	}
	if got := listed(controlPlane, ListInput{EpisodeID: "ep-none"}); len(got) != 0 {
		t.Fatalf("the control plane lists an unknown episode as %v", got)
	}
	if got := listed(controlPlane, ListInput{EpisodeID: "ep-1", States: []string{"ADMITTED"}}); !reflect.DeepEqual(got, set(first.ID, second.ID, third.ID)) {
		t.Fatalf("filters combine: %v", got)
	}

	// A token with an episode claim reads its own episode, and everything else
	// in the tenant, the other episode's attempts and the Control Plane's
	// included, is not found: the same answer as an attempt that never was.
	w1 := episodeWorker("ep-1", "v")
	for _, id := range []string{first.ID, second.ID} {
		if got, err := svc.Get(ctx, w1, id); err != nil || got.ID != id {
			t.Fatalf("Get(own) = %v, %v", got.ID, err)
		}
		if content, err := svc.GetContent(ctx, w1, id); err != nil || string(content) != `{"text":"hi"}` {
			t.Fatalf("GetContent(own) = %q, %v", content, err)
		}
	}
	_, never := svc.Get(ctx, w1, "00000000-0000-7000-8000-000000000000")
	_, neverContent := svc.GetContent(ctx, w1, "00000000-0000-7000-8000-000000000000")
	for _, id := range []string{other.ID, plain.ID} {
		_, err := svc.Get(ctx, w1, id)
		if !reflect.DeepEqual(err, never) {
			t.Fatalf("Get(%s) = %v, want what no attempt at all gets: %v", id, err, never)
		}
		_, err = svc.GetContent(ctx, w1, id)
		if !reflect.DeepEqual(err, neverContent) {
			t.Fatalf("GetContent(%s) = %v, want %v", id, err, neverContent)
		}
	}
	wantRefusal(t, "an attempt that never was", never, CodeNotFound, "")
	if got := listed(w1, ListInput{}); !reflect.DeepEqual(got, set(first.ID, second.ID, third.ID)) {
		t.Fatalf("the worker lists %v", got)
	}
	if got := listed(w1, ListInput{EpisodeID: "ep-1"}); !reflect.DeepEqual(got, set(first.ID, second.ID, third.ID)) {
		t.Fatalf("the worker lists its own episode by name as %v", got)
	}
	// Naming another episode narrows to nothing, not to that episode.
	if got := listed(w1, ListInput{EpisodeID: "ep-2"}); len(got) != 0 {
		t.Fatalf("the worker listed another episode: %v", got)
	}
	if got := listed(w1, ListInput{States: []string{"DENIED"}}); len(got) != 0 {
		t.Fatalf("a filter widened the worker's listing: %v", got)
	}

	// A page token belongs to the filters and the caller it was issued for: the
	// episode is part of it.
	page, err := svc.List(ctx, w1, ListInput{PageSize: 2})
	must(t, err)
	if len(page.Attempts) != 2 || page.NextPageToken == "" {
		t.Fatalf("page = %d attempts, token %q", len(page.Attempts), page.NextPageToken)
	}
	if rest, err := svc.List(ctx, w1, ListInput{PageSize: 2, PageToken: page.NextPageToken}); err != nil || len(rest.Attempts) != 1 {
		t.Fatalf("the next page = %d attempts, %v", len(rest.Attempts), err)
	}
	for name, c := range map[string]Caller{"the control plane": controlPlane, "another episode": episodeWorker("ep-2", "v")} {
		_, err := svc.List(ctx, c, ListInput{PageSize: 2, PageToken: page.NextPageToken})
		wantRefusal(t, name+" using the worker's page token", err, CodeInvalidArgument, contracts.ReasonSchemaViolation)
	}
	servicePage, err := svc.List(ctx, controlPlane, ListInput{PageSize: 2})
	must(t, err)
	_, err = svc.List(ctx, w1, ListInput{PageSize: 2, PageToken: servicePage.NextPageToken})
	wantRefusal(t, "a worker using the service's page token", err, CodeInvalidArgument, contracts.ReasonSchemaViolation)
	_, err = svc.List(ctx, controlPlane, ListInput{PageSize: 2, EpisodeID: "ep-1", PageToken: servicePage.NextPageToken})
	wantRefusal(t, "the same listing with an episode filter added", err, CodeInvalidArgument, contracts.ReasonSchemaViolation)
	if _, err := svc.List(ctx, controlPlane, ListInput{PageSize: 2, EpisodeID: strings.Repeat("e", maxWorkRefBytes+1)}); err == nil {
		t.Fatal("an episode filter past its bound was accepted")
	}

	// Another tenant's worker of the same name reads none of it.
	foreign := episodeWorker("ep-1", "v")
	foreign.TenantID = tenantB
	_, err = svc.Get(ctx, foreign, first.ID)
	wantRefusal(t, "another tenant", err, CodeNotFound, "")

	// An episode belongs to one seat: another principal carrying the same
	// episode id reads none of this seat's attempts, and sees its own only.
	must(t, f.rows.CreatePrincipal(ctx, tenantA, "agent-b", authorityrows.PrincipalAgent))
	f.rootMandate(tenantA, "agent-b", skeletonTerms(f.now))
	sameEpisodeOtherSeat := episodeWorker("ep-1", "v")
	sameEpisodeOtherSeat.PrincipalID = "agent-b"
	_, err = svc.Get(ctx, sameEpisodeOtherSeat, first.ID)
	wantRefusal(t, "another seat under the same episode id", err, CodeNotFound, "")
	_, err = svc.GetContent(ctx, sameEpisodeOtherSeat, first.ID)
	wantRefusal(t, "another seat's content read", err, CodeNotFound, "")
	if got := listed(sameEpisodeOtherSeat, ListInput{}); len(got) != 0 {
		t.Fatalf("another seat lists %v under the same episode id", got)
	}
	theirs := f.propose(sameEpisodeOtherSeat, workerNote("d1"))
	if got := listed(sameEpisodeOtherSeat, ListInput{}); !reflect.DeepEqual(got, set(theirs.ID)) {
		t.Fatalf("the other seat lists %v, want only its own %s", got, theirs.ID)
	}
	if got := listed(w1, ListInput{}); !reflect.DeepEqual(got, set(first.ID, second.ID, third.ID)) {
		t.Fatalf("the first seat lists %v after the other proposed", got)
	}
	if _, _, err := svc.Dispatch(ctx, sameEpisodeOtherSeat, first.ID); !reflect.DeepEqual(err, never) {
		t.Fatalf("another seat's dispatch = %v", err)
	}

	// Nor does an episode send, read back or cancel another episode's attempt,
	// though the principal is the same: only its own episode's worker moves it.
	w2 := episodeWorker("ep-2", "v")
	if _, _, err := svc.Dispatch(ctx, w1, other.ID); !reflect.DeepEqual(err, never) {
		t.Fatalf("another episode's dispatch = %v", err)
	}
	if _, _, err := svc.Observe(ctx, w1, other.ID); !reflect.DeepEqual(err, never) {
		t.Fatalf("another episode's read-back = %v", err)
	}
	if _, _, err := svc.Cancel(ctx, w1, Token{Scope: "helm.gateway.propose"}, other.ID); !reflect.DeepEqual(err, never) {
		t.Fatalf("another episode's cancel = %v", err)
	}
	if got, _ := svc.Get(ctx, controlPlane, other.ID); got.State != "ADMITTED" {
		t.Fatalf("another episode's attempt moved to %s", got.State)
	}
	sent, _, err := svc.Dispatch(ctx, w2, other.ID)
	must(t, err)
	wantOutcome(t, "its own worker's dispatch", sent, "OBSERVED", "SUCCEEDED", "")
	if sent.Episode == nil || sent.Episode.EpisodeID != "ep-2" {
		t.Fatalf("a dispatched attempt lost its episode: %+v", sent.Episode)
	}
	// The dispatch is recorded against the worker's own principal and the
	// workload that carried its token.
	var by, byActor string
	f.ownerTx(tenantA, func(tx *sql.Tx) error {
		return tx.QueryRow(`SELECT claimed_by_principal_id, claimed_by_actor_id FROM authority_permits WHERE tenant_id = $1 AND attempt_id = $2`,
			tenantA, other.ID).Scan(&by, &byActor)
	})
	if by != "agent-a" || byActor != actor {
		t.Fatalf("permit claimed by %q for %q", by, byActor)
	}
}

func TestPostgresPrincipalEffectsFollowTheLiveMandateChain(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	agent := episodeWorker("ep-1", "v")
	effects := func(c Caller) PrincipalEffects {
		t.Helper()
		got, err := f.svc.PrincipalEffects(ctx, c)
		must(t, err)
		return got
	}
	// A seat with no mandate has none, and a principal the tenant does not know
	// is not an agent of it.
	if got := effects(agent); got.Kind != "agent" || !got.Active || len(got.EffectTypes) != 0 {
		t.Fatalf("a seat with no mandates: %+v", got)
	}
	unknown := agent
	unknown.PrincipalID = "agt:nobody"
	if got := effects(unknown); got.Kind != "" || got.Active || len(got.EffectTypes) != 0 {
		t.Fatalf("an unknown principal: %+v", got)
	}

	// Delegated down the chain, the seat has the effect types of its leaf.
	leafTerms := authorityrows.Terms{EffectTypes: []string{effectargs.GitHubRepositoryGet, noteType}, ValidFrom: f.now.Add(-time.Hour / 2),
		ValidUntil: f.now.Add(2 * time.Hour), Targets: []string{repo}, Condition: skeletonCondition}
	leaf, err := f.rows.Delegate(ctx, tenantA, f.mandate.ID, "human-a", "agent-a", leafTerms)
	must(t, err)
	if got := effects(agent); !reflect.DeepEqual(got.EffectTypes, []string{effectargs.GitHubRepositoryGet, noteType}) {
		t.Fatalf("the delegated seat has %v, want the two effect types sorted", got.EffectTypes)
	}
	// Two leaves over different effect types are one union, each name once.
	second, err := f.rows.Delegate(ctx, tenantA, f.mandate.ID, "human-a", "agent-a", authorityrows.Terms{
		EffectTypes: []string{effectargs.GitHubBranchCreateFromChanges, noteType}, ValidFrom: f.now.Add(-time.Hour / 2), ValidUntil: f.now.Add(2 * time.Hour),
		Targets: []string{repo}, Condition: skeletonCondition})
	must(t, err)
	if got := effects(agent); !reflect.DeepEqual(got.EffectTypes, []string{effectargs.GitHubBranchCreateFromChanges, effectargs.GitHubRepositoryGet, noteType}) {
		t.Fatalf("two leaves: %v", got.EffectTypes)
	}
	// A leaf that expired names nothing, though its row is still active.
	expired, err := f.rows.Delegate(ctx, tenantA, f.mandate.ID, "human-a", "agent-a", authorityrows.Terms{
		EffectTypes: []string{effectargs.GitHubPullRequestCreateDraft}, ValidFrom: f.now.Add(-50 * time.Minute), ValidUntil: f.now.Add(-40 * time.Minute),
		Targets: []string{repo}, Condition: skeletonCondition, ApprovalRequired: []string{effectargs.GitHubPullRequestCreateDraft}})
	must(t, err)
	_ = expired
	if got := effects(agent); slices.Contains(got.EffectTypes, effectargs.GitHubPullRequestCreateDraft) {
		t.Fatalf("an expired leaf is listed: %v", got.EffectTypes)
	}
	// A revoked leaf is gone; the other stays.
	must(t, f.rows.Revoke(ctx, tenantA, second.ID))
	if got := effects(agent); !reflect.DeepEqual(got.EffectTypes, []string{effectargs.GitHubRepositoryGet, noteType}) {
		t.Fatalf("after revoking a leaf: %v", got.EffectTypes)
	}
	// Another tenant's agent of the same name has none of it.
	foreign := agent
	foreign.TenantID = tenantB
	if got := effects(foreign); got.Kind != "agent" || len(got.EffectTypes) != 0 {
		t.Fatalf("another tenant's agent: %+v", got)
	}
	// Revoking the parent removes every leaf under it: the chain is what is live.
	must(t, f.rows.Revoke(ctx, tenantA, f.mandate.ID))
	if got := effects(agent); len(got.EffectTypes) != 0 {
		t.Fatalf("under a revoked parent the seat has %v", got.EffectTypes)
	}
	_ = leaf
}

// The response a settled model call kept is as private as the attempt: only
// the episode that made the call, or a caller with no episode claim, reads it.
func TestPostgresAModelCallsStoredResponseIsReadOnlyByItsOwnEpisode(t *testing.T) {
	f := newFixture(t)
	f.modelFixture(1_000_000)
	ctx := context.Background()
	w1, w2 := episodeWorker("ep-1", "v"), episodeWorker("ep-2", "v")

	in := modelProposal("m1", modelRoute, 3_000)
	in.CaseID = "" // an episode proposes under its work item
	a, _, err := f.svc.Propose(ctx, w1, in)
	must(t, err)
	wantState(t, "the episode's model call", a, "ADMITTED", "")
	if a.Episode == nil || a.Episode.EpisodeID != "ep-1" || a.CaseID != "work-ep-1" {
		t.Fatalf("model call = %+v", a.Episode)
	}
	claim, claimed, err := f.svc.ClaimModelCall(ctx, w1, a.ID, 15*time.Minute)
	must(t, err)
	if claim == nil {
		t.Fatalf("the claim was refused: %+v", claimed)
	}
	body := []byte("event: message_stop\n\n")
	_, err = f.svc.SettleModelCall(ctx, claim, ModelCallOutcome{Result: ModelCallConfirmed, ConfirmedMicros: 1_200, Usage: []byte(`{"input_tokens":1}`),
		EvidenceDigest: sha(body), Replay: &ModelCallReplay{StatusCode: 200, Headers: map[string]string{"Content-Type": "text/event-stream"},
			Body: body, BodySHA256: sha(body), TTL: time.Hour}})
	must(t, err)

	for name, c := range map[string]Caller{"its own episode": w1, "the Control Plane": controlPlane} {
		if r, err := f.svc.ModelCallReplay(ctx, c, a.ID); err != nil || r == nil || string(r.Body) != string(body) {
			t.Fatalf("%s reads %+v, %v", name, r, err)
		}
	}
	other := w1
	other.PrincipalID = "agent-b"
	for name, c := range map[string]Caller{"another episode": w2, "another seat under the same episode id": other} {
		if r, err := f.svc.ModelCallReplay(ctx, c, a.ID); err != nil || r != nil {
			t.Fatalf("%s reads %+v, %v: a stored response is its episode's", name, r, err)
		}
	}
	// A claim on another episode's call is refused like any other read of it.
	if _, _, err := f.svc.ClaimModelCall(ctx, w2, a.ID, time.Minute); err == nil {
		t.Fatal("another episode claimed a model call that is not its own")
	}
}

// A disabled principal has a row and mandates, and no effect types.
func TestPostgresADisabledPrincipalHasNoEffectTypes(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.rootMandate(tenantA, "agent-a", skeletonTerms(f.now))
	agent := episodeWorker("ep-1", "v")
	if got, err := f.svc.PrincipalEffects(ctx, agent); err != nil || len(got.EffectTypes) == 0 {
		t.Fatalf("an active seat has %+v, %v", got, err)
	}
	must(t, f.rows.InTenant(ctx, tenantA, func(tx *authorityrows.Tx) error {
		_, err := tx.DisablePrincipal(ctx, "agent-a")
		return err
	}))
	got, err := f.svc.PrincipalEffects(ctx, agent)
	must(t, err)
	if got.Kind != "agent" || got.Active || len(got.EffectTypes) != 0 {
		t.Fatalf("a disabled seat has %+v", got)
	}
}
