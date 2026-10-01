package admission

// quantum_posture: compares SHA-256 content addresses; no signing claim.

import (
	"context"
	"database/sql"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/adapters"
)

type artifactAdapter struct{ *scripted }

func (a artifactAdapter) Declarations() []adapters.Declaration {
	return []adapters.Declaration{artifactDeclaration(noteType)}
}

func TestPostgresDeclaredResultSurvivesReplayAndRestart(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	fake := &scripted{}
	fake.set(nil, func(adapters.Effect) adapters.ObserveResult {
		return adapters.ObserveResult{Outcome: adapters.OutcomeSucceeded, Observation: artifactObservation(t, `{"child_id":"child-7"}`)}
	})
	svc := f.withAdapter(artifactAdapter{fake})
	a := f.propose(human, note("artifact-1"))
	got, _, err := svc.Dispatch(ctx, workload, a.ID)
	must(t, err)
	wantOutcome(t, "declared artifact", got, "OBSERVED", "SUCCEEDED", "")
	if got.LatestObservation == nil || got.LatestObservation.Artifact == nil {
		t.Fatalf("result was dropped: %+v", got)
	}
	artifact := got.LatestObservation.Artifact
	if string(artifact.CanonicalBytes) != `{"child_id":"child-7"}` || got.LatestObservation.ResultRef != artifact.Digest {
		t.Fatalf("result bytes/address changed: %+v", got.LatestObservation)
	}
	// A restart without today's adapter still reads the original stored
	// result; it cannot recompute it from mutable current runtime state.
	restarted, err := New(f.runtime, Config{})
	must(t, err)
	replayed, err := restarted.Get(ctx, human, a.ID)
	must(t, err)
	if replayed.LatestObservation.Artifact.Digest != artifact.Digest ||
		string(replayed.LatestObservation.Artifact.CanonicalBytes) != string(artifact.CanonicalBytes) {
		t.Fatal("restart lost the retained result")
	}
	_, existing, err := svc.Dispatch(ctx, workload, a.ID)
	must(t, err)
	if !existing || fake.dispatched.Load() != 1 {
		t.Fatal("replay applied the effect twice")
	}
	for name, caller := range map[string]Caller{
		"foreign tenant":    {TenantID: tenantB, WorkspaceID: workspace, PrincipalID: actor},
		"foreign workspace": {TenantID: tenantA, WorkspaceID: "other", PrincipalID: actor},
	} {
		_, err := restarted.Get(ctx, caller, a.ID)
		wantRefusal(t, name, err, CodeNotFound, "")
	}
}

func TestPostgresDeclaredResultCannotSettleWithAnUnexpectedShape(t *testing.T) {
	f := newFixture(t)
	fake := &scripted{}
	fake.set(nil, func(adapters.Effect) adapters.ObserveResult {
		return adapters.ObserveResult{Outcome: adapters.OutcomeSucceeded,
			Observation: artifactObservation(t, `{"child_id":"child-7","new_grants":["all"]}`)}
	})
	svc := f.withAdapter(artifactAdapter{fake})
	a := f.propose(human, note("bad-artifact"))
	got, _, err := svc.Dispatch(context.Background(), workload, a.ID)
	must(t, err)
	if got.State != "UNKNOWN" || got.LatestObservation != nil {
		t.Fatalf("invalid output was reported as a settled effect: %+v", got)
	}
	var observations int
	f.ownerTx(tenantA, func(tx *sql.Tx) error {
		return tx.QueryRow(`SELECT count(*) FROM authority_observations WHERE attempt_id=$1`, a.ID).Scan(&observations)
	})
	if observations != 0 {
		t.Fatal("invalid typed result was persisted")
	}
}
