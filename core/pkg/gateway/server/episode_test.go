package server

// The worker's episode on the wire and in the identity (HELM-752 K7, HELM-751
// N1), without a database: the episode reaches admission only through a
// verified token claim, and leaves only as EffectAttempt.episode.

import (
	"context"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/auth/jwks"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/admission"
	gatewayv1 "github.com/Mindburn-Labs/helm-ai-kernel/sdk/go/gen/helm/gateway/v1"
)

func TestTheEpisodeReachesAdmissionOnlyFromTheVerifiedClaim(t *testing.T) {
	claims := goodClaims()
	claims.Episode = &jwks.EpisodeClaim{EpisodeID: "ep-1", WorkItemID: "work-1", OrganizationVersionID: "ver-1"}
	a := &Authenticator{Validator: fakeValidator{claims: claims}, Actor: testActor}
	id, err := a.Authenticate(context.Background(), bearer(), ScopePropose)
	must(t, err)
	want := admission.Episode{EpisodeID: "ep-1", WorkItemID: "work-1", OrganizationVersionID: "ver-1"}
	if id.Caller.Episode == nil || *id.Caller.Episode != want {
		t.Fatalf("caller episode = %+v, want %+v", id.Caller.Episode, want)
	}
	if id.Episode == nil || id.Episode.EpisodeID != "ep-1" {
		t.Fatalf("identity episode = %+v", id.Episode)
	}

	// A token with no claim gives admission none: there is no other way to get one.
	plain := &Authenticator{Validator: fakeValidator{claims: goodClaims()}, Actor: testActor}
	id, err = plain.Authenticate(context.Background(), bearer(), ScopePropose)
	must(t, err)
	if id.Caller.Episode != nil || id.Episode != nil {
		t.Fatalf("a token with no episode claim carries %+v", id.Caller.Episode)
	}

	// The worker profile refuses a token with none, before it names a caller.
	worker := &Authenticator{Validator: fakeValidator{claims: goodClaims()}, Actor: testActor, RequireEpisode: true}
	if _, err := worker.Authenticate(context.Background(), bearer(), ScopePropose); err == nil {
		t.Fatal("the worker profile accepted a token with no episode")
	}
	// Each copy of the claim is its own: a caller cannot reach the validator's.
	id1, _ := a.Authenticate(context.Background(), bearer(), ScopePropose)
	id1.Caller.Episode.EpisodeID = "changed"
	if claims.Episode.EpisodeID != "ep-1" {
		t.Fatal("the caller's episode aliases the validated claim")
	}
}

func TestAnAttemptCarriesItsEpisodeOnTheWire(t *testing.T) {
	out := attemptProto(admission.Attempt{ID: "a", CaseID: "work-1",
		Episode: &admission.Episode{EpisodeID: "ep-1", WorkItemID: "work-1", OrganizationVersionID: "ver-1"}})
	if e := out.GetEpisode(); e.GetEpisodeId() != "ep-1" || e.GetWorkItemId() != "work-1" || e.GetOrganizationVersionId() != "ver-1" || out.GetCaseId() != "work-1" {
		t.Fatalf("episode = %v, case %q", e, out.GetCaseId())
	}
	// An attempt with no episode has none, and a claim with no version leaves it empty.
	if attemptProto(admission.Attempt{ID: "a"}).GetEpisode() != nil {
		t.Fatal("an attempt with no episode has one on the wire")
	}
	bare := attemptProto(admission.Attempt{ID: "a", Episode: &admission.Episode{EpisodeID: "ep-1", WorkItemID: "work-1"}})
	if bare.GetEpisode().GetOrganizationVersionId() != "" || bare.GetEpisode().GetEpisodeId() != "ep-1" {
		t.Fatalf("episode = %v", bare.GetEpisode())
	}
}

func TestTheListFilterCarriesTheEpisode(t *testing.T) {
	in, err := listInput(&gatewayv1.ListAttemptsRequest{EpisodeId: "ep-1"})
	must(t, err)
	if in.EpisodeID != "ep-1" {
		t.Fatalf("listInput = %+v", in)
	}
	in, err = listInput(&gatewayv1.ListAttemptsRequest{})
	must(t, err)
	if in.EpisodeID != "" {
		t.Fatalf("an empty request filters on episode %q", in.EpisodeID)
	}
}
