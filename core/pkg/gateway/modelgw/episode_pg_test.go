package modelgw

// A model call proposed on the worker listener records the episode of its token
// like any other attempt does (HELM-751 N1), against real PostgreSQL 16 (listed
// in scripts/ci/postgres-proofs.txt).
//
// quantum_posture: fake token claims; nothing here signs or verifies, and no
// post-quantum claim is made.

import (
	"context"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/admission"
)

func TestPostgresModelCallsRecordTheEpisodeOfTheirToken(t *testing.T) {
	e := newEnv(t, 1_000_000)
	e.anthropic.on(sseHandler(anthropicStream))

	// Two episodes of the same seat each make a model call; a service call on
	// the main listener, which has no episode, makes a third.
	for _, token := range []string{tokenAgent, tokenAgentEp2} {
		if r := post(t, e.worker.URL, "/v1/messages", workerHeaders(token), messagesRequest); r.Status != 200 {
			t.Fatalf("%s: %s", token, r)
		}
	}
	headers := map[string]string{"Authorization": "Bearer " + tokenService, "X-Helm-Idempotency-Scope": "compile-job-1", "X-Helm-Case-Id": "org-compile-7", "Anthropic-Version": "2023-06-01"}
	if r := post(t, e.main.URL, "/v1/messages", headers, messagesRequest); r.Status != 200 {
		t.Fatalf("the service call: %s", r)
	}

	byCase := map[string]admission.Attempt{}
	for _, a := range e.attempts() {
		byCase[a.CaseID] = a
	}
	for caseID, want := range map[string]*admission.Episode{
		"work-ep-1":     {EpisodeID: "ep-1", WorkItemID: "work-ep-1", OrganizationVersionID: "ver-1"},
		"work-ep-2":     {EpisodeID: "ep-2", WorkItemID: "work-ep-2", OrganizationVersionID: "ver-1"},
		"org-compile-7": nil,
	} {
		got, ok := byCase[caseID]
		if !ok {
			t.Fatalf("no attempt for case %s: %v", caseID, byCase)
		}
		if want == nil && got.Episode != nil {
			t.Fatalf("the service call records an episode: %+v", got.Episode)
		}
		if want != nil && (got.Episode == nil || *got.Episode != *want) {
			t.Fatalf("case %s records %+v, want %+v", caseID, got.Episode, want)
		}
	}

	// And the listener's own token reads its episode's attempts only.
	first, other := byCase["work-ep-1"], byCase["work-ep-2"]
	worker := admission.Caller{TenantID: tenantA, WorkspaceID: workspace, PrincipalID: "agt:seat-1", ActorID: cpActor,
		Episode: &admission.Episode{EpisodeID: "ep-1", WorkItemID: "work-ep-1", OrganizationVersionID: "ver-1"}}
	if got, err := e.svc.Get(context.Background(), worker, first.ID); err != nil || got.ID != first.ID {
		t.Fatalf("a worker reading its own model call: %v", err)
	}
	if _, err := e.svc.Get(context.Background(), worker, other.ID); err == nil {
		t.Fatal("a worker read another episode's model call")
	}
}
