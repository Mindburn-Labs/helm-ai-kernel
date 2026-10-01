package admission

import (
	"bytes"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/effectargs"
)

func TestWorkEffectIdentitySurvivesEpisodeSeatAndJSONRepresentation(t *testing.T) {
	c := Caller{TenantID: "t", WorkspaceID: "w", PrincipalID: "agt:first", ActorID: "cp",
		Episode: &Episode{EpisodeID: "first", WorkItemID: "work", OrganizationVersionID: "v1"}}
	in := ProposeInput{IdempotencyKey: "request-1", EffectType: effectargs.GitHubRepositoryGet,
		Target: "github.com/Acme/App", Arguments: []byte(`{"schema":"helm.github.repository.get.v1","branch":"main"}`)}
	first, err := prepareWorkEffect(c, in)
	if err != nil {
		t.Fatal(err)
	}
	c.PrincipalID, c.ActorID = "agt:replacement", "cp-new"
	c.Episode = &Episode{EpisodeID: "continuation", WorkItemID: "work", OrganizationVersionID: "v2"}
	in.IdempotencyKey, in.Target = "different-client-request", "github.com/acme/app"
	in.Arguments = []byte("{\n \"branch\": \"main\", \"schema\": \"helm.github.repository.get.v1\" }")
	in.Quote = []Amount{{Unit: "usd_micros", Amount: 7}}
	again, err := prepareWorkEffect(c, in)
	if err != nil {
		t.Fatal(err)
	}
	if first.IdempotencyKey != again.IdempotencyKey || !bytes.Equal(first.Arguments, again.Arguments) {
		t.Fatalf("same intent changed identity: %q vs %q", first.IdempotencyKey, again.IdempotencyKey)
	}
	if first.Target != "github.com/Acme/App" || first.CaseID != "work" {
		t.Fatalf("canonical identity rewrote the admitted target/work: %+v", first)
	}
}

func TestWorkEffectIdentitySeparatesAuthorityScopesAndIntent(t *testing.T) {
	c := Caller{TenantID: "t", WorkspaceID: "w", PrincipalID: "agt:seat",
		Episode: &Episode{EpisodeID: "ep", WorkItemID: "work"}}
	in := ProposeInput{EffectType: effectargs.GitHubRepositoryGet, Target: "github.com/acme/app",
		Arguments: []byte(`{"schema":"helm.github.repository.get.v1"}`)}
	first, err := prepareWorkEffect(c, in)
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*Caller, *ProposeInput){
		"tenant":    func(c *Caller, _ *ProposeInput) { c.TenantID = "other" },
		"workspace": func(c *Caller, _ *ProposeInput) { c.WorkspaceID = "other" },
		"work":      func(c *Caller, _ *ProposeInput) { c.Episode = &Episode{EpisodeID: "ep", WorkItemID: "other"} },
		"target":    func(_ *Caller, in *ProposeInput) { in.Target = "github.com/acme/other" },
		"intent": func(_ *Caller, in *ProposeInput) {
			in.Arguments = []byte(`{"schema":"helm.github.repository.get.v1","branch":"main"}`)
		},
	} {
		t.Run(name, func(t *testing.T) {
			otherCaller, otherInput := c, in
			mutate(&otherCaller, &otherInput)
			other, err := prepareWorkEffect(otherCaller, otherInput)
			if err != nil || other.IdempotencyKey == first.IdempotencyKey {
				t.Fatalf("distinct work intent collided: %q, %v", other.IdempotencyKey, err)
			}
		})
	}
}

func TestWorkEffectRejectsUntrustedWorkAndAmbiguousJSON(t *testing.T) {
	c := Caller{TenantID: "t", WorkspaceID: "w", PrincipalID: "agt:seat",
		Episode: &Episode{EpisodeID: "ep", WorkItemID: "work"}}
	for _, in := range []ProposeInput{
		{CaseID: "foreign", Arguments: []byte(`{"schema":"helm.github.repository.get.v1"}`)},
		{Arguments: []byte(`{"schema":"helm.github.repository.get.v1","branch":"main","branch":"other"}`)},
		{Arguments: []byte(`{"schema":"helm.github.repository.get.v1","grant":"admin"}`)},
	} {
		in.EffectType, in.Target = effectargs.GitHubRepositoryGet, "github.com/acme/app"
		if _, err := prepareWorkEffect(c, in); err == nil {
			t.Fatalf("accepted invalid work effect: %+v", in)
		}
	}
	c.Episode = nil
	if _, err := prepareWorkEffect(c, ProposeInput{}); err == nil {
		t.Fatal("accepted a work effect without a verified claim")
	}
}
