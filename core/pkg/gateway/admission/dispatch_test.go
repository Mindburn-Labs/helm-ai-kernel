package admission

import (
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/adapters"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/effectargs"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/kernel/authority/mandates"
)

func TestClaimRefusal(t *testing.T) {
	now := time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)
	versions := []AuthorityVersion{{Kind: "tenant", Version: 3}, {Kind: "principal", Key: "human-a", Version: 1},
		{Kind: "mandate", Key: "m1", Version: 2}, {Kind: "effect_type", Key: noteType, Version: 1}}
	chain := []mandates.Mandate{{Terms: mandates.Terms{ValidFrom: now.Add(-time.Hour), ValidUntil: now.Add(time.Hour)}}}
	good := func() claimInput {
		return claimInput{Permitted: versions, Current: append([]AuthorityVersion(nil), versions...), Chain: chain, Now: now}
	}
	// Known good: nothing changed; the order of the locked rows does not
	// matter.
	if r := claimRefusal(good()); r != "" {
		t.Fatalf("an unchanged claim is refused with %s", r)
	}
	reordered := good()
	reordered.Current = []AuthorityVersion{versions[3], versions[1], versions[0], versions[2]}
	if r := claimRefusal(reordered); r != "" {
		t.Fatalf("a reordered version list is refused with %s", r)
	}

	cases := map[string]struct {
		edit func(*claimInput)
		want contracts.ReasonCode
	}{
		"an active stop": {func(in *claimInput) { in.Stops = []string{"stop-1"} }, contracts.ReasonEmergencyStopFenced},
		// A stop bumps its scope's version too; the stop is the reason given.
		"a stop and its version bump": {func(in *claimInput) {
			in.Stops = []string{"stop-1"}
			in.Current[1].Version++
		}, contracts.ReasonEmergencyStopFenced},
		"an expired permit":      {func(in *claimInput) { in.Expired = true }, contracts.ReasonPermitExpired},
		"a bumped version":       {func(in *claimInput) { in.Current[2].Version++ }, contracts.ReasonAuthorityChanged},
		"a row no longer locked": {func(in *claimInput) { in.Current = in.Current[:3] }, contracts.ReasonAuthorityChanged},
		"a row newly locked": {func(in *claimInput) {
			in.Current = append(in.Current, AuthorityVersion{Kind: "limit", Key: "l1", Version: 1})
		}, contracts.ReasonAuthorityChanged},
		"another row of the kind": {func(in *claimInput) { in.Current[1].Key = "human-b" }, contracts.ReasonAuthorityChanged},
		"a mandate past its window": {func(in *claimInput) {
			in.Chain = []mandates.Mandate{{Terms: mandates.Terms{ValidFrom: now.Add(-2 * time.Hour), ValidUntil: now}}}
		}, contracts.ReasonMandateOutsideValidity},
		"a mandate not yet valid": {func(in *claimInput) {
			in.Chain = []mandates.Mandate{{Terms: mandates.Terms{ValidFrom: now.Add(time.Second), ValidUntil: now.Add(time.Hour)}}}
		}, contracts.ReasonMandateOutsideValidity},
	}
	for name, c := range cases {
		in := good()
		c.edit(&in)
		if got := claimRefusal(in); got != c.want {
			t.Errorf("%s: refused with %q, want %q", name, got, c.want)
		}
	}
}

func TestAfterDispatch(t *testing.T) {
	for status, want := range map[adapters.DispatchStatus]string{
		adapters.DispatchSent:       "DISPATCHED",
		adapters.DispatchNotSent:    "OBSERVED",
		adapters.DispatchIndefinite: "UNKNOWN",
		"":                          "UNKNOWN",
		"SOMETHING_ELSE":            "UNKNOWN",
	} {
		if got := afterDispatch(status); got != want {
			t.Errorf("%q: %s, want %s; only NOT_SENT is a certain failure", status, got, want)
		}
	}
}

func TestTypedResultFollowsTheEffectType(t *testing.T) {
	digest := make([]byte, 32)
	base := func() *adapters.Observation {
		return &adapters.Observation{Source: "s", TrustClass: "c", EvidenceDigest: digest}
	}
	branch := base()
	branch.GitHubBranch = &adapters.GitHubBranchResult{CommitSHA: commitSHA}
	kind, body, err := typedResult(effectargs.GitHubBranchCreateFromChanges, branch)
	if err != nil || kind != "github_branch" || len(body) == 0 {
		t.Fatalf("a branch result: %q %s %v", kind, body, err)
	}
	if kind, body, err := typedResult(noteType, base()); err != nil || kind != "" || body != nil {
		t.Fatalf("an effect type without a result: %q %s %v", kind, body, err)
	}
	both := base()
	both.GitHubBranch, both.GitHubPullRequest = branch.GitHubBranch, &adapters.GitHubPullRequestResult{}
	for name, c := range map[string]struct {
		effectType string
		o          *adapters.Observation
	}{
		"no observation":     {effectargs.GitHubBranchCreateFromChanges, nil},
		"the wrong member":   {effectargs.GitHubPullRequestCreateDraft, branch},
		"no member":          {effectargs.GitHubBranchCreateFromChanges, base()},
		"two members":        {effectargs.GitHubBranchCreateFromChanges, both},
		"a member for none":  {noteType, branch},
		"a short digest":     {noteType, &adapters.Observation{Source: "s", TrustClass: "c", EvidenceDigest: []byte{1}}},
		"no source or class": {noteType, &adapters.Observation{}},
	} {
		if _, _, err := typedResult(c.effectType, c.o); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
