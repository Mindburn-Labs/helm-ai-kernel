package admission

// The rules of worker episodes that need no database (HELM-752 K7, HELM-751
// N1): what an episode claim binds a proposal to, which claims are refused
// before anything is written, which statements hold a reader to its episode,
// and that a request with no episode claim digests exactly as before.
//
// quantum_posture: recomputes SHA-256 request and filter digests to compare
// with the ones the package computes; signs nothing.

import (
	"bytes"
	"crypto/sha256"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

func TestApprovalDispatchRefusal(t *testing.T) {
	worker := Caller{Episode: &Episode{EpisodeID: "ep-1", WorkItemID: "work-1"}}
	wantRefusal(t, "worker cannot resume an approved escalation", approvalDispatchRefusal(worker, []byte("approval")),
		CodePermissionDenied, contracts.ReasonInsufficientPrivilege)
	if err := approvalDispatchRefusal(worker, nil); err != nil {
		t.Fatalf("direct admission rejected: %v", err)
	}
	// The enclosing transaction still checks CP's workload and requester
	// authority; this restriction applies only to the worker same-call path.
	if err := approvalDispatchRefusal(Caller{}, []byte("approval")); err != nil {
		t.Fatalf("control-plane approval resume rejected: %v", err)
	}
}

func TestBindEpisodeTakesTheWorkReferenceFromTheClaim(t *testing.T) {
	e := &Episode{EpisodeID: "ep-1", WorkItemID: "work-1"}
	in := ProposeInput{IdempotencyKey: "k", EffectType: noteType, Target: "ops"}

	// No claim, nothing changes, whatever the request names.
	for _, in := range []ProposeInput{in, {CaseID: "c"}, {CommitmentID: "c"}} {
		if got, err := bindEpisode(nil, in); err != nil || !reflect.DeepEqual(got, in) {
			t.Fatalf("no claim: %+v, %v", got, err)
		}
	}
	// With one, the work item is the case, named or not.
	if got, err := bindEpisode(e, in); err != nil || got.CaseID != "work-1" || got.CommitmentID != "" {
		t.Fatalf("an unnamed case: %+v, %v", got, err)
	}
	named := in
	named.CaseID = "work-1"
	if got, err := bindEpisode(e, named); err != nil || got.CaseID != "work-1" {
		t.Fatalf("its own case named: %+v, %v", got, err)
	}
	// A request cannot name another case, or a commitment in its place.
	other := in
	other.CaseID = "work-2"
	_, err := bindEpisode(e, other)
	wantRefusal(t, "another case", err, CodePermissionDenied, contracts.ReasonInsufficientPrivilege)
	commitment := in
	commitment.CommitmentID = "commitment-1"
	_, err = bindEpisode(e, commitment)
	wantRefusal(t, "a commitment", err, CodeInvalidArgument, contracts.ReasonSchemaViolation)
	// The request's own fields are not edited on the way through.
	if in.CaseID != "" {
		t.Fatal("bindEpisode edited its argument")
	}
}

func TestCheckCallerRefusesAMalformedEpisodeClaim(t *testing.T) {
	c := Caller{TenantID: "t", WorkspaceID: "w", PrincipalID: "p"}
	good := []*Episode{nil, {EpisodeID: "ep-1", WorkItemID: "work-1"}, {EpisodeID: "a.b:c_d-e", WorkItemID: "W", OrganizationVersionID: "v1"},
		{EpisodeID: strings.Repeat("e", 128), WorkItemID: strings.Repeat("w", 128), OrganizationVersionID: strings.Repeat("v", 128)}}
	for _, e := range good {
		c.Episode = e
		if err := checkCaller(c); err != nil {
			t.Errorf("%+v refused: %v", e, err)
		}
	}
	bad := []*Episode{{}, {EpisodeID: "ep-1"}, {WorkItemID: "work-1"}, {EpisodeID: "a b", WorkItemID: "w"}, {EpisodeID: "ep", WorkItemID: "w/x"},
		{EpisodeID: "ep", WorkItemID: "w", OrganizationVersionID: "v v"}, {EpisodeID: "ep\n", WorkItemID: "w"}, {EpisodeID: strings.Repeat("e", 129), WorkItemID: "w"},
		{EpisodeID: "épisode", WorkItemID: "w"}}
	for _, e := range bad {
		c.Episode = e
		wantRefusal(t, "a malformed claim", checkCaller(c), CodePermissionDenied, contracts.ReasonInsufficientPrivilege)
	}
}

func TestEpisodeScopeIsTheCallersOwnEpisode(t *testing.T) {
	if got := episodeScope(Caller{}); got != "" {
		t.Fatalf("a caller with no claim is held to episode %q", got)
	}
	if got := episodeScope(Caller{Episode: &Episode{EpisodeID: "ep-7", WorkItemID: "w"}}); got != "ep-7" {
		t.Fatalf("scope = %q", got)
	}
}

// A listing by a caller with an episode claim is held to the episode and to the
// principal, whatever it filters on, and the filter is one more bound value.
func TestListStatementHoldsAnEpisodeCallerToItsEpisodeAndPrincipal(t *testing.T) {
	worker := Caller{TenantID: tenantA, WorkspaceID: workspace, PrincipalID: "agent-a", Episode: &Episode{EpisodeID: "ep-1", WorkItemID: "work-1"}}
	q, err := parseList(worker, ListInput{EpisodeID: "ep-2"})
	must(t, err)
	statement, args := q.statement(worker)
	for _, want := range []string{"tenant_id = $1", "workspace_id = $2", "episode_id = $3", "episode_id = $4", "requester_principal_id = $5"} {
		if !strings.Contains(statement, want) {
			t.Fatalf("the statement lacks %q: %s", want, statement)
		}
	}
	if len(args) != 6 || args[2] != "ep-2" || args[3] != "ep-1" || args[4] != "agent-a" || strings.Contains(statement, "ep-") {
		t.Fatalf("args = %v, statement %s", args, statement)
	}
	// The Control Plane, with no claim, is held to neither, and a filter is just a filter.
	q, err = parseList(controlPlane, ListInput{})
	must(t, err)
	if statement, args = q.statement(controlPlane); strings.Contains(statement, "episode_id") || len(args) != 3 {
		t.Fatalf("an unfiltered service listing = %s %v", statement, args)
	}
	q, err = parseList(controlPlane, ListInput{EpisodeID: "ep-2"})
	must(t, err)
	if statement, args = q.statement(controlPlane); strings.Count(statement, "episode_id") != 1 || strings.Contains(statement, "requester_principal_id") || args[2] != "ep-2" {
		t.Fatalf("a service listing by episode = %s %v", statement, args)
	}
	// A page token belongs to its caller's episode and principal and to its filter.
	digests := map[string]string{}
	for name, c := range map[string]Caller{"service": controlPlane, "worker": worker} {
		for filter, in := range map[string]ListInput{"none": {}, "ep-1": {EpisodeID: "ep-1"}, "ep-2": {EpisodeID: "ep-2"}} {
			q, err := parseList(c, in)
			must(t, err)
			key := string(q.digest)
			if other, dup := digests[key]; dup {
				t.Errorf("%s/%s and %s share a page-token digest", name, filter, other)
			}
			digests[key] = name + "/" + filter
		}
	}
	other := worker
	other.PrincipalID = "agent-b"
	a, _ := parseList(worker, ListInput{})
	b, _ := parseList(other, ListInput{})
	if bytes.Equal(a.digest, b.digest) {
		t.Fatal("two seats under one episode id share a page-token digest")
	}
	if _, err := parseList(worker, ListInput{EpisodeID: strings.Repeat("e", maxWorkRefBytes+1)}); err == nil {
		t.Fatal("an episode filter past its bound was accepted")
	}
	if _, err := parseList(worker, ListInput{EpisodeID: "a\x00b"}); err == nil {
		t.Fatal("an episode filter with a NUL was accepted")
	}
}

// What a request with no episode claim digests to is what it always did: the
// idempotency digest of every attempt already stored, and the page tokens in
// flight, stay valid. The expected bytes are the definitions before episodes.
func TestDigestsOfRequestsWithNoEpisodeAreUnchanged(t *testing.T) {
	at := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	in := ProposeInput{MandateID: "", CaseID: "case-1", EffectType: noteType, Target: "ops", Arguments: []byte(`{"text":"hi"}`),
		Quote: []Amount{{Unit: "notes", Amount: 1}, {Unit: "effects", Amount: 0}}, Distinct: []DistinctValue{{Unit: "u", Digest: bytes.Repeat([]byte{1}, 32)}},
		ApprovalExpiresAt: &at}
	caller := Caller{TenantID: tenantA, WorkspaceID: workspace, PrincipalID: "human-a", ActorID: actor}

	var m bytes.Buffer
	field(&m, []byte("helm.gateway.v1.request-digest.v1"))
	field(&m, []byte(caller.PrincipalID))
	field(&m, []byte(caller.WorkspaceID))
	field(&m, []byte(in.MandateID))
	field(&m, []byte(in.CommitmentID))
	field(&m, []byte(in.CaseID))
	field(&m, []byte(in.EffectType))
	field(&m, []byte(in.Target))
	field(&m, in.Arguments)
	quote := append([]Amount(nil), in.Quote...)
	sort.Slice(quote, func(i, j int) bool { return quote[i].Unit < quote[j].Unit })
	u64(&m, uint64(len(quote)))
	for _, q := range quote {
		field(&m, []byte(q.Unit))
		u64(&m, uint64(q.Amount)) // #nosec G115 -- a test value
	}
	u64(&m, uint64(len(in.Distinct)))
	for _, d := range in.Distinct {
		field(&m, []byte(d.Unit))
		field(&m, d.Digest)
	}
	field(&m, []byte(at.Format("2006-01-02T15:04:05Z")))
	want := sha256.Sum256(m.Bytes())
	if got := requestDigest(caller, in); !bytes.Equal(got, want[:]) {
		t.Fatal("the digest of a request with no episode claim changed")
	}

	// Any change of the claim is another request, and so is having one.
	digest := func(e *Episode) string {
		c := caller
		c.Episode = e
		return string(requestDigest(c, in))
	}
	seen := map[string]string{string(want[:]): "no claim"}
	for name, e := range map[string]*Episode{
		"a claim":          {EpisodeID: "ep-1", WorkItemID: "case-1", OrganizationVersionID: "v"},
		"another episode":  {EpisodeID: "ep-2", WorkItemID: "case-1", OrganizationVersionID: "v"},
		"another item":     {EpisodeID: "ep-1", WorkItemID: "case-2", OrganizationVersionID: "v"},
		"another version":  {EpisodeID: "ep-1", WorkItemID: "case-1", OrganizationVersionID: "w"},
		"no version":       {EpisodeID: "ep-1", WorkItemID: "case-1"},
		"ids run together": {EpisodeID: "ep-1case-1", WorkItemID: "", OrganizationVersionID: "v"},
	} {
		d := digest(e)
		if other, dup := seen[d]; dup {
			t.Errorf("%s and %s digest alike", name, other)
		}
		seen[d] = name
	}

	// The same for the page token: a listing with no episode involved digests as it did.
	q, err := parseList(controlPlane, ListInput{States: []string{"ESCALATED"}, CaseID: "c", EffectType: noteType})
	must(t, err)
	var f bytes.Buffer
	field(&f, []byte("helm.gateway.v1.list-attempts-filters.v1"))
	field(&f, []byte(controlPlane.TenantID))
	field(&f, []byte(controlPlane.WorkspaceID))
	u64(&f, 1)
	field(&f, []byte("ESCALATED"))
	field(&f, []byte(""))
	field(&f, []byte("c"))
	field(&f, []byte(""))
	field(&f, []byte(noteType))
	field(&f, []byte(""))
	wantList := sha256.Sum256(f.Bytes())
	if !bytes.Equal(q.digest, wantList[:]) {
		t.Fatal("the page-token digest of a listing with no episode changed")
	}
}
