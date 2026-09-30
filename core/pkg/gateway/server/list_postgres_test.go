package server

// ListAttempts on the wire, against real PostgreSQL 16 (listed in
// scripts/ci/postgres-proofs.txt): a JWKS issuer signs ADR-0005 tokens, a
// Connect client calls the handler, and every refusal carries its
// ErrorDetail.
//
// quantum_posture: signs classical RS256 test tokens; no post-quantum claim.

import (
	"context"
	"slices"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/admission"
	gatewayv1 "github.com/Mindburn-Labs/helm-ai-kernel/sdk/go/gen/helm/gateway/v1"
)

func TestPostgresListAttemptsOnTheWire(t *testing.T) {
	client, iss, _ := newWire(t)
	ctx := context.Background()
	propose := iss.token(t, testAudience, "tenant-a", "human-a", ScopePropose)
	read := iss.token(t, testAudience, "tenant-a", "human-a", ScopeRead)
	list := func(token string, msg *gatewayv1.ListAttemptsRequest) (*gatewayv1.ListAttemptsResponse, error) {
		resp, err := client.ListAttempts(ctx, withToken(msg, token))
		if err != nil {
			return nil, err
		}
		return resp.Msg, nil
	}
	ids := func(page *gatewayv1.ListAttemptsResponse) []string {
		var out []string
		for _, a := range page.GetAttempts() {
			out = append(out, a.GetAttemptId())
		}
		return out
	}
	// Every page, empty and last ones too, carries settled_before: database
	// time, the transaction bound and a 30 s margin before the page.
	mustList := func(token string, msg *gatewayv1.ListAttemptsRequest) *gatewayv1.ListAttemptsResponse {
		t.Helper()
		page, err := list(token, msg)
		must(t, err)
		settled := page.GetSettledBefore()
		want := admission.MaxTransaction + 30*time.Second
		if settled == nil || settled.CheckValid() != nil {
			t.Fatalf("a page without a valid settled_before: %v", page)
		}
		if lag := time.Since(settled.AsTime()); lag < want-time.Second || lag > want+time.Minute {
			t.Fatalf("settled_before is %v old, want about %v", lag, want)
		}
		return page
	}

	// Two escalated notes (for a case), an admitted branch, and a denied one
	// (for a commitment), in that order.
	var made []*gatewayv1.EffectAttempt
	for _, req := range []*gatewayv1.ProposeRequest{noteRequest("note-1"), noteRequest("note-2"), branchRequest("branch-1", "helm/skeleton"), branchRequest("branch-2", "main")} {
		resp, err := client.Propose(ctx, withToken(req, propose))
		must(t, err)
		made = append(made, resp.Msg.GetAttempt())
	}
	states := []gatewayv1.EffectAttemptState{
		gatewayv1.EffectAttemptState_EFFECT_ATTEMPT_STATE_ESCALATED, gatewayv1.EffectAttemptState_EFFECT_ATTEMPT_STATE_ESCALATED,
		gatewayv1.EffectAttemptState_EFFECT_ATTEMPT_STATE_ADMITTED, gatewayv1.EffectAttemptState_EFFECT_ATTEMPT_STATE_DENIED,
	}
	var order []string
	for i, a := range made {
		if a.GetState() != states[i] {
			t.Fatalf("attempt %d is %v, want %v", i, a.GetState(), states[i])
		}
		order = append(order, a.GetAttemptId())
	}

	// Known good: every attempt of the workspace, oldest change first, each
	// exactly as GetAttempt returns it.
	all := mustList(read, &gatewayv1.ListAttemptsRequest{})
	if !slices.Equal(ids(all), order) || all.GetNextPageToken() != "" {
		t.Fatalf("ListAttempts = %v (token %q), want %v", ids(all), all.GetNextPageToken(), order)
	}
	for _, listed := range all.GetAttempts() {
		got, err := client.GetAttempt(ctx, withToken(&gatewayv1.GetAttemptRequest{AttemptId: listed.GetAttemptId()}, read))
		must(t, err)
		if !proto.Equal(listed, got.Msg.GetAttempt()) {
			t.Fatalf("the listed attempt differs from GetAttempt's:\n%v\n%v", listed, got.Msg.GetAttempt())
		}
	}

	// Paging, one at a time: a token while more follows, none on the last.
	var walked []string
	req := &gatewayv1.ListAttemptsRequest{PageSize: 1}
	for pages := 0; ; pages++ {
		page := mustList(read, req)
		if len(page.GetAttempts()) != 1 || pages > 4 {
			t.Fatalf("page %d holds %d attempts", pages+1, len(page.GetAttempts()))
		}
		walked = append(walked, ids(page)...)
		if page.GetNextPageToken() == "" {
			break
		}
		req.PageToken = page.GetNextPageToken()
	}
	if !slices.Equal(walked, order) {
		t.Fatalf("paged = %v, want %v", walked, order)
	}
	// A token continues its own listing, whatever page size the request that
	// carries it names.
	escalated := gatewayv1.EffectAttemptState_EFFECT_ATTEMPT_STATE_ESCALATED
	firstEscalated := mustList(read, &gatewayv1.ListAttemptsRequest{PageSize: 1, States: []gatewayv1.EffectAttemptState{escalated}})
	secondEscalated := mustList(read, &gatewayv1.ListAttemptsRequest{PageSize: 5, States: []gatewayv1.EffectAttemptState{escalated}, PageToken: firstEscalated.GetNextPageToken()})
	if !slices.Equal(ids(firstEscalated), order[:1]) || firstEscalated.GetNextPageToken() == "" || !slices.Equal(ids(secondEscalated), order[1:2]) || secondEscalated.GetNextPageToken() != "" {
		t.Fatalf("the escalated attempts, one and then the rest: %v (token %q), %v (token %q)",
			ids(firstEscalated), firstEscalated.GetNextPageToken(), ids(secondEscalated), secondEscalated.GetNextPageToken())
	}

	// Filters.
	for _, test := range []struct {
		name string
		msg  *gatewayv1.ListAttemptsRequest
		want []string
	}{
		{"a state", &gatewayv1.ListAttemptsRequest{States: []gatewayv1.EffectAttemptState{escalated}}, order[:2]},
		{"either of two states", &gatewayv1.ListAttemptsRequest{States: []gatewayv1.EffectAttemptState{escalated, gatewayv1.EffectAttemptState_EFFECT_ATTEMPT_STATE_DENIED}}, []string{order[0], order[1], order[3]}},
		{"a case", &gatewayv1.ListAttemptsRequest{WorkRef: &gatewayv1.ListAttemptsRequest_CaseId{CaseId: "case-1"}}, order[:2]},
		{"a commitment", &gatewayv1.ListAttemptsRequest{WorkRef: &gatewayv1.ListAttemptsRequest_CommitmentId{CommitmentId: "commitment-1"}}, order[2:]},
		{"a requester", &gatewayv1.ListAttemptsRequest{RequesterPrincipalId: "human-a"}, order},
		{"a requester with no attempts", &gatewayv1.ListAttemptsRequest{RequesterPrincipalId: "human-b"}, nil},
		{"an effect type", &gatewayv1.ListAttemptsRequest{EffectType: "ops.note"}, order[:2]},
		{"updated_after", &gatewayv1.ListAttemptsRequest{UpdatedAfter: made[1].GetUpdatedAt()}, order[2:]},
		{"updated_after and a state", &gatewayv1.ListAttemptsRequest{UpdatedAfter: made[0].GetUpdatedAt(), States: []gatewayv1.EffectAttemptState{escalated}}, order[1:2]},
		{"filters that share no attempt", &gatewayv1.ListAttemptsRequest{EffectType: "ops.note", WorkRef: &gatewayv1.ListAttemptsRequest_CommitmentId{CommitmentId: "commitment-1"}}, nil},
	} {
		if got := ids(mustList(read, test.msg)); !slices.Equal(got, test.want) {
			t.Fatalf("%s: listed %v, want %v", test.name, got, test.want)
		}
	}
	// Every state the contract names is a state the gateway lists by.
	for number, name := range gatewayv1.EffectAttemptState_name {
		if number == 0 {
			continue
		}
		if _, err := list(read, &gatewayv1.ListAttemptsRequest{States: []gatewayv1.EffectAttemptState{gatewayv1.EffectAttemptState(number)}}); err != nil {
			t.Fatalf("listing by %s: %v", name, err)
		}
	}

	// A reader that has read to the end resumes at the settled_before of its
	// last page, and sees the recent changes again, so it applies them
	// idempotently.
	if got := ids(mustList(read, &gatewayv1.ListAttemptsRequest{UpdatedAfter: all.GetSettledBefore()})); !slices.Equal(got, order) {
		t.Fatalf("resuming at settled_before lists %v, want every recent change %v", got, order)
	}
	// updated_after lists what changed after an instant: nothing after the
	// last change, and then the attempt that changes, in its new state.
	cursor := all.GetAttempts()[len(order)-1].GetUpdatedAt()
	if got := mustList(read, &gatewayv1.ListAttemptsRequest{UpdatedAfter: cursor}); len(got.GetAttempts()) != 0 {
		t.Fatalf("after the last change: %v", ids(got))
	}
	_, err := client.Cancel(ctx, withToken(&gatewayv1.CancelRequest{AttemptId: order[0]}, propose))
	must(t, err)
	changed := mustList(read, &gatewayv1.ListAttemptsRequest{UpdatedAfter: cursor})
	if !slices.Equal(ids(changed), order[:1]) || changed.GetAttempts()[0].GetState() != gatewayv1.EffectAttemptState_EFFECT_ATTEMPT_STATE_CANCELLED ||
		!changed.GetAttempts()[0].GetUpdatedAt().AsTime().After(cursor.AsTime()) {
		t.Fatalf("after a change, updated_after lists %v", changed.GetAttempts())
	}

	// Known bad: another tenant's or workspace's token lists none of them,
	// whatever it filters on.
	otherTenant := iss.token(t, testAudience, "tenant-b", "human-a", ScopeRead)
	otherWorkspace := iss.token(t, testAudience, "tenant-a", "human-a", ScopeRead, func(c *tokenClaims) { c.WorkspaceID = "ws-b" })
	for name, token := range map[string]string{"another tenant": otherTenant, "another workspace": otherWorkspace} {
		for label, msg := range map[string]*gatewayv1.ListAttemptsRequest{
			"unfiltered": {},
			"matching every attempt": {
				States:               []gatewayv1.EffectAttemptState{escalated, gatewayv1.EffectAttemptState_EFFECT_ATTEMPT_STATE_ADMITTED},
				RequesterPrincipalId: "human-a", EffectType: "ops.note", UpdatedAfter: timestamppb.New(time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)),
			},
		} {
			if page := mustList(token, msg); len(page.GetAttempts()) != 0 || page.GetNextPageToken() != "" {
				t.Fatalf("%s, %s: listed %v", name, label, ids(page))
			}
		}
	}

	// Known bad: each scope that is not helm.gateway.read, and no token.
	for _, scope := range []string{ScopePropose, ScopeDecide, ScopeStop, ScopeExecute} {
		_, err := list(iss.token(t, testAudience, "tenant-a", "human-a", scope), &gatewayv1.ListAttemptsRequest{})
		wantRPCError(t, "a "+scope+" token on ListAttempts", err, connect.CodePermissionDenied, contracts.ReasonInsufficientPrivilege)
	}
	_, err = list("", &gatewayv1.ListAttemptsRequest{})
	wantRPCError(t, "no token", err, connect.CodeUnauthenticated, "")
	_, err = list(iss.token(t, "helm-kernel:test", "tenant-a", "human-a", ScopeRead), &gatewayv1.ListAttemptsRequest{})
	wantRPCError(t, "a kernel-audience token", err, connect.CodeUnauthenticated, "")
	// Authentication comes before validation: a bad request without a token
	// or with the wrong scope says nothing about its filters.
	_, err = list("", &gatewayv1.ListAttemptsRequest{PageSize: 1000})
	wantRPCError(t, "no token and a bad page size", err, connect.CodeUnauthenticated, "")
	_, err = list(propose, &gatewayv1.ListAttemptsRequest{PageSize: 1000})
	wantRPCError(t, "a propose token and a bad page size", err, connect.CodePermissionDenied, contracts.ReasonInsufficientPrivilege)

	// Known bad: malformed requests.
	token := firstEscalated.GetNextPageToken()
	for name, msg := range map[string]*gatewayv1.ListAttemptsRequest{
		"a page size over 200":                    {PageSize: 201},
		"a negative page size":                    {PageSize: -1},
		"an unspecified state":                    {States: []gatewayv1.EffectAttemptState{gatewayv1.EffectAttemptState_EFFECT_ATTEMPT_STATE_UNSPECIFIED}},
		"a state outside the enum":                {States: []gatewayv1.EffectAttemptState{99}},
		"a commitment_id set to nothing":          {WorkRef: &gatewayv1.ListAttemptsRequest_CommitmentId{}},
		"a case_id set to nothing":                {WorkRef: &gatewayv1.ListAttemptsRequest_CaseId{}},
		"an effect type in capitals":              {EffectType: "OPS.NOTE"},
		"a requester over 255 bytes":              {RequesterPrincipalId: strings.Repeat("p", 256)},
		"updated_after past year 9999":            {UpdatedAfter: &timestamppb.Timestamp{Seconds: 253402300800}},
		"a malformed page token":                  {PageToken: "not-a-token"},
		"a page token of other filters":           {PageToken: token, States: []gatewayv1.EffectAttemptState{gatewayv1.EffectAttemptState_EFFECT_ATTEMPT_STATE_ADMITTED}},
		"a page token of no filters":              {PageToken: token},
		"a page token under other paging filters": {PageToken: token, States: []gatewayv1.EffectAttemptState{escalated}, EffectType: "ops.note"},
	} {
		_, err := list(read, msg)
		wantRPCError(t, name, err, connect.CodeInvalidArgument, contracts.ReasonSchemaViolation)
	}
}
