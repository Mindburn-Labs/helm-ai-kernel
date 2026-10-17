package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"connectrpc.com/connect"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/activitytrail"
	gatewayv1 "github.com/Mindburn-Labs/helm-ai-kernel/sdk/go/gen/helm/gateway/v1"
)

type activityReaderProbe struct {
	scopes []activitytrail.Scope
	when   time.Time
}

func (p *activityReaderProbe) CoverageMap(_ context.Context, scope activitytrail.Scope) (activitytrail.Coverage, error) {
	p.scopes = append(p.scopes, scope)
	return activitytrail.Coverage{Repository: scope.Repository, Class: activitytrail.CoverageObservedOnly, Enabled: true,
		DefaultBranch: "main", HeadSHA: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", EventWindowCapped: true}, nil
}

func (p *activityReaderProbe) observation(scope activitytrail.Scope) activitytrail.Observation {
	return activitytrail.Observation{Repository: scope.Repository, Ref: "refs/heads/main",
		BeforeSHA: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", AfterSHA: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		FactDigest: "digest", ActorLogin: "break-glass", ProviderTime: &p.when, ObservedAt: p.when,
		Source: activitytrail.SourceGitHubActivity, Coverage: activitytrail.CoverageObservedOnly}
}

func (p *activityReaderProbe) ListObservations(_ context.Context, scope activitytrail.Scope, page activitytrail.Page) ([]activitytrail.Observation, string, error) {
	p.scopes = append(p.scopes, scope)
	return []activitytrail.Observation{p.observation(scope)}, "next", nil
}

func (p *activityReaderProbe) ListOwnerExceptions(_ context.Context, scope activitytrail.Scope, page activitytrail.Page) ([]activitytrail.OwnerException, string, error) {
	p.scopes = append(p.scopes, scope)
	return []activitytrail.OwnerException{{Observation: p.observation(scope), Reason: activitytrail.OutsideHELMReason}}, "", nil
}

func TestActivityTrailReadRPCsUseAuthenticatedScopeAndTypedEvidence(t *testing.T) {
	issuer := newIssuer(t)
	probe := &activityReaderProbe{when: time.Now().UTC().Truncate(time.Second)}
	api := &ActivityServer{Auth: &Authenticator{Validator: issuer.validator(), Actor: testActor}, Trail: probe}
	path, handler := api.Handler()
	mux := http.NewServeMux()
	mux.Handle(path, handler)
	srv := httptest.NewServer(mux)
	defer srv.Close()
	client := gatewayv1.NewActivityTrailServiceClient(srv.Client(), srv.URL)
	ctx := context.Background()
	read := issuer.token(t, testAudience, "tenant-a", "svc:reader", ScopeRead)
	repo := "github.com/Acme/widget"
	coverage, err := client.GetCoverage(ctx, withToken(&gatewayv1.GetCoverageRequest{Repository: repo}, read))
	if err != nil {
		t.Fatal(err)
	}
	if got := coverage.Msg.GetCoverage(); got.GetClass() != activitytrail.CoverageObservedOnly || !got.GetEventWindowCapped() || got.GetHeadSha() == "" {
		t.Fatalf("coverage projection: %+v", got)
	}
	observations, err := client.ListObservations(ctx, withToken(&gatewayv1.ListObservationsRequest{Repository: repo, PageSize: 1}, read))
	if err != nil {
		t.Fatal(err)
	}
	got := observations.Msg.GetObservations()
	if len(got) != 1 || got[0].GetActorLogin() != "break-glass" || got[0].GetProviderTime() == nil ||
		got[0].GetRef() != "refs/heads/main" || got[0].GetBeforeSha() == "" || got[0].GetAfterSha() == "" ||
		got[0].GetSource() != activitytrail.SourceGitHubActivity || got[0].GetCoverage() != activitytrail.CoverageObservedOnly || got[0].GetGoverned() || observations.Msg.GetNextPageToken() != "next" {
		t.Fatalf("observation projection: %+v", observations.Msg)
	}
	exceptions, err := client.ListOwnerExceptions(ctx, withToken(&gatewayv1.ListOwnerExceptionsRequest{Repository: repo}, read))
	if err != nil {
		t.Fatal(err)
	}
	if len(exceptions.Msg.GetExceptions()) != 1 || exceptions.Msg.GetExceptions()[0].GetReason() != activitytrail.OutsideHELMReason {
		t.Fatalf("exception projection: %+v", exceptions.Msg)
	}
	if len(probe.scopes) != 3 {
		t.Fatalf("reader calls: %d", len(probe.scopes))
	}
	for _, scope := range probe.scopes {
		if scope.TenantID != "tenant-a" || scope.WorkspaceID != "ws-a" || scope.Repository != repo {
			t.Fatalf("scope escaped token: %+v", scope)
		}
	}
	for name, token := range map[string]string{"no token": "", "write scope": issuer.token(t, testAudience, "tenant-a", "svc:reader", ScopePropose)} {
		_, err := client.GetCoverage(ctx, withToken(&gatewayv1.GetCoverageRequest{Repository: repo}, token))
		if name == "no token" {
			wantRPCError(t, name, err, connect.CodeUnauthenticated, "")
		} else {
			wantRPCError(t, name, err, connect.CodePermissionDenied, contracts.ReasonInsufficientPrivilege)
		}
	}
	_, err = client.GetCoverage(ctx, withToken(&gatewayv1.GetCoverageRequest{Repository: "https://github.com/Acme/widget"}, read))
	wantRPCError(t, "malformed repository", err, connect.CodeInvalidArgument, contracts.ReasonSchemaViolation)
	_, err = client.ListObservations(ctx, withToken(&gatewayv1.ListObservationsRequest{Repository: repo, PageSize: 101}, read))
	wantRPCError(t, "oversized page", err, connect.CodeInvalidArgument, contracts.ReasonSchemaViolation)
	if len(probe.scopes) != 3 {
		t.Fatal("invalid request reached activity reader")
	}
}
