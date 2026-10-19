package server

// Counters surround the actual adapter and App custody. Provider state and
// HTTP answers come exclusively from the shared GitHub testkit.

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"

	testkit "github.com/Mindburn-Labs/helm-ai-kernel/core/internal/testkit/github"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/adapters"
	githubadapter "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/adapters/github"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/admission"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/custody"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/kernel/authority/authorityrows"
	gatewayv1 "github.com/Mindburn-Labs/helm-ai-kernel/sdk/go/gen/helm/gateway/v1"
)

type bindingGitHub struct {
	adapters.Adapter
	providers       map[string]*testkit.GitHub
	implementations map[string]adapters.Adapter
	afterDispatch   func(adapters.Effect)
	dispatchCalls   atomic.Int64
	observeCalls    atomic.Int64
	credentialCalls atomic.Int64
}

type bindingTokenSource struct {
	adapters.TokenSource
	calls *atomic.Int64
}

func (s bindingTokenSource) Token(ctx context.Context) (string, error) {
	s.calls.Add(1)
	return s.TokenSource.Token(ctx)
}

func newBindingGitHub(t *testing.T) *bindingGitHub {
	t.Helper()
	g := &bindingGitHub{
		providers: map[string]*testkit.GitHub{
			testRepo:                           testkit.NewFakeGitHubFor(t, "Mindburn-Labs", "example"),
			"github.com/Another-Owner/example": testkit.NewFakeGitHubFor(t, "Another-Owner", "example"),
		}, implementations: map[string]adapters.Adapter{},
	}
	for target, provider := range g.providers {
		g.implementations[target] = githubadapter.New(githubadapter.WithBaseURL(provider.URL()))
		// Named bases at one real commit let the base-ref control hold every
		// other provider prerequisite fixed. The HTTP fake verifies the object.
		body, err := json.Marshal(map[string]string{"ref": "refs/heads/release", "sha": provider.BaseSHA()})
		must(t, err)
		req, err := http.NewRequest(http.MethodPost, provider.URL()+"/repos/"+provider.Owner()+"/"+provider.Repository()+"/git/refs", bytes.NewReader(body))
		must(t, err)
		req.Header.Set("Authorization", "Bearer "+provider.Token())
		req.Header.Set("Content-Type", "application/json")
		response, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
		must(t, err)
		_, err = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
		must(t, err)
		must(t, response.Body.Close())
		if response.StatusCode != http.StatusCreated || provider.Head("release") != provider.BaseSHA() {
			t.Fatal("the shared HTTP GitHub did not create the explicit alternate base")
		}
	}
	g.Adapter = g.implementations[testRepo]
	return g
}

func (g *bindingGitHub) credentials(t *testing.T, installations ...[]byte) *custody.GitHubApp {
	t.Helper()
	if len(installations) == 0 {
		installations = [][]byte{[]byte(`{"installations":[{"tenant_id":"tenant-a","owner":"Mindburn-Labs","installation_id":7,"repositories":["Mindburn-Labs/example"]},{"tenant_id":"tenant-a","owner":"Another-Owner","installation_id":8,"repositories":["Another-Owner/example"]}]}`)}
	}
	return githubAppForTokens(t, map[string]string{
		"/app/installations/7/access_tokens": g.providers[testRepo].Token(),
		"/app/installations/8/access_tokens": g.providers["github.com/Another-Owner/example"].Token(),
	}, installations...)
}

func (g *bindingGitHub) branchRequest(t *testing.T, key, head, target, base string) *gatewayv1.ProposeRequest {
	t.Helper()
	req := branchRequest(key, head)
	req.Quote = []*gatewayv1.ResourceAmount{{Unit: "count", Amount: 1}}
	req.Effect.Target = target
	var args map[string]any
	must(t, json.Unmarshal(req.Effect.Arguments, &args))
	args["base"], args["base_sha"] = base, g.providers[target].Head(base)
	var err error
	req.Effect.Arguments, err = json.Marshal(args)
	must(t, err)
	return req
}

func bindingQuote() []admission.Amount { return []admission.Amount{{Unit: "count", Amount: 1}} }

func bindingLimits(t *testing.T, db *sql.DB, rows *authorityrows.Store) {
	t.Helper()
	result, err := db.Query(`SELECT mandate_id FROM authority_mandates WHERE tenant_id='tenant-a' AND holder_id='human-a' AND status='active'`)
	must(t, err)
	var ids []uuid.UUID
	for result.Next() {
		var id uuid.UUID
		must(t, result.Scan(&id))
		ids = append(ids, id)
	}
	must(t, result.Err())
	must(t, result.Close())
	for _, id := range ids {
		_, err = rows.CreateLimit(context.Background(), "tenant-a", authorityrows.LimitSpec{
			MandateID: &id, Unit: "count", Measure: "sum", Window: "day", Value: 100, Span: 1,
		})
		must(t, err)
	}
}

func (g *bindingGitHub) branchWrites(head string) int {
	total := 0
	for _, provider := range g.providers {
		total += provider.AppliedRef("heads/" + head)
	}
	return total
}

func (g *bindingGitHub) pullWrites(head string) int {
	total := 0
	for _, provider := range g.providers {
		total += provider.AppliedPull(head)
	}
	return total
}

func (g *bindingGitHub) Dispatch(ctx context.Context, creds adapters.TokenSource, effect adapters.Effect, digest []byte) adapters.DispatchResult {
	g.dispatchCalls.Add(1)
	implementation := g.implementations[effect.Target]
	if implementation == nil {
		implementation = g.Adapter
	}
	result := implementation.Dispatch(ctx, bindingTokenSource{creds, &g.credentialCalls}, effect, digest)
	if g.afterDispatch != nil && result.Status == adapters.DispatchSent {
		g.afterDispatch(effect)
	}
	return result
}

func (g *bindingGitHub) Observe(ctx context.Context, creds adapters.TokenSource, effect adapters.Effect) adapters.ObserveResult {
	g.observeCalls.Add(1)
	implementation := g.implementations[effect.Target]
	if implementation == nil {
		implementation = g.Adapter
	}
	return implementation.Observe(ctx, bindingTokenSource{creds, &g.credentialCalls}, effect)
}
