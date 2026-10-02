package mcpserver

// The MCP endpoint against real PostgreSQL 16 (listed in
// scripts/ci/postgres-proofs.txt): the real token check and handler over the
// real admission service, with a scripted adapter in place of GitHub. Each test
// migrates a fresh schema, seeds authority rows as the owner and runs the
// gateway as a restricted role, the way `helm-gateway serve` runs.
//
// quantum_posture: fake token claims and SHA-256 digests; nothing here signs or
// verifies a real credential, and no post-quantum claim is made.

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	_ "github.com/lib/pq"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/auth/jwks"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/adapters"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/admission"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/effectargs"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/server"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/kernel/authority/authorityrows"
)

const (
	tenantA   = "tenant-a"
	tenantB   = "tenant-b"
	workspace = "ws-a"
	cpActor   = "spiffe://helm/control-plane"
	audience  = "helm-gateway-worker:test"

	repoA = "github.com/acme/app"
	repoB = "github.com/other/app"

	// The tokens callers hold: a worker's episode token by seat and episode.
	tokenSeat1Ep1     = "canary-seat-1-episode-1"
	tokenContinuation = "canary-seat-1-continuation"
	tokenReassigned   = "canary-seat-2-continuation"
	tokenSeat1Ep2     = "canary-seat-1-episode-2"
	tokenSeat1Read    = "canary-seat-1-episode-1-propose-read"
	tokenSeat1Ro      = "canary-seat-1-episode-1-reads"
	tokenSeat2        = "canary-seat-2-episode-1"
	tokenNoSeat       = "canary-seat-without-mandates"
	tokenTenantB      = "canary-tenant-b-seat-1-episode-1"
	tokenService      = "canary-service-with-episode"
	tokenHuman        = "canary-human-with-episode"
	tokenNoEp         = "canary-seat-1-no-episode"
)

// scriptedAdapter performs the three GitHub effect types without GitHub. By
// default Dispatch checks the permit digest and is SENT, and Observe is
// SUCCEEDED with the effect type's typed result; a test sets its answers.
type scriptedAdapter struct {
	mu                   sync.Mutex
	dispatchFn           func(adapters.Effect) adapters.DispatchResult
	observeFn            func(adapters.Effect) adapters.ObserveResult
	dispatched, observed atomic.Int32
}

func (a *scriptedAdapter) Declarations() []adapters.Declaration {
	var out []adapters.Declaration
	for _, d := range []struct {
		effect     string
		risk       adapters.RiskClass
		reversible adapters.Reversibility
	}{
		{effectargs.GitHubRepositoryGet, adapters.RiskLow, adapters.ReversibleNotApplicable},
		{effectargs.GitHubBranchCreateFromChanges, adapters.RiskMedium, adapters.ReversibleYes},
		{effectargs.GitHubPullRequestCreateDraft, adapters.RiskMedium, adapters.ReversibleYes},
	} {
		schema, _ := effectargs.ArgumentSchema(d.effect)
		out = append(out, adapters.Declaration{EffectType: d.effect, RiskClass: d.risk, Idempotent: adapters.IdempotentConditional,
			Observable: adapters.ObservableYes, Reversible: d.reversible, Mediation: adapters.MediationEnforced,
			TargetForm: "github.com/{owner}/{repo}", Description: "A scripted " + d.effect + ".", ArgumentSchema: schema, Grantable: true})
	}
	return out
}

func (*scriptedAdapter) Prepare(context.Context, adapters.TokenSource, adapters.Effect) (*adapters.Preparation, error) {
	return nil, adapters.Refuse("SCHEMA_VIOLATION", "not used")
}

func (a *scriptedAdapter) Dispatch(_ context.Context, _ adapters.TokenSource, effect adapters.Effect, digest []byte) adapters.DispatchResult {
	a.dispatched.Add(1)
	if r := adapters.CheckPermitDigest(effect.Arguments, digest); r != nil {
		return adapters.DispatchResult{Status: adapters.DispatchNotSent, Reason: r.Reason, Detail: r.Detail}
	}
	a.mu.Lock()
	fn := a.dispatchFn
	a.mu.Unlock()
	if fn != nil {
		return fn(effect)
	}
	return adapters.DispatchResult{Status: adapters.DispatchSent}
}

func (a *scriptedAdapter) Observe(_ context.Context, _ adapters.TokenSource, effect adapters.Effect) adapters.ObserveResult {
	a.observed.Add(1)
	a.mu.Lock()
	fn := a.observeFn
	a.mu.Unlock()
	if fn != nil {
		return fn(effect)
	}
	return succeeded(effect)
}

func (a *scriptedAdapter) script(dispatch func(adapters.Effect) adapters.DispatchResult, observe func(adapters.Effect) adapters.ObserveResult) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.dispatchFn, a.observeFn = dispatch, observe
}

const commitSHA = "89abcdef0123456789abcdef0123456789abcdef"

// succeeded is a read-back that establishes SUCCEEDED with the effect type's
// typed result.
func succeeded(effect adapters.Effect) adapters.ObserveResult {
	evidence := sha256.Sum256([]byte("provider bytes"))
	o := &adapters.Observation{Source: "fake.readback", TrustClass: "provider_readback", EvidenceDigest: evidence[:]}
	switch effect.EffectType {
	case effectargs.GitHubBranchCreateFromChanges:
		o.GitHubBranch = &adapters.GitHubBranchResult{Ref: "refs/heads/helm/x", CommitSHA: commitSHA,
			BaseSHA: "0123456789abcdef0123456789abcdef01234567", FilesDigest: evidence[:]}
	case effectargs.GitHubPullRequestCreateDraft:
		o.GitHubPullRequest = &adapters.GitHubPullRequestResult{URL: "https://github.com/acme/app/pull/7", Number: 7, Draft: true, State: "open"}
	case effectargs.GitHubRepositoryGet:
		o.GitHubRepository = &adapters.GitHubRepositoryResult{DefaultBranch: "main", DefaultBranchSHA: commitSHA}
	}
	return adapters.ObserveResult{Outcome: adapters.OutcomeSucceeded, Observation: o}
}

type fakeCredentials struct{}

func (fakeCredentials) Token(_ context.Context, tenantID string, effect adapters.Effect) (string, error) {
	return "token-for-" + tenantID + "-" + effect.EffectType, nil
}

// testValidator maps a token to its claims: the fake of the signature check,
// which the real Authenticator wraps.
type testValidator map[string]*jwks.OAuthTokenClaims

func (v testValidator) ValidateAuthorization(token string) (*jwks.OAuthTokenClaims, error) {
	if c, ok := v[token]; ok {
		return c, nil
	}
	return nil, &jwks.JWKSValidationError{Kind: jwks.JWKSErrInvalidSignature}
}

func claims(tenant, subject, scope string, episode *jwks.EpisodeClaim) *jwks.OAuthTokenClaims {
	return &jwks.OAuthTokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{Subject: subject, Audience: jwt.ClaimStrings{audience}, ID: "jti-" + subject},
		Scopes:           []string{scope}, TenantID: tenant, WorkspaceID: workspace, Actor: cpActor, Episode: episode,
	}
}

func episode(id string) *jwks.EpisodeClaim {
	return &jwks.EpisodeClaim{EpisodeID: id, WorkItemID: "work-" + id, OrganizationVersionID: "ver-1"}
}

// env is a running endpoint: the ledger, the adapter and the listener.
type env struct {
	t       *testing.T
	owner   *sql.DB
	runtime *sql.DB
	svc     *admission.Service
	rows    *authorityrows.Store
	adapter *scriptedAdapter
	gw      *Gateway
	auth    *server.Authenticator
	srv     *httptest.Server
	now     time.Time
}

func must(t testing.TB, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func withSearchPath(t *testing.T, raw, schema, role string) string {
	t.Helper()
	parsed, err := url.Parse(raw)
	must(t, err)
	query := parsed.Query()
	query.Set("search_path", schema)
	parsed.RawQuery = query.Encode()
	if role != "" {
		parsed.User = url.UserPassword(role, "gateway-probe")
	}
	return parsed.String()
}

// newEnv migrates a schema, seeds both tenants and serves the endpoint.
func newEnv(t *testing.T) *env {
	t.Helper()
	base := os.Getenv("HELM_TEST_POSTGRES_URL")
	if base == "" {
		t.Skip("set HELM_TEST_POSTGRES_URL to run the MCP endpoint proofs")
	}
	schema := fmt.Sprintf("helm_mcp_%d", time.Now().UnixNano())
	admin, err := sql.Open("postgres", base)
	must(t, err)
	t.Cleanup(func() { _ = admin.Close() })
	_, err = admin.Exec(`CREATE SCHEMA ` + schema)
	must(t, err)
	role := schema + "_role"
	t.Cleanup(func() {
		_, _ = admin.Exec(`DROP SCHEMA ` + schema + ` CASCADE`)
		_, _ = admin.Exec(`DROP ROLE IF EXISTS ` + role)
	})
	owner, err := sql.Open("postgres", withSearchPath(t, base, schema, ""))
	must(t, err)
	t.Cleanup(func() { _ = owner.Close() })
	must(t, admission.Migrate(context.Background(), owner))
	tables := append(append([]string{}, authorityrows.Tables...), admission.Tables...)
	for _, statement := range []string{
		`CREATE ROLE ` + role + ` LOGIN PASSWORD 'gateway-probe' NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB`,
		`GRANT USAGE ON SCHEMA ` + schema + ` TO ` + role,
		`GRANT SELECT, INSERT, UPDATE ON ` + strings.Join(tables, ", ") + ` TO ` + role,
		`REVOKE UPDATE ON authority_postings FROM ` + role,
		`REVOKE UPDATE ON authority_distinct_values, authority_token_replay FROM ` + role,
		`GRANT DELETE ON authority_token_replay TO ` + role,
		`GRANT SELECT ON gateway_schema_migrations TO ` + role,
	} {
		_, err := owner.Exec(statement)
		must(t, err)
	}
	runtime, err := sql.Open("postgres", withSearchPath(t, base, schema, role))
	must(t, err)
	runtime.SetMaxOpenConns(20)
	t.Cleanup(func() { _ = runtime.Close() })
	adapter := &scriptedAdapter{}
	svc, err := admission.New(runtime, admission.Config{Adapters: []adapters.Adapter{adapter}, Credentials: fakeCredentials{}})
	must(t, err)
	rows, err := authorityrows.New(owner)
	must(t, err)
	gw, err := NewGateway(svc, []adapters.Adapter{adapter})
	must(t, err)

	e := &env{t: t, owner: owner, runtime: runtime, svc: svc, rows: rows, adapter: adapter, gw: gw}
	must(t, owner.QueryRow(`SELECT now()`).Scan(&e.now))
	e.seed()

	// The worker listener's own token check, as runtime mounts it: the same
	// Authenticator as the model endpoints, for a token that proposes or reads.
	auth := &server.Authenticator{Actor: cpActor, RequireEpisode: true, Validator: testValidator{
		tokenSeat1Ep1:     claims(tenantA, "agt:seat-1", server.ScopePropose, episode("ep-1")),
		tokenContinuation: claims(tenantA, "agt:seat-1", server.ScopePropose, &jwks.EpisodeClaim{EpisodeID: "ep-continuation", WorkItemID: "work-ep-1", OrganizationVersionID: "ver-2"}),
		tokenReassigned:   claims(tenantA, "agt:seat-2", server.ScopePropose, &jwks.EpisodeClaim{EpisodeID: "ep-reassigned", WorkItemID: "work-ep-1", OrganizationVersionID: "ver-2"}),
		tokenSeat1Ep2:     claims(tenantA, "agt:seat-1", server.ScopePropose, episode("ep-2")),
		tokenSeat1Read: func() *jwks.OAuthTokenClaims {
			c := claims(tenantA, "agt:seat-1", server.ScopePropose, episode("ep-1"))
			c.Scopes = []string{server.ScopePropose, server.ScopeRead}
			return c
		}(),
		tokenSeat1Ro: claims(tenantA, "agt:seat-1", server.ScopeRead, episode("ep-1")),
		tokenSeat2:   claims(tenantA, "agt:seat-2", server.ScopePropose, episode("ep-1")),
		tokenNoSeat:  claims(tenantA, "agt:seat-none", server.ScopePropose, episode("ep-1")),
		tokenTenantB: claims(tenantB, "agt:seat-1", server.ScopePropose, episode("ep-1")),
		tokenService: claims(tenantA, "svc:compiler", server.ScopePropose, episode("ep-1")),
		tokenHuman:   claims(tenantA, "human-a", server.ScopePropose, episode("ep-1")),
		tokenNoEp:    claims(tenantA, "agt:seat-1", server.ScopePropose, nil),
	}}
	e.auth = auth
	e.srv = httptest.NewServer(&Handler{Backend: gw, Version: "test", Authenticate: func(ctx context.Context, header http.Header) (Caller, error) {
		id, err := auth.Authenticate(ctx, header, server.ScopePropose, server.ScopeRead)
		if err != nil {
			return Caller{}, err
		}
		return Caller{Caller: id.Caller, Scope: id.Scope}, nil
	}})
	t.Cleanup(e.srv.Close)
	return e
}

// seed creates both tenants. In tenant A seat 1 may read the repository and
// create branches, which its mandate makes wait for an approval; seat 2 may
// only read; one seat has no mandate; a service principal holds one, to show
// that only agents are served, whatever they hold. Tenant B's seat 1 has a
// mandate of its own over another repository.
func (e *env) seed() {
	e.t.Helper()
	ctx := context.Background()
	widen := authorityrows.WideningApproval{RequesterID: "human-a", ApproverID: "human-b"}
	for _, tenant := range []string{tenantA, tenantB} {
		must(e.t, e.rows.CreateTenant(ctx, tenant))
		for _, p := range []struct {
			id   string
			kind authorityrows.PrincipalKind
		}{{"human-a", authorityrows.PrincipalHuman}, {"human-b", authorityrows.PrincipalHuman}, {"agt:seat-1", authorityrows.PrincipalAgent},
			{"agt:seat-2", authorityrows.PrincipalAgent}, {"agt:seat-none", authorityrows.PrincipalAgent},
			{"svc:compiler", authorityrows.PrincipalService}, {cpActor, authorityrows.PrincipalService}} {
			must(e.t, e.rows.CreatePrincipal(ctx, tenant, p.id, p.kind))
		}
		must(e.t, e.rows.CreateEffectType(ctx, tenant, effectargs.GitHubRepositoryGet, authorityrows.RiskLow))
		must(e.t, e.rows.CreateEffectType(ctx, tenant, effectargs.GitHubBranchCreateFromChanges, authorityrows.RiskMedium))
		must(e.t, e.rows.CreateEffectType(ctx, tenant, effectargs.GitHubPullRequestCreateDraft, authorityrows.RiskMedium))
	}
	terms := func(targets []string, effects ...string) authorityrows.Terms {
		return authorityrows.Terms{EffectTypes: effects, ValidFrom: e.now.Add(-time.Hour), ValidUntil: e.now.Add(24 * time.Hour), Targets: targets}
	}
	seat1 := terms([]string{repoA}, effectargs.GitHubRepositoryGet, effectargs.GitHubBranchCreateFromChanges)
	seat1.ApprovalRequired = []string{effectargs.GitHubBranchCreateFromChanges}
	for holder, t := range map[string]authorityrows.Terms{
		"agt:seat-1":   seat1,
		"agt:seat-2":   terms([]string{repoA}, effectargs.GitHubRepositoryGet),
		"svc:compiler": terms([]string{repoA}, effectargs.GitHubRepositoryGet),
	} {
		_, err := e.rows.CreateMandate(ctx, tenantA, holder, t, widen)
		must(e.t, err)
	}
	_, err := e.rows.CreateMandate(ctx, tenantB, "agt:seat-1", terms([]string{repoB}, effectargs.GitHubRepositoryGet), widen)
	must(e.t, err)
}

// reply is an MCP answer as a client sees it.
type reply struct {
	Status int
	Header http.Header
	Body   map[string]any
}

func (r reply) result(t testing.TB) map[string]any {
	t.Helper()
	m, ok := r.Body["result"].(map[string]any)
	if r.Status != http.StatusOK || !ok {
		t.Fatalf("not a result: %d %v", r.Status, r.Body)
	}
	return m
}

func (r reply) rpcError(t testing.TB, status, code int) map[string]any {
	t.Helper()
	e, ok := r.Body["error"].(map[string]any)
	if r.Status != status || !ok || int(e["code"].(float64)) != code {
		t.Fatalf("want JSON-RPC error %d (HTTP %d), got HTTP %d %v", code, status, r.Status, r.Body)
	}
	return e
}

// structured is the structuredContent of a tool result, and whether the result
// is an error.
func (r reply) structured(t testing.TB) (content map[string]any, isError bool) {
	t.Helper()
	res := r.result(t)
	content, ok := res["structuredContent"].(map[string]any)
	if !ok {
		t.Fatalf("no structuredContent: %v", res)
	}
	var text map[string]any
	if json.Unmarshal([]byte(res["content"].([]any)[0].(map[string]any)["text"].(string)), &text) != nil || text["status"] != content["status"] {
		t.Fatalf("the text content is not the structured result: %v", res["content"])
	}
	return content, res["isError"] == true
}

// post sends one HTTP request with an SDK-like client.
func (e *env) post(t testing.TB, token string, headers map[string]string, body string) reply {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, e.srv.URL, strings.NewReader(body))
	must(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	must(t, err)
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(resp.Body)
	must(t, err)
	out := reply{Status: resp.StatusCode, Header: resp.Header}
	if len(raw) > 0 && strings.HasPrefix(resp.Header.Get("Content-Type"), "application/json") {
		must(t, json.Unmarshal(raw, &out.Body))
	}
	return out
}

// modern sends a 2026-07-28 request.
func (e *env) modern(t testing.TB, token string, id any, method string, params map[string]any) reply {
	t.Helper()
	if params == nil {
		params = map[string]any{}
	}
	meta := map[string]any{
		"io.modelcontextprotocol/protocolVersion":    ProtocolModern,
		"io.modelcontextprotocol/clientInfo":         map[string]string{"name": "native-client", "version": "1"},
		"io.modelcontextprotocol/clientCapabilities": map[string]any{},
	}
	for k, v := range extraMeta(params) {
		meta[k] = v
	}
	params["_meta"] = meta
	raw, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": id, "method": method, "params": params})
	must(t, err)
	headers := map[string]string{"MCP-Protocol-Version": ProtocolModern, "Mcp-Method": method}
	if name, ok := params["name"].(string); ok {
		headers["Mcp-Name"] = name
	}
	return e.post(t, token, headers, string(raw))
}

// extraMeta lets a test add to _meta through the params it passes.
func extraMeta(params map[string]any) map[string]any {
	m, _ := params["_extra_meta"].(map[string]any)
	delete(params, "_extra_meta")
	return m
}

// legacy sends a request of the initialization-based revisions.
func (e *env) legacy(t testing.TB, token, version string, id any, method string, params map[string]any) reply {
	t.Helper()
	body := map[string]any{"jsonrpc": "2.0", "id": id, "method": method}
	if params != nil {
		body["params"] = params
	}
	raw, err := json.Marshal(body)
	must(t, err)
	headers := map[string]string{}
	if version != "" {
		headers["MCP-Protocol-Version"] = version
	}
	return e.post(t, token, headers, string(raw))
}

// callTool sends a tool call as a native client does.
func (e *env) callTool(t testing.TB, token string, id any, tool string, args map[string]any) reply {
	t.Helper()
	return e.modern(t, token, id, "tools/call", map[string]any{"name": tool, "arguments": args})
}

func getArgs(target string) map[string]any {
	return map[string]any{"target": target, "arguments": map[string]any{"schema": "helm.github.repository.get.v1"}}
}

func branchCall(target, head string) map[string]any {
	return map[string]any{"target": target, "arguments": map[string]any{
		"schema": "helm.github.branch.create_from_changes.v1", "base": "main", "base_sha": "0123456789abcdef0123456789abcdef01234567",
		"head": head, "message": "Add skeleton", "files": []any{map[string]any{"path": "docs/skeleton.md", "mode": "100644", "content_utf8": "# Skeleton\n"}}}}
}

// ownerCount counts rows as the gateway's runtime role sees them for tenant.
func (e *env) count(tenant, query string, args ...any) int {
	e.t.Helper()
	tx, err := e.runtime.Begin()
	must(e.t, err)
	defer func() { _ = tx.Rollback() }()
	_, err = tx.Exec(`SELECT set_config('app.current_tenant', $1, true)`, tenant)
	must(e.t, err)
	var n int
	must(e.t, tx.QueryRow(query, args...).Scan(&n))
	return n
}

// attempt reads an attempt the way the Control Plane does: a service principal
// with no episode.
func (e *env) attempt(tenant, id string) admission.Attempt {
	e.t.Helper()
	a, err := e.svc.Get(context.Background(), admission.Caller{TenantID: tenant, WorkspaceID: workspace, PrincipalID: cpActor}, id)
	must(e.t, err)
	return a
}
