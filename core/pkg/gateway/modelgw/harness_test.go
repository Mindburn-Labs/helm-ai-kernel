package modelgw

// The model gateway against real PostgreSQL 16 (listed in
// scripts/ci/postgres-proofs.txt) and stub provider APIs on loopback. Each test
// migrates a fresh schema, seeds authority rows as the owner and serves the
// gateway as a restricted role, the way `helm-gateway serve` runs.
//
// quantum_posture: fake token claims and SHA-256 digests; nothing here signs or
// verifies a real credential, and no post-quantum claim is made.

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
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
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/custody"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/effectargs"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/server"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/kernel/authority/authorityrows"
)

const (
	tenantA   = "tenant-a"
	tenantB   = "tenant-b"
	workspace = "ws-a"
	cpActor   = "spiffe://helm/control-plane"

	// The provider keys the gateway holds, and the tokens callers hold. A test
	// asserts the first never reach a client, a log or the database, and the
	// second never reach a provider.
	keyAnthropic  = "canary-anthropic-api-key-aaaa"
	keyOpenAI     = "canary-openai-api-key-91bc"
	keyOpenRouter = "canary-openrouter-api-key-c04d"

	tokenAgent     = "canary-episode-token-agent"
	tokenAgentEp2  = "canary-episode-token-agent-episode-2"
	tokenService   = "canary-service-token-compiler"
	tokenHuman     = "canary-human-token"
	tokenNoEpisode = "canary-worker-token-without-episode"
	tokenOtherTen  = "canary-agent-token-tenant-b"
	// Seats whose mandates differ from the first seat's in one term each.
	tokenLimited  = "canary-episode-token-seat-limited"
	tokenApproval = "canary-episode-token-seat-approval"
	tokenHaiku    = "canary-episode-token-seat-haiku"
)

// stubProvider is a provider API on loopback whose behaviour a test sets.
type stubProvider struct {
	*httptest.Server
	handler atomic.Value // http.HandlerFunc
	calls   atomic.Int32

	mu       sync.Mutex
	requests []seen
}

// seen is one request a provider received.
type seen struct {
	Method, Path, Query string
	Header              http.Header
	Body                []byte
}

func newStubProvider(t *testing.T) *stubProvider {
	t.Helper()
	p := &stubProvider{}
	p.handler.Store(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { http.Error(w, "no behaviour set", 500) }))
	p.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		p.calls.Add(1)
		p.mu.Lock()
		p.requests = append(p.requests, seen{r.Method, r.URL.Path, r.URL.RawQuery, r.Header.Clone(), body})
		p.mu.Unlock()
		r.Body = io.NopCloser(bytes.NewReader(body))
		p.handler.Load().(http.HandlerFunc)(w, r)
	}))
	t.Cleanup(p.Close)
	return p
}

func (p *stubProvider) on(h http.HandlerFunc) { p.handler.Store(h) }

func (p *stubProvider) last(t *testing.T) seen {
	t.Helper()
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.requests) == 0 {
		t.Fatal("the provider received no request")
	}
	return p.requests[len(p.requests)-1]
}

// testValidator maps a token to its claims: the fake of the JWKS check, which
// the real Authenticator wraps.
type testValidator map[string]*jwks.OAuthTokenClaims

func (v testValidator) ValidateAuthorization(token string) (*jwks.OAuthTokenClaims, error) {
	if c, ok := v[token]; ok {
		return c, nil
	}
	return nil, &jwks.JWKSValidationError{Kind: jwks.JWKSErrInvalidSignature}
}

func claims(subject, audience, scope string, episode *jwks.EpisodeClaim) *jwks.OAuthTokenClaims {
	return &jwks.OAuthTokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{Subject: subject, Audience: jwt.ClaimStrings{audience}, ID: "jti-" + subject},
		Scopes:           []string{scope}, TenantID: tenantA, WorkspaceID: workspace, Actor: cpActor, Episode: episode,
	}
}

// env is a running gateway: the ledger, the providers and both listeners.
type env struct {
	t       *testing.T
	owner   *sql.DB
	runtime *sql.DB
	svc     *admission.Service
	rows    *authorityrows.Store
	now     time.Time

	anthropic, openai, openrouter *stubProvider
	cfg                           *Config
	gw                            *Gateway
	main, worker                  *httptest.Server
	logs                          *lockedBuffer
	keys                          string
}

type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
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

// newEnv migrates a schema, seeds the tenant, serves the gateway on both
// listeners and returns it. modelBudget is the daily usd_micros limit of the
// agent's mandate.
func newEnv(t *testing.T, modelBudget int64) *env {
	t.Helper()
	base := os.Getenv("HELM_TEST_POSTGRES_URL")
	if base == "" {
		t.Skip("set HELM_TEST_POSTGRES_URL to run the model gateway proofs")
	}
	schema := fmt.Sprintf("helm_modelgw_%d", time.Now().UnixNano())
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
	ctx := context.Background()
	must(t, admission.Migrate(ctx, owner))
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
	runtime.SetMaxOpenConns(40)
	t.Cleanup(func() { _ = runtime.Close() })
	svc, err := admission.New(runtime, admission.Config{Adapters: []adapters.Adapter{NewAdapter()}})
	must(t, err)
	rows, err := authorityrows.New(owner)
	must(t, err)

	e := &env{t: t, owner: owner, runtime: runtime, svc: svc, rows: rows, logs: &lockedBuffer{}}
	must(t, owner.QueryRow(`SELECT now()`).Scan(&e.now))
	e.seed(modelBudget)

	e.anthropic, e.openai, e.openrouter = newStubProvider(t), newStubProvider(t), newStubProvider(t)
	e.keys = keyFiles(t, map[string]string{"anthropic": keyAnthropic, "openai": keyOpenAI, "openrouter": keyOpenRouter})
	cfg, err := ParseConfig([]byte(routesJSON(e.anthropic.URL, e.openai.URL+"/v1", e.openrouter.URL+"/api/v1", e.keys)))
	must(t, err)
	e.cfg = cfg
	custodyKeys, err := custody.NewProviderKeys(cfg.KeyFiles())
	must(t, err)
	e.gw = &Gateway{Config: cfg, Ledger: svc, Keys: custodyKeys, Logger: slog.New(slog.NewTextHandler(e.logs, &slog.HandlerOptions{Level: slog.LevelDebug}))}
	e.main = e.serve(false)
	e.worker = e.serve(true)
	return e
}

// authenticator is a listener's token check. The main listener accepts service
// tokens of the gateway's audience; the worker listener episode tokens of the
// worker audience, and each refuses the other's, as their validators do.
func (e *env) authenticator(worker bool) *server.Authenticator {
	audience, tokens := "helm-gateway:test", testValidator{
		tokenService:        claims("svc:helm-org-compiler", "helm-gateway:test", server.ScopePropose, nil),
		tokenHuman:          claims("human-a", "helm-gateway:test", server.ScopePropose, nil),
		"canary-read-token": claims("svc:helm-org-compiler", "helm-gateway:test", server.ScopeRead, nil),
	}
	if worker {
		audience = "helm-gateway-worker:test"
		episode := func(id string) *jwks.EpisodeClaim {
			return &jwks.EpisodeClaim{EpisodeID: id, WorkItemID: "work-" + id, OrganizationVersionID: "ver-1"}
		}
		tokens = testValidator{
			tokenAgent:     claims("agt:seat-1", audience, server.ScopePropose, episode("ep-1")),
			tokenAgentEp2:  claims("agt:seat-1", audience, server.ScopePropose, episode("ep-2")),
			tokenNoEpisode: claims("agt:seat-1", audience, server.ScopePropose, nil),
			tokenOtherTen: func() *jwks.OAuthTokenClaims {
				c := claims("agt:seat-1", audience, server.ScopePropose, episode("ep-1"))
				c.TenantID = tenantB
				return c
			}(),
			tokenLimited:          claims("agt:seat-limited", audience, server.ScopePropose, episode("ep-1")),
			tokenApproval:         claims("agt:seat-approval", audience, server.ScopePropose, episode("ep-1")),
			tokenHaiku:            claims("agt:seat-haiku", audience, server.ScopePropose, episode("ep-1")),
			"canary-human-worker": claims("human-a", audience, server.ScopePropose, episode("ep-1")),
			"canary-svc-worker":   claims("svc:helm-org-compiler", audience, server.ScopePropose, episode("ep-1")),
			"canary-read-worker":  claims("agt:seat-1", audience, server.ScopeRead, episode("ep-1")),
		}
	}
	return &server.Authenticator{Validator: tokens, Actor: cpActor, RequireEpisode: worker}
}

func (e *env) workerAuth() *server.Authenticator { return e.authenticator(true) }

// serve starts a listener.
func (e *env) serve(worker bool) *httptest.Server {
	name := "main"
	if worker {
		name = "worker"
	}
	srv := httptest.NewServer(server.WithTLSState(e.gw.Handler(Listener{Name: name, Auth: e.authenticator(worker), Worker: worker})))
	e.t.Cleanup(srv.Close)
	return srv
}

// newTestServer serves h on loopback until the test ends and returns its URL.
func newTestServer(t *testing.T, h http.Handler) string {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return srv.URL
}

// requestOnce sends one POST and returns the response as soon as its headers
// arrive, for tests that read the body themselves.
func requestOnce(url string, headers map[string]string, body string) (*http.Response, error) {
	req, err := http.NewRequest(http.MethodPost, url, strings.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	return http.DefaultClient.Do(req)
}

// waitFor polls cond for a few seconds.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	for deadline := time.Now().Add(8 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		if cond() {
			return
		}
	}
	t.Fatalf("timed out waiting for %s", what)
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	must(t, os.WriteFile(path, []byte(content), 0o600))
}

// seed creates tenant A: the seat's agent principal with a mandate over the
// routes it may use, a service principal for the compiler, and the effect type.
func (e *env) seed(modelBudget int64) {
	e.t.Helper()
	ctx := context.Background()
	for _, tenant := range []string{tenantA, tenantB} {
		must(e.t, e.rows.CreateTenant(ctx, tenant))
		for _, p := range []struct {
			id   string
			kind authorityrows.PrincipalKind
		}{{"human-a", authorityrows.PrincipalHuman}, {"human-b", authorityrows.PrincipalHuman}, {"agt:seat-1", authorityrows.PrincipalAgent},
			{"agt:seat-limited", authorityrows.PrincipalAgent}, {"agt:seat-approval", authorityrows.PrincipalAgent}, {"agt:seat-haiku", authorityrows.PrincipalAgent},
			{"svc:helm-org-compiler", authorityrows.PrincipalService}, {cpActor, authorityrows.PrincipalService}} {
			must(e.t, e.rows.CreatePrincipal(ctx, tenant, p.id, p.kind))
		}
		must(e.t, e.rows.CreateEffectType(ctx, tenant, effectargs.ModelInference, authorityrows.RiskLow))
	}
	terms := authorityrows.Terms{
		EffectTypes: []string{effectargs.ModelInference}, ValidFrom: e.now.Add(-time.Hour), ValidUntil: e.now.Add(24 * time.Hour),
		Targets: []string{routeSonnet, routeHaiku, routeGPT, routeOR},
	}
	seat, err := e.rows.CreateMandate(ctx, tenantA, "agt:seat-1", terms, authorityrows.WideningApproval{RequesterID: "human-a", ApproverID: "human-b"})
	must(e.t, err)
	_, err = e.rows.CreateLimit(ctx, tenantA, authorityrows.LimitSpec{MandateID: &seat.ID, Unit: admission.UnitUSDMicros, Measure: "sum", Window: "day", Value: modelBudget, Span: 1})
	must(e.t, err)
	// Seats that differ in one term: a per-call limit, an approval rule, one route.
	widen := authorityrows.WideningApproval{RequesterID: "human-a", ApproverID: "human-b"}
	perCall := int64(1000)
	limited := terms
	limited.PerCallLimit = &perCall
	_, err = e.rows.CreateMandate(ctx, tenantA, "agt:seat-limited", limited, widen)
	must(e.t, err)
	approval := terms
	approval.ApprovalRequired = []string{effectargs.ModelInference}
	_, err = e.rows.CreateMandate(ctx, tenantA, "agt:seat-approval", approval, widen)
	must(e.t, err)
	haiku := terms
	haiku.Targets = []string{routeHaiku}
	_, err = e.rows.CreateMandate(ctx, tenantA, "agt:seat-haiku", haiku, widen)
	must(e.t, err)
	// The compiler is a platform service: any route.
	anyTarget := terms
	anyTarget.Targets = nil
	_, err = e.rows.CreateMandate(ctx, tenantA, "svc:helm-org-compiler", anyTarget, authorityrows.WideningApproval{RequesterID: "human-a", ApproverID: "human-b"})
	must(e.t, err)
	// Tenant B has its own agent, with a mandate of its own.
	_, err = e.rows.CreateMandate(ctx, tenantB, "agt:seat-1", terms, authorityrows.WideningApproval{RequesterID: "human-a", ApproverID: "human-b"})
	must(e.t, err)
}

func (e *env) count(tenant, query string, args ...any) int {
	e.t.Helper()
	var n int
	// Inspect through the gateway role: the migration owner can be a
	// superuser and bypass RLS even after binding app.current_tenant.
	tx, err := e.runtime.Begin()
	must(e.t, err)
	defer func() { _ = tx.Rollback() }()
	_, err = tx.Exec(`SELECT set_config('app.current_tenant', $1, true)`, tenant)
	must(e.t, err)
	must(e.t, tx.QueryRow(query, args...).Scan(&n))
	return n
}

// attempts returns every attempt of tenant A, oldest first, as the ledger has
// them.
func (e *env) attempts() []admission.Attempt {
	e.t.Helper()
	tx, err := e.runtime.Begin()
	must(e.t, err)
	defer func() { _ = tx.Rollback() }()
	_, err = tx.Exec(`SELECT set_config('app.current_tenant', $1, true)`, tenantA)
	must(e.t, err)
	rows, err := tx.Query(`SELECT attempt_id::text FROM authority_effect_attempts ORDER BY created_at, attempt_id`)
	must(e.t, err)
	var ids []string
	for rows.Next() {
		var id string
		must(e.t, rows.Scan(&id))
		ids = append(ids, id)
	}
	must(e.t, rows.Close())
	must(e.t, tx.Commit())
	var out []admission.Attempt
	for _, id := range ids {
		a, err := e.svc.Get(context.Background(), admission.Caller{TenantID: tenantA, WorkspaceID: workspace, PrincipalID: "x"}, id)
		must(e.t, err)
		out = append(out, a)
	}
	return out
}

// counters returns the used and reserved totals of tenant A's usd_micros limits.
func (e *env) counters() (used, reserved int64) {
	e.t.Helper()
	tx, err := e.runtime.Begin()
	must(e.t, err)
	defer func() { _ = tx.Rollback() }()
	_, err = tx.Exec(`SELECT set_config('app.current_tenant', $1, true)`, tenantA)
	must(e.t, err)
	must(e.t, tx.QueryRow(`SELECT COALESCE(sum(used), 0), COALESCE(sum(reserved), 0) FROM authority_counters`).Scan(&used, &reserved))
	return used, reserved
}

// ledgerBalances fails unless every counter carries exactly its exposures
// (ADR-0003 S-I1): reserved is the sum of held, used the sum of estimated and
// confirmed.
func (e *env) ledgerBalances() {
	e.t.Helper()
	if bad := e.count(tenantA, `SELECT count(*) FROM authority_counters c WHERE
			c.reserved <> COALESCE((SELECT sum(amount) FROM authority_exposures e WHERE e.tenant_id = c.tenant_id AND e.limit_id = c.limit_id AND e.bucket_start = c.bucket_start AND kind = 'held'), 0)
			OR c.used <> COALESCE((SELECT sum(amount) FROM authority_exposures e WHERE e.tenant_id = c.tenant_id AND e.limit_id = c.limit_id AND e.bucket_start = c.bucket_start AND kind IN ('estimated', 'confirmed')), 0)`); bad != 0 {
		e.t.Fatalf("%d counters disagree with their exposures", bad)
	}
}

// reply is an HTTP response as a client sees it.
type reply struct {
	Status int
	Header http.Header
	Body   []byte
}

func (r reply) String() string { return fmt.Sprintf("%d %s", r.Status, r.Body) }

// post sends one request to a listener with an SDK-like client.
func post(t testing.TB, base, path string, headers map[string]string, body string) reply {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, base+path, strings.NewReader(body))
	must(t, err)
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	must(t, err)
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(resp.Body)
	must(t, err)
	return reply{Status: resp.StatusCode, Header: resp.Header, Body: raw}
}

func bearerHeader(token string) map[string]string {
	return map[string]string{"Authorization": "Bearer " + token}
}

func jsonBody(t testing.TB, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	must(t, err)
	return string(b)
}
