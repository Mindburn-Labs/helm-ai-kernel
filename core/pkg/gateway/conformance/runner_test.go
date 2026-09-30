package conformance

// The conformance table against the real gateway on PostgreSQL 16 (listed in
// scripts/ci/postgres-proofs.txt): each scenario gets a fresh schema seeded
// from its fixtures, the admission service with a scripted adapter and the
// GitHub App custody, and the Connect server behind the kernel's JWKS
// verifier. The runner mints a signed token from each scenario's abstract
// claims.
//
// quantum_posture: signs classical RS256 test tokens and a test GitHub App
// JWT and computes SHA-256 digests; no post-quantum claim.

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/go-jose/go-jose/v4"
	"github.com/golang-jwt/jwt/v5"
	_ "github.com/lib/pq"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/auth/jwks"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/adapters"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/admission"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/custody"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/effectargs"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/server"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/kernel/authority/authorityrows"
	errorsv1 "github.com/Mindburn-Labs/helm-ai-kernel/sdk/go/gen/helm/errors/v1"
	gatewayv1 "github.com/Mindburn-Labs/helm-ai-kernel/sdk/go/gen/helm/gateway/v1"
)

const (
	testIssuer   = "https://control-plane.conformance.test"
	testAudience = "helm-gateway:conformance"
)

func TestPostgresGatewayConformanceTable(t *testing.T) {
	base := postgresURL(t)
	scenarios, err := checkTable(repoRoot(t), tableDir(t))
	must(t, err)
	for _, sc := range scenarios {
		t.Run(sc.ID, func(t *testing.T) {
			if err := runScenario(t, base, sc); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// The planted check: copies of scenarios with one expected outcome flipped
// must each fail at the flipped step, so the runner is not a table that
// passes whatever it says. Each flip is a different kind of expectation.
func TestPostgresConformanceRunnerRejectsAFlippedExpectation(t *testing.T) {
	base := postgresURL(t)
	for _, flip := range []struct {
		file, from, to, step string
	}{
		{"GW-001-walking-skeleton.json", `"state": "ADMITTED"`, `"state": "DENIED"`, "step 1 (Propose)"},
		{"GW-004-self-approval-refused.json", `"reason_code": "APPROVER_NOT_DISTINCT"`, `"reason_code": "INSUFFICIENT_PRIVILEGE"`, "step 4 (Approve)"},
		{"GW-011-double-dispatch-calls-the-adapter-once.json", `"dispatch": 1,`, `"dispatch": 2,`, "step 2 (Dispatch)"},
		{"GW-014-contradicting-readback-consumes-the-reservation.json", `"exposure": "CONFIRMED"`, `"exposure": "RELEASED"`, "step 2 (Dispatch)"},
		{"GW-016-idempotent-propose.json", `"existing": true`, `"existing": false`, "step 2 (Propose)"},
		{"GW-024-step-up-proof-admits-and-is-single-use.json", `"reason_code": "STEP_UP_REQUIRED"`, `"reason_code": "INSUFFICIENT_PRIVILEGE"`, "step 3 (Approve)"},
		{"GW-024-step-up-proof-admits-and-is-single-use.json", `"state": "ADMITTED"`, `"state": "ESCALATED"`, "step 13 (Approve)"},
	} {
		t.Run(flip.file, func(t *testing.T) {
			source := filepath.Join(tableDir(t), "scenarios", flip.file)
			body, err := os.ReadFile(source) // #nosec G304 -- a table file of this repository
			must(t, err)
			flipped := bytes.Replace(body, []byte(flip.from), []byte(flip.to), 1)
			if bytes.Equal(flipped, body) {
				t.Fatalf("%s no longer contains %s; plant another flip", flip.file, flip.from)
			}
			path := filepath.Join(t.TempDir(), flip.file)
			must(t, os.WriteFile(path, flipped, 0o600))
			sc, err := loadScenario(path)
			must(t, err)
			err = runScenario(t, base, sc)
			if err == nil || !strings.Contains(err.Error(), flip.step) {
				t.Fatalf("the flip %s -> %s passed or failed elsewhere: %v", flip.from, flip.to, err)
			}
			t.Logf("refused as it must be: %v", err)
		})
	}
}

func postgresURL(t *testing.T) string {
	t.Helper()
	base := os.Getenv("HELM_TEST_POSTGRES_URL")
	if base == "" {
		t.Skip("set HELM_TEST_POSTGRES_URL to run the gateway conformance table")
	}
	return base
}

// run is one scenario's gateway and its state.
type run struct {
	t       *testing.T
	sc      scenario
	db      *sql.DB
	rows    *authorityrows.Store
	adapter *scripted
	client  gatewayv1.EffectGatewayServiceClient
	key     *rsa.PrivateKey
	minted  map[string]string
	labels  map[string]*gatewayv1.EffectAttempt
}

func runScenario(t *testing.T, base string, sc scenario) error {
	r := &run{t: t, sc: sc, minted: map[string]string{}, labels: map[string]*gatewayv1.EffectAttempt{}}
	if err := r.start(base); err != nil {
		return fmt.Errorf("%s: setup: %w", sc.ID, err)
	}
	for i, st := range sc.Steps {
		what := fmt.Sprintf("%s step %d (%s)", sc.ID, i+1, st.RPC)
		if st.Control != nil {
			what = fmt.Sprintf("%s step %d (control %s)", sc.ID, i+1, st.Control.Kind)
		}
		if err := r.step(st); err != nil {
			return fmt.Errorf("%s: %w", what, err)
		}
	}
	return nil
}

// start migrates a fresh schema, seeds the fixtures in every tenant, and
// serves the gateway to a Connect client.
func (r *run) start(base string) error {
	ctx := context.Background()
	admin, err := sql.Open("postgres", base)
	if err != nil {
		return err
	}
	r.t.Cleanup(func() { _ = admin.Close() })
	schema := fmt.Sprintf("helm_gateway_conformance_%d", time.Now().UnixNano())
	if _, err := admin.Exec(`CREATE SCHEMA ` + schema); err != nil {
		return err
	}
	r.t.Cleanup(func() { _, _ = admin.Exec(`DROP SCHEMA ` + schema + ` CASCADE`) })
	parsed, err := url.Parse(base)
	if err != nil {
		return err
	}
	query := parsed.Query()
	query.Set("search_path", schema)
	parsed.RawQuery = query.Encode()
	if r.db, err = sql.Open("postgres", parsed.String()); err != nil {
		return err
	}
	r.t.Cleanup(func() { _ = r.db.Close() })
	if err := admission.Migrate(ctx, r.db); err != nil {
		return err
	}
	if r.rows, err = authorityrows.New(r.db); err != nil {
		return err
	}
	if err := r.seed(ctx); err != nil {
		return err
	}

	fx := r.sc.Fixtures
	r.adapter = &scripted{effectTypes: fx.Adapter.EffectTypes, dispatch: fx.Adapter.Dispatch, observe: fx.Adapter.Observe}
	r.adapter.provider.defaultBranch = fx.Adapter.Provider.DefaultBranch
	r.adapter.provider.defaultBranchSHA = fx.Adapter.Provider.DefaultBranchSHA
	r.adapter.provider.branchCommitSHA = fx.Adapter.Provider.BranchCommitSHA
	app, err := githubApp(r.t, fx.Tenants)
	if err != nil {
		return err
	}
	svc, err := admission.New(r.db, admission.Config{Adapters: []adapters.Adapter{r.adapter}, Credentials: app})
	if err != nil {
		return err
	}
	validator, err := r.issuer()
	if err != nil {
		return err
	}
	api := &server.Server{Admission: svc, Auth: &server.Authenticator{Validator: validator, Actor: fx.ConfiguredActor}}
	mux := http.NewServeMux()
	mux.Handle(api.Handler())
	srv := httptest.NewUnstartedServer(mux)
	srv.EnableHTTP2 = true
	srv.StartTLS()
	r.t.Cleanup(srv.Close)
	r.client = gatewayv1.NewEffectGatewayServiceClient(srv.Client(), srv.URL, connect.WithGRPC())
	return nil
}

func (r *run) seed(ctx context.Context) error {
	fx := r.sc.Fixtures
	var now time.Time
	if err := r.db.QueryRowContext(ctx, `SELECT now()`).Scan(&now); err != nil {
		return err
	}
	for _, tenant := range fx.Tenants {
		if err := r.rows.CreateTenant(ctx, tenant); err != nil {
			return err
		}
		for _, p := range fx.Principals {
			if err := r.rows.CreatePrincipal(ctx, tenant, p.ID, authorityrows.PrincipalKind(p.Kind)); err != nil {
				return fmt.Errorf("principal %s: %w", p.ID, err)
			}
		}
		for _, e := range fx.EffectTypes {
			if err := r.rows.CreateEffectType(ctx, tenant, e.EffectType, authorityrows.RiskClass(e.Risk)); err != nil {
				return fmt.Errorf("effect type %s: %w", e.EffectType, err)
			}
		}
		for i, m := range fx.Mandates {
			terms := authorityrows.Terms{
				EffectTypes: m.EffectTypes, Targets: m.Targets, Condition: m.Condition, ApprovalRequired: m.ApprovalRequired,
				ValidFrom: now.Add(-time.Hour), ValidUntil: now.Add(time.Hour),
			}
			if len(m.RiskClasses) > 0 {
				terms.RiskClasses = map[string]authorityrows.RiskClass{}
				for effectType, risk := range m.RiskClasses {
					terms.RiskClasses[effectType] = authorityrows.RiskClass(risk)
				}
			}
			mandate, err := r.rows.CreateMandate(ctx, tenant, m.Holder, terms,
				authorityrows.WideningApproval{RequesterID: m.Activation.Requester, ApproverID: m.Activation.Approver})
			if err != nil {
				return fmt.Errorf("mandate %d: %w", i+1, err)
			}
			for _, l := range m.Limits {
				if _, err := r.rows.CreateLimit(ctx, tenant, authorityrows.LimitSpec{
					MandateID: &mandate.ID, Unit: l.Unit, Measure: "sum", Window: l.Window, Value: l.Value, Span: 1,
				}); err != nil {
					return fmt.Errorf("mandate %d limit %s: %w", i+1, l.Unit, err)
				}
			}
		}
	}
	return nil
}

// issuer serves a JWKS for a fresh signing key and returns the kernel's
// verifier for it, configured as helm-gateway configures it.
func (r *run) issuer() (*jwks.JWKSValidator, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	r.key = key
	body, err := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "k1", Use: "sig", Algorithm: "RS256"}}})
	if err != nil {
		return nil, err
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(body) }))
	r.t.Cleanup(srv.Close)
	return jwks.NewJWKSValidator(jwks.JWKSConfig{
		JWKSURL: srv.URL, Issuer: testIssuer, Audience: testAudience, Algorithms: []string{"RS256"},
		MaxTokenTTL: 5 * time.Minute, Leeway: 30 * time.Second, AllowInsecureLoopback: true,
	}), nil
}

// token mints the named token once; every later use presents the same
// bytes, so reusing a name reuses its jti.
func (r *run) token(name string) (string, error) {
	if signed, ok := r.minted[name]; ok {
		return signed, nil
	}
	tk, ok := r.sc.Tokens[name]
	if !ok {
		return "", fmt.Errorf("no token %q", name)
	}
	now := time.Now()
	claims := jwt.MapClaims{
		"iss": testIssuer, "aud": []string{testAudience}, "sub": tk.Sub,
		"iat": now.Unix(), "exp": now.Add(2 * time.Minute).Unix(), "jti": tk.JTI,
		"scope": tk.Scope, "tenant_id": tk.Tenant, "workspace_id": tk.Workspace,
	}
	if tk.ActSub != "" {
		claims["act"] = map[string]string{"sub": tk.ActSub}
	}
	if len(tk.AuthorizationDetails) > 0 {
		details, err := r.substitute(tk.AuthorizationDetails)
		if err != nil {
			return "", err
		}
		claims["authorization_details"] = json.RawMessage(details)
	}
	jt := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	jt.Header["kid"] = "k1"
	signed, err := jt.SignedString(r.key)
	if err != nil {
		return "", err
	}
	r.minted[name] = signed
	return signed, nil
}

// substitute resolves {{attempt_id:L}}, {{approval_digest:L}} (base64) and
// {{approval_digest_hex:L}} (lower-case hex, the form a helm_step_up entry
// carries) from the attempts earlier steps labelled.
func (r *run) substitute(raw []byte) ([]byte, error) {
	var missing error
	out := placeholder.ReplaceAllFunc(raw, func(m []byte) []byte {
		parts := placeholder.FindSubmatch(m)
		a, ok := r.labels[string(parts[2])]
		if !ok {
			missing = fmt.Errorf("label %q is not defined yet", parts[2])
			return m
		}
		digest := a.GetPendingApproval().GetApprovalDigest()
		switch string(parts[1]) {
		case "attempt_id":
			return []byte(a.GetAttemptId())
		case "approval_digest_hex":
			return []byte(hex.EncodeToString(digest))
		}
		return []byte(base64.StdEncoding.EncodeToString(digest))
	})
	return out, missing
}

// request turns a step's request into the RPC's message: placeholders
// resolved, and ProposeRequest.effect.arguments_json replaced by its compact
// bytes as arguments.
func (r *run) request(st step, msg proto.Message) error {
	raw, err := r.substitute(st.Request)
	if err != nil {
		return err
	}
	if st.RPC == "Propose" {
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(raw, &fields); err != nil {
			return err
		}
		var effect map[string]json.RawMessage
		if err := json.Unmarshal(fields["effect"], &effect); err != nil {
			return fmt.Errorf("effect: %w", err)
		}
		if args, ok := effect["arguments_json"]; ok {
			var compact bytes.Buffer
			if err := json.Compact(&compact, args); err != nil {
				return err
			}
			delete(effect, "arguments_json")
			encoded, _ := json.Marshal(compact.Bytes()) // base64, as proto3 JSON carries bytes
			effect["arguments"] = encoded
		}
		if fields["effect"], err = json.Marshal(effect); err != nil {
			return err
		}
		if raw, err = json.Marshal(fields); err != nil {
			return err
		}
	}
	return protojson.Unmarshal(raw, msg)
}

func (r *run) step(st step) error {
	if st.Control != nil {
		return r.control(*st.Control)
	}
	header := http.Header{}
	if st.Token != "" {
		signed, err := r.token(st.Token)
		if err != nil {
			return err
		}
		header.Set("Authorization", "Bearer "+signed)
	}
	attempt, existing, err := r.call(st, header)
	if err := r.compare(st, attempt, existing, err); err != nil {
		return err
	}
	if st.Label != "" {
		if attempt == nil {
			return fmt.Errorf("label %q names no attempt", st.Label)
		}
		r.labels[st.Label] = attempt
	}
	return nil
}

// call performs one RPC. An error comes back as the error, not a failure of
// the step; compare decides.
func (r *run) call(st step, header http.Header) (*gatewayv1.EffectAttempt, *bool, error) {
	ctx := context.Background()
	flag := func(b bool) *bool { return &b }
	switch st.RPC {
	case "Propose":
		msg := &gatewayv1.ProposeRequest{}
		if err := r.request(st, msg); err != nil {
			return nil, nil, fmt.Errorf("request: %w", err)
		}
		resp, err := r.client.Propose(ctx, withHeader(msg, header))
		if err != nil {
			return nil, nil, err
		}
		return resp.Msg.GetAttempt(), flag(resp.Msg.GetExisting()), nil
	case "Approve":
		msg := &gatewayv1.ApproveRequest{}
		if err := r.request(st, msg); err != nil {
			return nil, nil, fmt.Errorf("request: %w", err)
		}
		if st.StepUpToken != "" {
			proof, err := r.token(st.StepUpToken)
			if err != nil {
				return nil, nil, fmt.Errorf("step-up token: %w", err)
			}
			msg.StepUpProof = proof
		}
		resp, err := r.client.Approve(ctx, withHeader(msg, header))
		if err != nil {
			return nil, nil, err
		}
		return resp.Msg.GetAttempt(), flag(resp.Msg.GetExisting()), nil
	case "Reject":
		msg := &gatewayv1.RejectRequest{}
		if err := r.request(st, msg); err != nil {
			return nil, nil, fmt.Errorf("request: %w", err)
		}
		resp, err := r.client.Reject(ctx, withHeader(msg, header))
		if err != nil {
			return nil, nil, err
		}
		return resp.Msg.GetAttempt(), flag(resp.Msg.GetExisting()), nil
	case "Cancel":
		msg := &gatewayv1.CancelRequest{}
		if err := r.request(st, msg); err != nil {
			return nil, nil, fmt.Errorf("request: %w", err)
		}
		resp, err := r.client.Cancel(ctx, withHeader(msg, header))
		if err != nil {
			return nil, nil, err
		}
		return resp.Msg.GetAttempt(), flag(resp.Msg.GetExisting()), nil
	case "Dispatch":
		msg := &gatewayv1.DispatchRequest{}
		if err := r.request(st, msg); err != nil {
			return nil, nil, fmt.Errorf("request: %w", err)
		}
		resp, err := r.client.Dispatch(ctx, withHeader(msg, header))
		if err != nil {
			return nil, nil, err
		}
		return resp.Msg.GetAttempt(), flag(resp.Msg.GetExisting()), nil
	case "Observe":
		msg := &gatewayv1.ObserveRequest{}
		if err := r.request(st, msg); err != nil {
			return nil, nil, fmt.Errorf("request: %w", err)
		}
		resp, err := r.client.Observe(ctx, withHeader(msg, header))
		if err != nil {
			return nil, nil, err
		}
		return resp.Msg.GetAttempt(), flag(resp.Msg.GetExisting()), nil
	case "GetAttempt":
		msg := &gatewayv1.GetAttemptRequest{}
		if err := r.request(st, msg); err != nil {
			return nil, nil, fmt.Errorf("request: %w", err)
		}
		resp, err := r.client.GetAttempt(ctx, withHeader(msg, header))
		if err != nil {
			return nil, nil, err
		}
		return resp.Msg.GetAttempt(), nil, nil
	case "GetAttemptContent":
		msg := &gatewayv1.GetAttemptContentRequest{}
		if err := r.request(st, msg); err != nil {
			return nil, nil, fmt.Errorf("request: %w", err)
		}
		_, err := r.client.GetAttemptContent(ctx, withHeader(msg, header))
		return nil, nil, err
	}
	return nil, nil, fmt.Errorf("unknown rpc %q", st.RPC)
}

func withHeader[T any](msg *T, header http.Header) *connect.Request[T] {
	req := connect.NewRequest(msg)
	for k, v := range header {
		req.Header()[k] = v
	}
	return req
}

// compare checks one step's result against its expectation.
func (r *run) compare(st step, a *gatewayv1.EffectAttempt, existing *bool, err error) error {
	want := st.Expect
	var ce *connect.Error
	if err != nil && !errors.As(err, &ce) {
		return err // the runner's own failure, not the gateway's answer
	}
	if want.Error != nil {
		if ce == nil {
			return fmt.Errorf("got %s, want %s %q", describe(a), want.Error.Code, want.Error.ReasonCode)
		}
		reason := ""
		for _, d := range ce.Details() {
			if v, derr := d.Value(); derr == nil {
				if detail, ok := v.(*errorsv1.ErrorDetail); ok {
					reason = detail.GetReasonCode()
				}
			}
		}
		if ce.Code().String() != want.Error.Code || reason != want.Error.ReasonCode {
			return fmt.Errorf("got %s %q (%s), want %s %q", ce.Code(), reason, ce.Message(), want.Error.Code, want.Error.ReasonCode)
		}
	} else if ce != nil {
		return fmt.Errorf("got %s (%s), want a response", ce.Code(), ce.Message())
	}
	if want.Existing != nil && (existing == nil || *existing != *want.Existing) {
		return fmt.Errorf("existing = %v, want %v", deref(existing), *want.Existing)
	}
	if want.Attempt != nil {
		if err := r.compareAttempt(*want.Attempt, a); err != nil {
			return err
		}
	}
	if c := want.AdapterCalls; c != nil {
		d, o := r.adapter.dispatched.Load(), r.adapter.observed.Load()
		if (c.Dispatch != nil && *c.Dispatch != d) || (c.Observe != nil && *c.Observe != o) {
			return fmt.Errorf("adapter calls: %d dispatch, %d observe; want %v dispatch, %v observe", d, o, deref(c.Dispatch), deref(c.Observe))
		}
	}
	return nil
}

func (r *run) compareAttempt(want expectedAttempt, a *gatewayv1.EffectAttempt) error {
	if a == nil {
		return errors.New("the response carries no attempt")
	}
	got := map[string]string{
		"state":                  strings.TrimPrefix(a.GetState().String(), "EFFECT_ATTEMPT_STATE_"),
		"reason_code":            a.GetReasonCode(),
		"outcome":                strings.TrimPrefix(a.GetOutcome().String(), "EFFECT_OUTCOME_"),
		"outcome_basis":          strings.TrimPrefix(a.GetOutcomeBasis().String(), "OUTCOME_BASIS_"),
		"risk_class":             strings.TrimPrefix(a.GetRiskClass().String(), "RISK_CLASS_"),
		"requester_principal_id": a.GetRequesterPrincipalId(),
		"requester_actor_id":     a.GetRequesterActorId(),
		"approver_principal_id":  a.GetApproval().GetApproverPrincipalId(),
		"pending_approval":       fmt.Sprint(a.GetPendingApproval() != nil),
		"permit":                 permitState(a.GetPermit()),
		"exposure":               exposureState(a.GetExposures()),
	}
	checks := []struct {
		field string
		want  *string
	}{
		{"state", want.State}, {"reason_code", want.ReasonCode}, {"outcome", want.Outcome}, {"outcome_basis", want.OutcomeBasis},
		{"risk_class", want.RiskClass}, {"requester_principal_id", want.RequesterPrincipalID},
		{"requester_actor_id", want.RequesterActorID}, {"approver_principal_id", want.ApproverPrincipalID},
		{"permit", want.Permit}, {"exposure", want.Exposure},
	}
	if want.PendingApproval != nil {
		s := fmt.Sprint(*want.PendingApproval)
		checks = append(checks, struct {
			field string
			want  *string
		}{"pending_approval", &s})
	}
	var diffs []string
	for _, c := range checks {
		if c.want != nil && got[c.field] != *c.want {
			diffs = append(diffs, fmt.Sprintf("%s = %q, want %s", c.field, got[c.field], orEmpty(*c.want)))
		}
	}
	if s := want.SameAttemptAs; s != nil {
		if other := r.labels[*s]; other == nil || other.GetAttemptId() != a.GetAttemptId() {
			diffs = append(diffs, fmt.Sprintf("attempt_id = %s, want the attempt of %q", a.GetAttemptId(), *s))
		}
	}
	if len(diffs) > 0 {
		return fmt.Errorf("attempt %s: %s", describe(a), strings.Join(diffs, "; "))
	}
	return nil
}

func orEmpty(s string) string {
	if s == "" {
		return `""`
	}
	return s
}

func describe(a *gatewayv1.EffectAttempt) string {
	if a == nil {
		return "no attempt"
	}
	return fmt.Sprintf("%s(%s) %q", strings.TrimPrefix(a.GetState().String(), "EFFECT_ATTEMPT_STATE_"),
		strings.TrimPrefix(a.GetOutcome().String(), "EFFECT_OUTCOME_"), a.GetReasonCode())
}

func deref[T any](p *T) any {
	if p == nil {
		return "unset"
	}
	return *p
}

func permitState(p *gatewayv1.Permit) string {
	switch {
	case p == nil:
		return "NONE"
	case p.GetConsumedAt() != nil:
		return "CONSUMED"
	case p.GetVoidReasonCode() != "":
		return "VOIDED"
	}
	return "ISSUED"
}

func exposureState(exposures []*gatewayv1.Exposure) string {
	if len(exposures) == 0 {
		return "NONE"
	}
	kind := strings.TrimPrefix(exposures[0].GetKind().String(), "EXPOSURE_KIND_")
	for _, e := range exposures[1:] {
		if k := strings.TrimPrefix(e.GetKind().String(), "EXPOSURE_KIND_"); k != kind {
			return "MIXED(" + kind + "," + k + ")"
		}
	}
	return kind
}

func (r *run) control(c control) error {
	ctx := context.Background()
	switch c.Kind {
	case "stop":
		_, err := r.rows.Stop(ctx, c.Tenant, authorityrows.StopSpec{
			Scope:  authorityrows.Scope{Kind: authorityrows.ScopeKind(c.ScopeKind), Key: c.ScopeKey},
			Reason: "conformance", IssuedBy: c.IssuedBy,
		})
		return err
	case "pass_dispatch_fence":
		id, err := r.substitute([]byte(c.AttemptID))
		if err != nil {
			return err
		}
		return inTenant(ctx, r.db, c.Tenant, func(tx *sql.Tx) error {
			res, err := tx.ExecContext(ctx, `UPDATE authority_effect_attempts SET dispatch_deadline = now() - interval '1 second'
				WHERE attempt_id = $1 AND dispatch_deadline IS NOT NULL`, string(id))
			if err != nil {
				return err
			}
			if n, _ := res.RowsAffected(); n != 1 {
				return fmt.Errorf("attempt %s has no dispatch fence", id)
			}
			return nil
		})
	case "set_adapter":
		r.adapter.set(c.Dispatch, c.Observe)
		return nil
	}
	return fmt.Errorf("unknown control %q", c.Kind)
}

func inTenant(ctx context.Context, db *sql.DB, tenant string, fn func(*sql.Tx) error) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `SELECT set_config('app.current_tenant', $1, true)`, tenant); err != nil {
		return err
	}
	if err := fn(tx); err != nil {
		return err
	}
	return tx.Commit()
}

// scripted is the fake provider adapter: its answers are the scenario's
// adapter behaviour. Like a real adapter it checks the permit's argument
// digest and asks the custody for a credential on every call.
type scripted struct {
	effectTypes []string
	provider    struct{ defaultBranch, defaultBranchSHA, branchCommitSHA string }

	mu         sync.Mutex
	dispatch   dispatchBehaviour
	observe    observeBehaviour
	dispatched atomic.Int32
	observed   atomic.Int32
}

func (s *scripted) set(d *dispatchBehaviour, o *observeBehaviour) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if d != nil {
		s.dispatch = *d
	}
	if o != nil {
		s.observe = *o
	}
}

func (s *scripted) Declarations() []adapters.Declaration {
	out := make([]adapters.Declaration, 0, len(s.effectTypes))
	for _, t := range s.effectTypes {
		out = append(out, adapters.Declaration{EffectType: t, Idempotent: adapters.IdempotentConditional, Observable: adapters.ObservableYes})
	}
	return out
}

func (s *scripted) Prepare(context.Context, adapters.TokenSource, adapters.Effect) (*adapters.Preparation, error) {
	return nil, adapters.Refuse(contracts.ReasonSchemaViolation, "not used by the gateway")
}

func (s *scripted) Dispatch(ctx context.Context, creds adapters.TokenSource, effect adapters.Effect, digest []byte) adapters.DispatchResult {
	s.dispatched.Add(1)
	if refusal := adapters.CheckPermitDigest(effect.Arguments, digest); refusal != nil {
		return adapters.DispatchResult{Status: adapters.DispatchNotSent, Reason: refusal.Reason, Detail: refusal.Detail}
	}
	if _, err := creds.Token(ctx); err != nil {
		return adapters.DispatchResult{Status: adapters.DispatchNotSent, Reason: contracts.ReasonProviderCredentialRejected, Detail: err.Error()}
	}
	s.mu.Lock()
	b := s.dispatch
	s.mu.Unlock()
	return adapters.DispatchResult{Status: adapters.DispatchStatus(b.Status), Reason: contracts.ReasonCode(b.ReasonCode), Detail: "scripted"}
}

func (s *scripted) Observe(ctx context.Context, creds adapters.TokenSource, effect adapters.Effect) adapters.ObserveResult {
	s.observed.Add(1)
	if _, err := creds.Token(ctx); err != nil {
		return adapters.ObserveResult{Outcome: adapters.OutcomeUnknown, Reason: contracts.ReasonProviderCredentialRejected}
	}
	s.mu.Lock()
	b := s.observe
	s.mu.Unlock()
	if b.Status == "INCONCLUSIVE" {
		return adapters.ObserveResult{Outcome: adapters.OutcomeUnknown, Reason: contracts.ReasonProviderError}
	}
	result := adapters.ObserveResult{Outcome: adapters.OutcomeSucceeded, Observation: s.readBack(effect)}
	switch b.Status {
	case "ABSENT":
		result.Outcome, result.Reason, result.Absent = adapters.OutcomeFailed, contracts.ReasonReadbackMismatch, true
	case "CONTRADICTING":
		result.Outcome, result.Reason = adapters.OutcomeFailed, contracts.ReasonReadbackMismatch
	}
	return result
}

// readBack is the typed result the effect type defines, from the scenario's
// provider facts and the effect's own arguments.
func (s *scripted) readBack(effect adapters.Effect) *adapters.Observation {
	var args struct {
		Head, Base, BaseSHA, HeadSHA string
	}
	var raw map[string]any
	_ = json.Unmarshal(effect.Arguments, &raw)
	str := func(k string) string { v, _ := raw[k].(string); return v }
	args.Head, args.Base, args.BaseSHA, args.HeadSHA = str("head"), str("base"), str("base_sha"), str("head_sha")
	evidence := sha256.Sum256(effect.Arguments)
	o := &adapters.Observation{Source: "conformance.readback", TrustClass: "provider_readback", EvidenceDigest: evidence[:], ObservedAt: time.Now()}
	switch effect.EffectType {
	case effectargs.GitHubRepositoryGet:
		o.GitHubRepository = &adapters.GitHubRepositoryResult{DefaultBranch: s.provider.defaultBranch, DefaultBranchSHA: s.provider.defaultBranchSHA}
	case effectargs.GitHubBranchCreateFromChanges:
		o.GitHubBranch = &adapters.GitHubBranchResult{Ref: "refs/heads/" + args.Head, CommitSHA: s.provider.branchCommitSHA, BaseSHA: args.BaseSHA, FilesDigest: evidence[:]}
	case effectargs.GitHubPullRequestCreateDraft:
		o.GitHubPullRequest = &adapters.GitHubPullRequestResult{URL: "https://github.com/Mindburn-Labs/example/pull/1", Number: 1,
			HeadRef: args.Head, HeadSHA: args.HeadSHA, BaseRef: args.Base, Draft: true, State: "open"}
	}
	return o
}

// githubApp is the real connection custody against a fake GitHub App token
// endpoint, with an installation for every tenant of the scenario.
func githubApp(t *testing.T, tenants []string) (*custody.GitHubApp, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	var n atomic.Int32
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") || !strings.HasSuffix(r.URL.Path, "/access_tokens") {
			http.Error(w, "{}", http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{"token": fmt.Sprintf("ghs_conformance_%d", n.Add(1)), "expires_at": time.Now().Add(time.Hour).UTC()})
	}))
	t.Cleanup(api.Close)
	type installation struct {
		TenantID       string   `json:"tenant_id"`
		Owner          string   `json:"owner"`
		InstallationID int64    `json:"installation_id"`
		Repositories   []string `json:"repositories"`
	}
	var installations []installation
	for i, tenant := range tenants {
		installations = append(installations, installation{TenantID: tenant, Owner: "Mindburn-Labs", InstallationID: int64(i + 1),
			Repositories: []string{"Mindburn-Labs/example", "Mindburn-Labs/other"}})
	}
	file, err := json.Marshal(map[string]any{"installations": installations})
	if err != nil {
		return nil, err
	}
	return custody.NewGitHubApp("1234", pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}), file, api.URL)
}
