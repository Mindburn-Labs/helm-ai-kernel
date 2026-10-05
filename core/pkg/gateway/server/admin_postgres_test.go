package server

// The authority administration API on the wire, against real PostgreSQL 16
// (listed in scripts/ci/postgres-proofs.txt), through a restricted role that
// row security applies to: a JWKS issuer signs ADR-0005 tokens, a Connect client
// calls the handler, and every refusal carries its ErrorDetail.
//
// quantum_posture: signs classical RS256 test tokens and computes SHA-256
// digests; no post-quantum claim.

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	_ "github.com/lib/pq"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/adapters"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/adapters/github"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/adapters/provision"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/admission"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/effectargs"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/kernel/authority/authorityrows"
	gatewayv1 "github.com/Mindburn-Labs/helm-ai-kernel/sdk/go/gen/helm/gateway/v1"
)

const (
	adminRegistrar = "svc:helm-control-plane"
	adminProvision = "svc:helm-org"
	adminOwner     = "usr_owner"
	adminOrg       = "org:admin-wire"
	adminTeam      = "team:admin-wire"
)

type adminWire struct {
	t      *testing.T
	client gatewayv1.AuthorityAdminServiceClient
	// effects is the effect API of the same gateway, which dispatches the
	// authority plans through the adapter.
	effects gatewayv1.EffectGatewayServiceClient
	iss     *issuer
	rows    *authorityrows.Store
	adapter *provision.Adapter
}

// newAdminWire migrates a fresh schema, serves the admin API over it through a
// role that is neither a superuser nor exempt from row security, and returns
// a client.
func newAdminWire(t *testing.T) *adminWire {
	t.Helper()
	base := os.Getenv("HELM_TEST_POSTGRES_URL")
	if base == "" {
		t.Skip("set HELM_TEST_POSTGRES_URL to run the authority administration wire proofs")
	}
	ctx := context.Background()
	schema := fmt.Sprintf("helm_gateway_admin_%d", time.Now().UnixNano())
	role := schema + "_role"
	admin, err := sql.Open("postgres", base)
	must(t, err)
	t.Cleanup(func() { _ = admin.Close() })
	_, err = admin.Exec(`CREATE SCHEMA ` + schema)
	must(t, err)
	parsed, err := url.Parse(base)
	must(t, err)
	query := parsed.Query()
	query.Set("search_path", schema)
	parsed.RawQuery = query.Encode()
	owner, err := sql.Open("postgres", parsed.String())
	must(t, err)
	t.Cleanup(func() { _ = owner.Close() })
	must(t, admission.Migrate(ctx, owner))
	for _, stmt := range []string{
		`CREATE ROLE ` + role + ` NOLOGIN NOSUPERUSER NOBYPASSRLS`,
		`GRANT USAGE ON SCHEMA ` + schema + ` TO ` + role,
		`GRANT SELECT, INSERT, UPDATE ON ALL TABLES IN SCHEMA ` + schema + ` TO ` + role,
		`REVOKE UPDATE ON authority_distinct_values, authority_token_replay FROM ` + role,
		// A decide token is used up in a transaction that also clears expired
		// replay rows: the grant the chart's 002_grants.sql gives helm_gateway.
		`GRANT DELETE ON authority_token_replay TO ` + role,
	} {
		_, err = owner.Exec(stmt)
		must(t, err)
	}
	t.Cleanup(func() {
		_, _ = admin.Exec(`DROP SCHEMA ` + schema + ` CASCADE`)
		_, _ = admin.Exec(`DROP ROLE ` + role)
	})
	query.Set("options", "-c role="+role)
	parsed.RawQuery = query.Encode()
	db, err := sql.Open("postgres", parsed.String())
	must(t, err)
	t.Cleanup(func() { _ = db.Close() })

	adapter, err := provision.New(db)
	must(t, err)
	catalog, err := BuildCatalog([]adapters.Adapter{github.New(), adapter})
	must(t, err)
	svc, err := admission.New(db, admission.Config{Adapters: []adapters.Adapter{adapter}})
	must(t, err)
	iss := newIssuer(t)
	auth := &Authenticator{Validator: iss.validator(), Actor: testActor}
	api := &AdminServer{Rows: adapter.Store(), Auth: auth, Catalog: catalog}
	effects := &Server{Admission: svc, Auth: auth}
	mux := http.NewServeMux()
	mux.Handle(api.Handler())
	mux.Handle(effects.Handler())
	srv := httptest.NewUnstartedServer(mux)
	srv.EnableHTTP2 = true
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return &adminWire{t: t, client: gatewayv1.NewAuthorityAdminServiceClient(srv.Client(), srv.URL, connect.WithGRPC()),
		effects: gatewayv1.NewEffectGatewayServiceClient(srv.Client(), srv.URL, connect.WithGRPC()),
		iss:     iss, rows: adapter.Store(), adapter: adapter}
}

func (w *adminWire) token(tenant, principal, scope string) string {
	return w.iss.token(w.t, testAudience, tenant, principal, scope)
}

func (w *adminWire) ensure(tenant string, specs ...*gatewayv1.PrincipalSpec) (*gatewayv1.EnsurePrincipalsResponse, error) {
	resp, err := w.client.EnsurePrincipals(context.Background(),
		withToken(&gatewayv1.EnsurePrincipalsRequest{Principals: specs}, w.token(tenant, adminRegistrar, ScopeProvision)))
	if err != nil {
		return nil, err
	}
	return resp.Msg, nil
}

func principal(id string, kind gatewayv1.PrincipalKind, system, subject string) *gatewayv1.PrincipalSpec {
	spec := &gatewayv1.PrincipalSpec{PrincipalId: id, Kind: kind}
	if system != "" {
		spec.ExternalSubject = &gatewayv1.ExternalSubject{System: system, Id: subject}
	}
	return spec
}

func serviceSpec(id string) *gatewayv1.PrincipalSpec {
	return principal(id, gatewayv1.PrincipalKind_PRINCIPAL_KIND_SERVICE, "", "")
}

func humanSpec(id, subject string) *gatewayv1.PrincipalSpec {
	return principal(id, gatewayv1.PrincipalKind_PRINCIPAL_KIND_HUMAN, "helm-control-plane", subject)
}

func (w *adminWire) stored(tenant, id string) (authorityrows.Principal, error) {
	var p authorityrows.Principal
	err := w.rows.InTenant(context.Background(), tenant, func(tx *authorityrows.Tx) error {
		var err error
		p, err = tx.Principal(context.Background(), id)
		return err
	})
	return p, err
}

func TestPostgresEnsurePrincipalsOnTheWire(t *testing.T) {
	w := newAdminWire(t)
	ctx := context.Background()

	// Known good: the first call makes the tenant and its principals exist,
	// in the request's order, each active with its kind and subject.
	first, err := w.ensure("tenant-a", serviceSpec(adminProvision), humanSpec(adminOwner, adminOwner),
		principal("agt:engineer", gatewayv1.PrincipalKind_PRINCIPAL_KIND_AGENT, "", ""))
	must(t, err)
	if !first.GetTenantCreated() || len(first.GetPrincipals()) != 3 {
		t.Fatalf("first call = %+v", first)
	}
	for i, want := range []struct {
		id      string
		kind    gatewayv1.PrincipalKind
		subject string
	}{
		{adminProvision, gatewayv1.PrincipalKind_PRINCIPAL_KIND_SERVICE, ""},
		{adminOwner, gatewayv1.PrincipalKind_PRINCIPAL_KIND_HUMAN, adminOwner},
		{"agt:engineer", gatewayv1.PrincipalKind_PRINCIPAL_KIND_AGENT, ""},
	} {
		got := first.GetPrincipals()[i]
		if got.GetPrincipalId() != want.id || got.GetKind() != want.kind ||
			got.GetStatus() != gatewayv1.PrincipalStatus_PRINCIPAL_STATUS_ACTIVE || got.GetExternalSubject().GetId() != want.subject {
			t.Errorf("principal %d = %+v, want %s %v %q", i, got, want.id, want.kind, want.subject)
		}
	}
	// Idempotent by its nature: the same request answers the same principals.
	again, err := w.ensure("tenant-a", serviceSpec(adminProvision), humanSpec(adminOwner, adminOwner),
		principal("agt:engineer", gatewayv1.PrincipalKind_PRINCIPAL_KIND_AGENT, "", ""))
	must(t, err)
	if again.GetTenantCreated() || len(again.GetPrincipals()) != 3 || again.GetPrincipals()[1].GetVersion() != first.GetPrincipals()[1].GetVersion() {
		t.Fatalf("second call = %+v", again)
	}
	// A subject may be attached, once, to a principal that has none.
	attached, err := w.ensure("tenant-a", principal(adminProvision, gatewayv1.PrincipalKind_PRINCIPAL_KIND_SERVICE, "helm-control-plane", "svc-1"))
	must(t, err)
	if attached.GetPrincipals()[0].GetExternalSubject().GetId() != "svc-1" {
		t.Fatalf("attach = %+v", attached)
	}

	// Known bad: each refusal is a Connect error with its ErrorDetail, and the
	// whole request is refused: nothing it lists is created.
	_, err = w.ensure("tenant-a", serviceSpec("svc:new"), principal(adminOwner, gatewayv1.PrincipalKind_PRINCIPAL_KIND_AGENT, "", ""))
	wantRPCError(t, "a principal presented as another kind", err, connect.CodeAlreadyExists, contracts.ReasonIdentityIsolationViolation)
	if _, err := w.stored("tenant-a", "svc:new"); !errors.Is(err, authorityrows.ErrNotFound) {
		t.Errorf("a refused request still created svc:new: %v", err)
	}
	_, err = w.ensure("tenant-a", humanSpec("usr_second", adminOwner))
	wantRPCError(t, "a second principal with a subject that names another", err, connect.CodeAlreadyExists, contracts.ReasonIdentityIsolationViolation)
	_, err = w.ensure("tenant-a", humanSpec(adminOwner, "another-subject"))
	wantRPCError(t, "a principal presented with another subject", err, connect.CodeAlreadyExists, contracts.ReasonIdentityIsolationViolation)
	_, err = w.ensure("tenant-a", principal(adminProvision, gatewayv1.PrincipalKind_PRINCIPAL_KIND_SERVICE, "helm-control-plane", "svc-2"))
	wantRPCError(t, "a subject attached twice", err, connect.CodeAlreadyExists, contracts.ReasonIdentityIsolationViolation)
	_, err = w.ensure("tenant-a", principal("usr_nosubject", gatewayv1.PrincipalKind_PRINCIPAL_KIND_HUMAN, "", ""))
	wantRPCError(t, "a human without a subject", err, connect.CodeInvalidArgument, contracts.ReasonSchemaViolation)
	_, err = w.ensure("tenant-a", principal("usr_badsystem", gatewayv1.PrincipalKind_PRINCIPAL_KIND_HUMAN, "Not A System", "x"))
	wantRPCError(t, "a subject whose system is not a system name", err, connect.CodeInvalidArgument, contracts.ReasonSchemaViolation)

	// A disabled principal is never re-enabled, nor re-registered.
	must(t, w.rows.InTenant(ctx, "tenant-a", func(tx *authorityrows.Tx) error {
		_, err := tx.DisablePrincipal(ctx, "agt:engineer")
		return err
	}))
	_, err = w.ensure("tenant-a", principal("agt:engineer", gatewayv1.PrincipalKind_PRINCIPAL_KIND_AGENT, "", ""))
	wantRPCError(t, "a disabled principal", err, connect.CodeFailedPrecondition, contracts.ReasonPrincipalInactive)
	if p, err := w.stored("tenant-a", "agt:engineer"); err != nil || p.Active {
		t.Errorf("the disabled principal = %+v, %v", p, err)
	}

	// A caller the tenant registers as a person does not register principals,
	// whatever its token says.
	_, err = w.client.EnsurePrincipals(ctx, withToken(&gatewayv1.EnsurePrincipalsRequest{Principals: []*gatewayv1.PrincipalSpec{serviceSpec("svc:by-a-person")}},
		w.token("tenant-a", adminOwner, ScopeProvision)))
	wantRPCError(t, "a human registrar", err, connect.CodePermissionDenied, contracts.ReasonInsufficientPrivilege)
	if _, err := w.stored("tenant-a", "svc:by-a-person"); !errors.Is(err, authorityrows.ErrNotFound) {
		t.Errorf("a human registrar created a principal: %v", err)
	}

	// Scopes: only helm.gateway.provision registers.
	for _, scope := range []string{ScopeRead, ScopePropose, ScopeDecide, ScopeStop, ScopeExecute} {
		_, err = w.client.EnsurePrincipals(ctx, withToken(&gatewayv1.EnsurePrincipalsRequest{Principals: []*gatewayv1.PrincipalSpec{serviceSpec("svc:x")}},
			w.token("tenant-a", adminRegistrar, scope)))
		wantRPCError(t, scope+" token", err, connect.CodePermissionDenied, contracts.ReasonInsufficientPrivilege)
	}
	_, err = w.client.EnsurePrincipals(ctx, withToken(&gatewayv1.EnsurePrincipalsRequest{Principals: []*gatewayv1.PrincipalSpec{serviceSpec("svc:x")}}, ""))
	wantRPCError(t, "no token", err, connect.CodeUnauthenticated, "")

	// The tenant comes from the token alone: tenant b has its own rows, where
	// the same ids are new and the subject the first tenant holds is free.
	other, err := w.ensure("tenant-b", serviceSpec(adminProvision), humanSpec(adminOwner, adminOwner))
	must(t, err)
	if !other.GetTenantCreated() || other.GetPrincipals()[1].GetExternalSubject().GetId() != adminOwner {
		t.Fatalf("tenant b = %+v", other)
	}
	if _, err := w.stored("tenant-b", "agt:engineer"); !errors.Is(err, authorityrows.ErrNotFound) {
		t.Errorf("tenant b sees tenant a's principal: %v", err)
	}
}

// plan builds a provision plan for adminOrg with a team below it.
func adminPlan(t *testing.T, base, version string, now time.Time) []byte {
	t.Helper()
	doc := map[string]any{
		"schema": effectargs.AuthorityProvision, "org_ref": adminOrg, "version_ref": version, "stage": "constrained-live", "base_plan_digest": base,
		"valid_from": now.Add(-time.Minute).UTC().Format(time.RFC3339), "valid_until": now.Add(24 * time.Hour).UTC().Format(time.RFC3339),
		"effect_types": []any{map[string]any{"effect_type": "github.repository.get", "risk_class": "low"}},
		"principals":   []any{map[string]any{"id": adminOrg, "kind": "service"}, map[string]any{"id": adminTeam, "kind": "service"}},
		"mandates": []any{
			map[string]any{"node": adminOrg, "holder": adminOrg, "parent": nil,
				"terms": map[string]any{"effect_types": []string{"github.repository.get"}, "targets": nil}},
			map[string]any{"node": adminTeam, "holder": adminTeam, "parent": adminOrg,
				"terms": map[string]any{"effect_types": []string{"github.repository.get"}, "targets": []string{testRepo}}},
		},
	}
	raw, err := json.Marshal(doc)
	must(t, err)
	if _, err := provision.Check(effectargs.AuthorityProvision, raw); err != nil {
		t.Fatal(err)
	}
	return raw
}

// apply records the attempt and the approval the gateway commits before it
// invokes an adapter, then dispatches the plan through the adapter. It stands
// in for Propose, Approve and Dispatch, which their own proofs cover.
func (w *adminWire) apply(tenant string, raw []byte) string {
	w.t.Helper()
	ctx := context.Background()
	attemptID := uuid.NewString()
	digest := sha256.Sum256(raw)
	must(w.t, w.rows.InTenant(ctx, tenant, func(tx *authorityrows.Tx) error {
		if _, err := tx.SQL().ExecContext(ctx, `INSERT INTO authority_effect_attempts
			(tenant_id, attempt_id, workspace_id, idempotency_key, request_digest, requester_principal_id,
			 effect_type, target, target_digest, argument_digest, state)
			VALUES ($1, $2::uuid, 'ws-a', $2::text, $3, $4, $5, $6, $3, $3, 'DISPATCHING')`,
			tenant, attemptID, digest[:], adminProvision, effectargs.AuthorityProvision, adminOrg); err != nil {
			return err
		}
		_, err := tx.SQL().ExecContext(ctx, `INSERT INTO authority_approvals
			(tenant_id, attempt_id, approver_principal_id, decision, approval_digest)
			VALUES ($1, $2, $3, 'APPROVED', $4)`, tenant, attemptID, adminOwner, digest[:])
		return err
	}))
	result := w.adapter.Dispatch(ctx, nil, adapters.Effect{EffectType: effectargs.AuthorityProvision, Target: adminOrg, Arguments: raw,
		Invocation: &adapters.Invocation{TenantID: tenant, AttemptID: attemptID, RequesterPrincipalID: adminProvision}}, digest[:])
	if result.Status != adapters.DispatchSent {
		w.t.Fatalf("dispatch = %+v", result)
	}
	return attemptID
}

func TestPostgresGetProvisioningOnTheWire(t *testing.T) {
	w := newAdminWire(t)
	ctx := context.Background()
	for _, tenant := range []string{"tenant-a", "tenant-b"} {
		_, err := w.ensure(tenant, serviceSpec(adminProvision), humanSpec(adminOwner, adminOwner))
		must(t, err)
	}
	read := w.token("tenant-a", "svc:reader", ScopeRead)
	get := func(token, orgRef string) (*gatewayv1.Provisioning, error) {
		resp, err := w.client.GetProvisioning(ctx, withToken(&gatewayv1.GetProvisioningRequest{OrgRef: orgRef}, token))
		if err != nil {
			return nil, err
		}
		return resp.Msg.GetProvisioning(), nil
	}

	// Known bad before any plan: nothing is provisioned, and a malformed
	// organization is refused before any read.
	_, err := get(read, adminOrg)
	wantRPCError(t, "an organization never provisioned", err, connect.CodeNotFound, "")
	for _, bad := range []string{"", "org:", "team:admin-wire", "org:has space", "ORG:admin-wire"} {
		_, err = get(read, bad)
		wantRPCError(t, fmt.Sprintf("org_ref %q", bad), err, connect.CodeInvalidArgument, contracts.ReasonSchemaViolation)
	}

	// Known good: the applied plan, with each node's mandate, in the plan's order.
	now := time.Now()
	raw := adminPlan(t, "", "v1", now)
	attemptID := w.apply("tenant-a", raw)
	plan, err := effectargs.ParsePlan(effectargs.AuthorityProvision, raw)
	must(t, err)
	got, err := get(read, adminOrg)
	must(t, err)
	if got.GetOrgRef() != adminOrg || got.GetPlanDigest() != plan.Digest || got.GetVersionRef() != "v1" || got.GetStage() != "constrained-live" ||
		got.GetAttemptId() != attemptID || got.GetRevision() != 1 || got.GetProvisioner() != adminProvision ||
		got.GetAppliedAt().AsTime().IsZero() || len(got.GetNodes()) != 2 {
		t.Fatalf("GetProvisioning = %+v", got)
	}
	org, team := got.GetNodes()[0], got.GetNodes()[1]
	if org.GetNode() != adminOrg || org.GetHolderId() != adminOrg || org.GetParentNode() != "" || !org.GetActive() || org.GetMandateVersion() < 1 ||
		team.GetNode() != adminTeam || team.GetHolderId() != adminTeam || team.GetParentNode() != adminOrg || !team.GetActive() {
		t.Fatalf("nodes = %+v", got.GetNodes())
	}
	for _, n := range got.GetNodes() {
		if _, err := uuid.Parse(n.GetMandateId()); err != nil {
			t.Errorf("node %s has mandate id %q", n.GetNode(), n.GetMandateId())
		}
	}

	// A mandate revoked since the plan applied is not active now.
	teamID, err := uuid.Parse(team.GetMandateId())
	must(t, err)
	must(t, w.rows.Revoke(ctx, "tenant-a", teamID))
	revoked, err := get(read, adminOrg)
	must(t, err)
	if !revoked.GetNodes()[0].GetActive() || revoked.GetNodes()[1].GetActive() || revoked.GetPlanDigest() != plan.Digest {
		t.Fatalf("after a revocation = %+v", revoked.GetNodes())
	}

	// The tenant comes from the token: tenant b has no provisioning for it.
	_, err = get(w.token("tenant-b", "svc:reader", ScopeRead), adminOrg)
	wantRPCError(t, "another tenant", err, connect.CodeNotFound, "")

	// Scopes.
	for _, scope := range []string{ScopePropose, ScopeDecide, ScopeStop, ScopeExecute, ScopeProvision} {
		_, err = get(w.token("tenant-a", "svc:reader", scope), adminOrg)
		wantRPCError(t, scope+" token", err, connect.CodePermissionDenied, contracts.ReasonInsufficientPrivilege)
	}
	_, err = get("", adminOrg)
	wantRPCError(t, "no token", err, connect.CodeUnauthenticated, "")
}

func TestPostgresProvisionBudgetOnTheWire(t *testing.T) {
	w := newAdminWire(t)
	ctx := context.Background()
	_, err := w.ensure("tenant-a", serviceSpec(adminProvision), humanSpec(adminOwner, adminOwner))
	must(t, err)
	var plan map[string]any
	must(t, json.Unmarshal(adminPlan(t, "", "budget-v1", time.Now()), &plan))
	plan["limits"] = []any{map[string]any{"node": adminOrg, "unit": "usd_micros", "measure": "sum", "window": "none", "span": 1, "value": 5000000}}
	raw, err := json.Marshal(plan)
	must(t, err)
	w.apply("tenant-a", raw)
	read := w.token("tenant-a", adminProvision, ScopeRead)
	p, err := w.client.GetProvisioning(ctx, withToken(&gatewayv1.GetProvisioningRequest{OrgRef: adminOrg}, read))
	must(t, err)
	applied := p.Msg.GetProvisioning()
	node := applied.GetNodes()[0]
	if len(node.GetLimits()) != 1 {
		t.Fatalf("wire readback cannot construct a budget binding: %+v", node)
	}
	l := node.GetLimits()[0]
	if l.GetUnit() != "usd_micros" || l.GetMeasure() != "sum" || l.GetWindow() != "none" || l.GetSpan() != 1 || l.GetValue() != 5000000 || l.GetVersion() < 1 {
		t.Fatalf("wire limit metadata: %+v", l)
	}
	binding := &gatewayv1.ProvisionBudgetBinding{
		OrgRef: applied.GetOrgRef(), VersionRef: applied.GetVersionRef(), PlanDigest: applied.GetPlanDigest(), Revision: applied.GetRevision(),
		Node: node.GetNode(), MandateId: node.GetMandateId(), LimitId: l.GetLimitId(), LimitVersion: l.GetVersion(),
	}
	req := &gatewayv1.GetProvisionBudgetRequest{Binding: binding}
	resp, err := w.client.GetProvisionBudget(ctx, withToken(req, read))
	must(t, err)
	x := resp.Msg
	if !x.GetCoverageComplete() || x.GetAmounts() == nil || x.GetAmounts().GetCap() != 5000000 ||
		x.GetActivity() != gatewayv1.ProvisionBudgetActivity_PROVISION_BUDGET_ACTIVITY_NO_RUNS_YET || len(x.GetEvidenceDigest()) != sha256.Size {
		t.Fatalf("wire budget: %+v", x)
	}
	for _, principal := range []string{adminOwner, "svc:not-registered"} {
		_, err = w.client.GetProvisionBudget(ctx, withToken(req, w.token("tenant-a", principal, ScopeRead)))
		wantRPCError(t, principal+" reader", err, connect.CodePermissionDenied, contracts.ReasonInsufficientPrivilege)
	}
	binding.LimitVersion++
	_, err = w.client.GetProvisionBudget(ctx, withToken(req, read))
	wantRPCError(t, "stale wire binding", err, connect.CodeFailedPrecondition, "")
}

func TestPostgresListEffectTypesOnTheWire(t *testing.T) {
	w := newAdminWire(t)
	ctx := context.Background()
	list := func(tenant string) []*gatewayv1.EffectTypeDeclaration {
		resp, err := w.client.ListEffectTypes(ctx, withToken(&gatewayv1.ListEffectTypesRequest{}, w.token(tenant, "svc:reader", ScopeRead)))
		must(t, err)
		return resp.Msg.GetEffectTypes()
	}
	got := list("tenant-a")
	var names []string
	byName := map[string]*gatewayv1.EffectTypeDeclaration{}
	for _, e := range got {
		names = append(names, e.GetEffectType())
		byName[e.GetEffectType()] = e
	}
	want := []string{"github.branch.create_from_changes", "github.pull_request.create_draft", "github.repository.get",
		effectargs.AuthorityNarrow, effectargs.AuthorityProvision}
	if fmt.Sprint(names) != fmt.Sprint(want) {
		t.Fatalf("catalog = %v, want %v", names, want)
	}
	for _, name := range want {
		schema, _ := effectargs.ArgumentSchema(name)
		e := byName[name]
		grantable := name != effectargs.AuthorityNarrow && name != effectargs.AuthorityProvision
		if string(e.GetArgumentSchema()) != string(schema) || e.GetGrantable() != grantable || e.GetTargetForm() == "" ||
			e.GetRiskClass() == gatewayv1.RiskClass_RISK_CLASS_UNSPECIFIED || e.GetMediation() != "enforced" {
			t.Errorf("%s entry = %+v", name, e)
		}
	}
	if byName[effectargs.AuthorityProvision].GetRiskClass() != gatewayv1.RiskClass_RISK_CLASS_IRREVERSIBLE {
		t.Errorf("provision risk = %v", byName[effectargs.AuthorityProvision].GetRiskClass())
	}
	// The same for every tenant.
	if other := list("tenant-b"); len(other) != len(got) {
		t.Fatalf("tenant b lists %d entries, tenant a %d", len(other), len(got))
	}
}
