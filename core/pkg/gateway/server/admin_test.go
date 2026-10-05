package server

// The authority administration API without a database: the catalog it serves,
// the scopes it takes and the requests it refuses before it writes anything.
//
// quantum_posture: signs classical RS256 test tokens; no post-quantum claim.

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"testing"

	"connectrpc.com/connect"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/adapters"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/adapters/github"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/effectargs"
	gatewayv1 "github.com/Mindburn-Labs/helm-ai-kernel/sdk/go/gen/helm/gateway/v1"
)

// declared is an adapter that only declares effect types.
type declared []adapters.Declaration

func (d declared) Declarations() []adapters.Declaration { return d }

func (declared) Prepare(context.Context, adapters.TokenSource, adapters.Effect) (*adapters.Preparation, error) {
	return nil, errors.New("not used")
}

func (declared) Dispatch(context.Context, adapters.TokenSource, adapters.Effect, []byte) adapters.DispatchResult {
	return adapters.DispatchResult{Status: adapters.DispatchNotSent}
}

func (declared) Observe(context.Context, adapters.TokenSource, adapters.Effect) adapters.ObserveResult {
	return adapters.ObserveResult{Outcome: adapters.OutcomeUnknown}
}

func TestBuildCatalogRendersTheDeclarationsByEffectType(t *testing.T) {
	plan := adapters.Declaration{
		EffectType: effectargs.AuthorityProvision, RiskClass: adapters.RiskIrreversible,
		Idempotent: adapters.IdempotentConditional, Observable: adapters.ObservableYes,
		Reversible: adapters.ReversibleNo, Mediation: adapters.MediationEnforced,
		TargetForm: "org:{org_id}", Description: "Applies a plan.", ArgumentSchema: []byte(`{"type":"object"}`),
	}
	catalog, err := BuildCatalog([]adapters.Adapter{declared{plan}, github.New()})
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	byName := map[string]*gatewayv1.EffectTypeDeclaration{}
	for _, entry := range catalog {
		names = append(names, entry.GetEffectType())
		byName[entry.GetEffectType()] = entry
	}
	want := []string{"github.branch.create_from_changes", "github.pull_request.create_draft", "github.repository.get", "helm.authority.provision.v1"}
	if fmt.Sprint(names) != fmt.Sprint(want) {
		t.Fatalf("catalog order = %v, want %v", names, want)
	}
	got := byName[effectargs.AuthorityProvision]
	if got.GetRiskClass() != gatewayv1.RiskClass_RISK_CLASS_IRREVERSIBLE || got.GetIdempotent() != "conditional" ||
		got.GetObservable() != "yes" || got.GetReversible() != "no" || got.GetMediation() != "enforced" ||
		got.GetTargetForm() != "org:{org_id}" || got.GetDescription() != "Applies a plan." ||
		string(got.GetArgumentSchema()) != `{"type":"object"}` || got.GetGrantable() {
		t.Fatalf("provision entry = %+v", got)
	}
	repo := byName["github.repository.get"]
	published, _ := effectargs.ArgumentSchema("github.repository.get")
	if repo.GetRiskClass() != gatewayv1.RiskClass_RISK_CLASS_LOW || !repo.GetGrantable() ||
		repo.GetTargetForm() != "github.com/{owner}/{repo}" || !bytes.Equal(repo.GetArgumentSchema(), published) {
		t.Fatalf("repository.get entry = %+v", repo)
	}
}

func TestBuildCatalogRefusesWhatWouldMisleadAClient(t *testing.T) {
	one := adapters.Declaration{EffectType: "ops.note"}
	if _, err := BuildCatalog([]adapters.Adapter{declared{one}, declared{one}}); err == nil {
		t.Error("an effect type declared twice was listed")
	}
	bad := adapters.Declaration{EffectType: "ops.note", ArgumentSchema: []byte(`{"type":`)}
	if _, err := BuildCatalog([]adapters.Adapter{declared{bad}}); err == nil {
		t.Error("an argument schema that is not JSON was listed")
	}
	catalog, err := BuildCatalog(nil)
	if err != nil || len(catalog) != 0 {
		t.Errorf("an empty gateway lists %d entries (%v)", len(catalog), err)
	}
}

func TestListEffectTypesTakesTheReadScopeAndNoOther(t *testing.T) {
	iss := newIssuer(t)
	catalog, err := BuildCatalog([]adapters.Adapter{github.New()})
	if err != nil {
		t.Fatal(err)
	}
	admin := &AdminServer{Auth: &Authenticator{Validator: iss.validator(), Actor: testActor}, Catalog: catalog}
	ctx := context.Background()

	resp, err := admin.ListEffectTypes(ctx, withToken(&gatewayv1.ListEffectTypesRequest{}, iss.token(t, testAudience, "tenant-a", "svc:reader", ScopeRead)))
	if err != nil || len(resp.Msg.GetEffectTypes()) != 3 {
		t.Fatalf("a read token: %d entries, %v", len(resp.Msg.GetEffectTypes()), err)
	}
	// The same for every tenant.
	other, err := admin.ListEffectTypes(ctx, withToken(&gatewayv1.ListEffectTypesRequest{}, iss.token(t, testAudience, "tenant-b", "svc:reader", ScopeRead)))
	if err != nil || len(other.Msg.GetEffectTypes()) != len(resp.Msg.GetEffectTypes()) {
		t.Fatalf("another tenant: %v", err)
	}
	_, err = admin.ListEffectTypes(ctx, withToken(&gatewayv1.ListEffectTypesRequest{}, ""))
	wantRPCError(t, "no token", err, connect.CodeUnauthenticated, "")
	for _, scope := range []string{ScopePropose, ScopeDecide, ScopeStop, ScopeExecute, ScopeProvision} {
		_, err = admin.ListEffectTypes(ctx, withToken(&gatewayv1.ListEffectTypesRequest{}, iss.token(t, testAudience, "tenant-a", "svc:reader", scope)))
		wantRPCError(t, scope+" token", err, connect.CodePermissionDenied, contracts.ReasonInsufficientPrivilege)
	}
}

func TestProvisionBudgetTakesReadScopeBeforeBinding(t *testing.T) {
	iss := newIssuer(t)
	admin := &AdminServer{Auth: &Authenticator{Validator: iss.validator(), Actor: testActor}}
	ctx := context.Background()
	_, err := admin.GetProvisionBudget(ctx, withToken(&gatewayv1.GetProvisionBudgetRequest{}, ""))
	wantRPCError(t, "no token", err, connect.CodeUnauthenticated, "")
	for _, scope := range []string{ScopePropose, ScopeDecide, ScopeStop, ScopeExecute, ScopeProvision} {
		_, err = admin.GetProvisionBudget(ctx, withToken(&gatewayv1.GetProvisionBudgetRequest{}, iss.token(t, testAudience, "tenant-a", "svc:reader", scope)))
		wantRPCError(t, scope+" budget token", err, connect.CodePermissionDenied, contracts.ReasonInsufficientPrivilege)
	}
	_, err = admin.GetProvisionBudget(ctx, withToken(&gatewayv1.GetProvisionBudgetRequest{}, iss.token(t, testAudience, "tenant-a", "svc:reader", ScopeRead)))
	wantRPCError(t, "missing binding", err, connect.CodeInvalidArgument, contracts.ReasonSchemaViolation)
}

// Only helm.gateway.provision registers principals, and no other RPC takes it.
func TestProvisionScopeIsOnlyForEnsurePrincipals(t *testing.T) {
	iss := newIssuer(t)
	admin := &AdminServer{Auth: &Authenticator{Validator: iss.validator(), Actor: testActor}}
	ctx := context.Background()
	provisioning := iss.token(t, testAudience, "tenant-a", "svc:helm-control-plane", ScopeProvision)
	_, err := admin.GetProvisioning(ctx, withToken(&gatewayv1.GetProvisioningRequest{OrgRef: "org:x"}, provisioning))
	wantRPCError(t, "a provision token on GetProvisioning", err, connect.CodePermissionDenied, contracts.ReasonInsufficientPrivilege)
	for _, scope := range []string{ScopeRead, ScopePropose, ScopeDecide, ScopeStop, ScopeExecute} {
		_, err := admin.EnsurePrincipals(ctx, withToken(&gatewayv1.EnsurePrincipalsRequest{}, iss.token(t, testAudience, "tenant-a", "svc:helm-control-plane", scope)))
		wantRPCError(t, scope+" token on EnsurePrincipals", err, connect.CodePermissionDenied, contracts.ReasonInsufficientPrivilege)
	}
	_, err = admin.EnsurePrincipals(ctx, withToken(&gatewayv1.EnsurePrincipalsRequest{}, ""))
	wantRPCError(t, "no token on EnsurePrincipals", err, connect.CodeUnauthenticated, "")
	other := iss.token(t, "helm-kernel:test", "tenant-a", "svc:helm-control-plane", ScopeProvision)
	_, err = admin.EnsurePrincipals(ctx, withToken(&gatewayv1.EnsurePrincipalsRequest{}, other))
	wantRPCError(t, "a kernel-audience token", err, connect.CodeUnauthenticated, "")
}

func TestPrincipalSpecsRefuseMalformedRequestsBeforeTheDatabase(t *testing.T) {
	human := func(id, subject string) *gatewayv1.PrincipalSpec {
		return &gatewayv1.PrincipalSpec{PrincipalId: id, Kind: gatewayv1.PrincipalKind_PRINCIPAL_KIND_HUMAN,
			ExternalSubject: &gatewayv1.ExternalSubject{System: "helm-control-plane", Id: subject}}
	}
	service := func(id string) *gatewayv1.PrincipalSpec {
		return &gatewayv1.PrincipalSpec{PrincipalId: id, Kind: gatewayv1.PrincipalKind_PRINCIPAL_KIND_SERVICE}
	}
	many := make([]*gatewayv1.PrincipalSpec, maxPrincipalsPerRequest+1)
	for i := range many {
		many[i] = service(fmt.Sprintf("svc:%d", i))
	}
	for name, in := range map[string][]*gatewayv1.PrincipalSpec{
		"none":                nil,
		"too many":            many,
		"a nil entry":         {nil},
		"an empty id":         {service("")},
		"edge whitespace":     {service(" svc:x")},
		"a control character": {service("svc:\x01")},
		"a duplicate":         {service("svc:x"), service("svc:x")},
		"no kind":             {{PrincipalId: "svc:x"}},
		"an unknown kind":     {{PrincipalId: "svc:x", Kind: gatewayv1.PrincipalKind(99)}},
	} {
		_, err := principalSpecs(in)
		wantRPCError(t, name, err, connect.CodeInvalidArgument, contracts.ReasonSchemaViolation)
	}
	specs, err := principalSpecs([]*gatewayv1.PrincipalSpec{service("svc:helm-org"), human("usr_owner", "usr_owner"),
		{PrincipalId: "agt:e", Kind: gatewayv1.PrincipalKind_PRINCIPAL_KIND_AGENT}})
	if err != nil || len(specs) != 3 || specs[1].External == nil || specs[1].External.ID != "usr_owner" ||
		specs[0].Kind != "service" || specs[2].Kind != "agent" || specs[0].External != nil {
		t.Fatalf("principalSpecs = %+v, %v", specs, err)
	}
	if _, err := principalSpecs(many[:maxPrincipalsPerRequest]); err != nil {
		t.Errorf("64 principals: %v", err)
	}
}

func TestAdminHandlerMountsTheService(t *testing.T) {
	path, handler := (&AdminServer{}).Handler()
	if path != gatewayv1.AuthorityAdminServiceName+"/" && path != "/"+gatewayv1.AuthorityAdminServiceName+"/" || handler == nil {
		t.Fatalf("Handler() = %q, %v", path, handler)
	}
}
