package server

// AuthorityAdminService on the wire (docs/architecture/gateway-provisioning-
// api.md): EnsurePrincipals registers a tenant's first principals,
// GetProvisioning reads what an authority plan applied, and ListEffectTypes
// serves the catalog of effect types the gateway performs. Authority itself is
// provisioned as effects through the effect API; this service does what an
// effect cannot do for itself.
//
// quantum_posture: the digests it returns are SHA-256 values read from rows;
// the service signs and verifies nothing, and no post-quantum claim is made.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sort"

	"connectrpc.com/connect"
	"github.com/lib/pq"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/adapters"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/adapters/provision"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/effectargs"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/kernel/authority/authorityrows"
	gatewayv1 "github.com/Mindburn-Labs/helm-ai-kernel/sdk/go/gen/helm/gateway/v1"
)

// MaxAdminMessageBytes caps one decoded request message of the admin service:
// 64 principals fit in a fraction of it.
const MaxAdminMessageBytes = 128 << 10

// maxPrincipalsPerRequest is the proto's bound on EnsurePrincipalsRequest.
const maxPrincipalsPerRequest = 64

// AdminServer implements AuthorityAdminServiceHandler.
type AdminServer struct {
	gatewayv1.UnimplementedAuthorityAdminServiceHandler

	// Rows is the authority rows store: the tenant's principals and the
	// provisioning its plans applied.
	Rows *authorityrows.Store
	Auth *Authenticator
	// Catalog is what ListEffectTypes returns, from BuildCatalog.
	Catalog []*gatewayv1.EffectTypeDeclaration
}

// Handler returns the mount path and the HTTP handler of the service, with the
// same pre-handler size bounds as the effect service.
func (s *AdminServer) Handler() (string, http.Handler) {
	path, handler := gatewayv1.NewAuthorityAdminServiceHandler(s, connect.WithReadMaxBytes(MaxAdminMessageBytes))
	return path, http.MaxBytesHandler(withTLSState(handler), MaxAdminMessageBytes+4<<10)
}

// errHumanRegistrar reports a registrar the tenant's own rows register as a
// person.
var errHumanRegistrar = errors.New("a principal the tenant registers as a human does not register principals")

// EnsurePrincipals makes the token's tenant and the listed principals exist in
// one transaction (token scope helm.gateway.provision). It changes nothing
// that exists, and is idempotent by its nature.
func (s *AdminServer) EnsurePrincipals(ctx context.Context, req *connect.Request[gatewayv1.EnsurePrincipalsRequest]) (*connect.Response[gatewayv1.EnsurePrincipalsResponse], error) {
	id, err := s.Auth.Authenticate(ctx, req.Header(), ScopeProvision)
	if err != nil {
		return nil, err
	}
	specs, err := principalSpecs(req.Msg.GetPrincipals())
	if err != nil {
		return nil, err
	}
	var stored []authorityrows.Principal
	var created bool
	err = s.Rows.InTenant(ctx, id.TenantID, func(tx *authorityrows.Tx) error {
		var err error
		if _, created, err = tx.EnsureTenant(ctx); err != nil {
			return err
		}
		// The gateway takes a principal's kind from the tenant's own rows, so
		// a caller it already knows as a person is refused here whatever its
		// token says. An unknown caller is the tenant's first registrar.
		switch caller, err := tx.Principal(ctx, id.PrincipalID); {
		case err == nil && caller.Kind == authorityrows.PrincipalHuman:
			return errHumanRegistrar
		case err != nil && !errors.Is(err, authorityrows.ErrNotFound):
			return err
		}
		stored = stored[:0]
		for _, spec := range specs {
			p, err := tx.UpsertPrincipal(ctx, spec)
			if err != nil {
				return err
			}
			stored = append(stored, p)
		}
		return nil
	})
	if err != nil {
		return nil, adminError(ctx, "EnsurePrincipals", err)
	}
	resp := &gatewayv1.EnsurePrincipalsResponse{TenantCreated: created}
	for _, p := range stored {
		resp.Principals = append(resp.Principals, principalProto(p))
	}
	return connect.NewResponse(resp), nil
}

// GetProvisioning returns what the latest plan applied for an organization
// (token scope helm.gateway.read).
func (s *AdminServer) GetProvisioning(ctx context.Context, req *connect.Request[gatewayv1.GetProvisioningRequest]) (*connect.Response[gatewayv1.GetProvisioningResponse], error) {
	id, err := s.Auth.Authenticate(ctx, req.Header(), ScopeRead)
	if err != nil {
		return nil, err
	}
	orgRef := req.Msg.GetOrgRef()
	if !effectargs.ValidOrgRef(orgRef) {
		return nil, rpcError(connect.CodeInvalidArgument, contracts.ReasonSchemaViolation, false, errors.New(`org_ref must be "org:<id>"`))
	}
	applied, err := provision.GetProvisioning(ctx, s.Rows, id.TenantID, orgRef)
	if err != nil {
		return nil, adminError(ctx, "GetProvisioning", err)
	}
	return connect.NewResponse(&gatewayv1.GetProvisioningResponse{Provisioning: provisioningProto(applied)}), nil
}

// ListEffectTypes returns the catalog of effect types the gateway performs
// (token scope helm.gateway.read). It is the same for every tenant.
func (s *AdminServer) ListEffectTypes(ctx context.Context, req *connect.Request[gatewayv1.ListEffectTypesRequest]) (*connect.Response[gatewayv1.ListEffectTypesResponse], error) {
	if _, err := s.Auth.Authenticate(ctx, req.Header(), ScopeRead); err != nil {
		return nil, err
	}
	return connect.NewResponse(&gatewayv1.ListEffectTypesResponse{EffectTypes: s.Catalog}), nil
}

// BuildCatalog renders the declarations of the gateway's adapters as the
// catalog ListEffectTypes serves, ordered by effect type. An effect type
// declared twice, or a schema that is not JSON, is a configuration error the
// gateway refuses to start with.
func BuildCatalog(all []adapters.Adapter) ([]*gatewayv1.EffectTypeDeclaration, error) {
	seen := map[string]bool{}
	var out []*gatewayv1.EffectTypeDeclaration
	for _, a := range all {
		for _, d := range a.Declarations() {
			if seen[d.EffectType] {
				return nil, fmt.Errorf("two adapters declare %s", d.EffectType)
			}
			seen[d.EffectType] = true
			if len(d.ArgumentSchema) > 0 && !json.Valid(d.ArgumentSchema) {
				return nil, fmt.Errorf("the argument schema of %s is not JSON", d.EffectType)
			}
			out = append(out, &gatewayv1.EffectTypeDeclaration{
				EffectType:     d.EffectType,
				RiskClass:      riskProto(string(d.RiskClass)),
				Idempotent:     string(d.Idempotent),
				Observable:     string(d.Observable),
				Reversible:     string(d.Reversible),
				Mediation:      string(d.Mediation),
				TargetForm:     d.TargetForm,
				Description:    d.Description,
				ArgumentSchema: d.ArgumentSchema,
				Grantable:      d.Grantable,
			})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].EffectType < out[j].EffectType })
	return out, nil
}

// principalSpecs validates an EnsurePrincipals request before anything is
// written: 1 to 64 principals, each named once, each of a kind. The store
// validates the rest (ids, external subjects).
func principalSpecs(in []*gatewayv1.PrincipalSpec) ([]authorityrows.PrincipalSpec, error) {
	bad := func(format string, args ...any) error {
		return rpcError(connect.CodeInvalidArgument, contracts.ReasonSchemaViolation, false, fmt.Errorf(format, args...))
	}
	if len(in) == 0 || len(in) > maxPrincipalsPerRequest {
		return nil, bad("principals must list 1 to %d principals, not %d", maxPrincipalsPerRequest, len(in))
	}
	seen := map[string]bool{}
	out := make([]authorityrows.PrincipalSpec, 0, len(in))
	for i, p := range in {
		if p == nil || !authorityrows.ValidPrincipalID(p.GetPrincipalId()) {
			return nil, bad("principals[%d].principal_id is not a principal id", i)
		}
		if seen[p.GetPrincipalId()] {
			return nil, bad("principal %q is listed twice", p.GetPrincipalId())
		}
		seen[p.GetPrincipalId()] = true
		kind, ok := principalKinds[p.GetKind()]
		if !ok {
			return nil, bad("principals[%d].kind is required", i)
		}
		spec := authorityrows.PrincipalSpec{ID: p.GetPrincipalId(), Kind: kind}
		if ext := p.GetExternalSubject(); ext != nil {
			spec.External = &authorityrows.ExternalSubject{System: ext.GetSystem(), ID: ext.GetId()}
		}
		out = append(out, spec)
	}
	return out, nil
}

var principalKinds = map[gatewayv1.PrincipalKind]authorityrows.PrincipalKind{
	gatewayv1.PrincipalKind_PRINCIPAL_KIND_HUMAN:   authorityrows.PrincipalHuman,
	gatewayv1.PrincipalKind_PRINCIPAL_KIND_AGENT:   authorityrows.PrincipalAgent,
	gatewayv1.PrincipalKind_PRINCIPAL_KIND_SERVICE: authorityrows.PrincipalService,
}

func principalProto(p authorityrows.Principal) *gatewayv1.AuthorityPrincipal {
	out := &gatewayv1.AuthorityPrincipal{PrincipalId: p.ID, Version: p.Version, Status: gatewayv1.PrincipalStatus_PRINCIPAL_STATUS_DISABLED}
	for kind, stored := range principalKinds {
		if stored == p.Kind {
			out.Kind = kind
		}
	}
	if p.Active {
		out.Status = gatewayv1.PrincipalStatus_PRINCIPAL_STATUS_ACTIVE
	}
	if p.External != nil {
		out.ExternalSubject = &gatewayv1.ExternalSubject{System: p.External.System, Id: p.External.ID}
	}
	return out
}

func provisioningProto(p *provision.Provisioning) *gatewayv1.Provisioning {
	out := &gatewayv1.Provisioning{
		OrgRef: p.OrgRef, PlanDigest: p.Digest, VersionRef: p.VersionRef, Stage: p.Stage,
		AttemptId: p.AttemptID, Revision: p.Revision, AppliedAt: timestamppb.New(p.AppliedAt), Provisioner: p.Provisioner,
	}
	for i, n := range p.Nodes {
		node := &gatewayv1.ProvisionedNode{
			Node: n.Node, MandateId: n.MandateID, HolderId: n.HolderID, ParentNode: n.ParentNode,
			Active: p.Status[i].Active, MandateVersion: p.Status[i].Version,
		}
		for _, l := range p.Status[i].Limits {
			node.Limits = append(node.Limits, &gatewayv1.ProvisionedLimit{
				LimitId: l.ID.String(), Unit: l.Spec.Unit, Measure: l.Spec.Measure,
				Window: l.Spec.Window, Span: int64(l.Spec.Span), Value: l.Spec.Value, Version: l.Version,
			})
		}
		out.Nodes = append(out.Nodes, node)
	}
	return out
}

// adminError maps a store or provisioning error onto the service's Connect
// codes (the service comment of authority_admin.proto). Anything else is
// transient: aborted for a serialization failure or a deadlock, unavailable
// for the rest, both retryable with the same request.
func adminError(ctx context.Context, rpc string, err error) error {
	switch {
	case errors.Is(err, provision.ErrBudgetReader):
		return rpcError(connect.CodePermissionDenied, contracts.ReasonInsufficientPrivilege, false, err)
	case errors.Is(err, provision.ErrBudgetBinding):
		return rpcError(connect.CodeFailedPrecondition, "", false, err)
	case errors.Is(err, errHumanRegistrar):
		return rpcError(connect.CodePermissionDenied, contracts.ReasonInsufficientPrivilege, false, errHumanRegistrar)
	case errors.Is(err, authorityrows.ErrInvalid):
		return rpcError(connect.CodeInvalidArgument, contracts.ReasonSchemaViolation, false, err)
	case errors.Is(err, authorityrows.ErrIdentityConflict):
		return rpcError(connect.CodeAlreadyExists, contracts.ReasonIdentityIsolationViolation, false, err)
	case errors.Is(err, authorityrows.ErrPrincipalInactive):
		return rpcError(connect.CodeFailedPrecondition, contracts.ReasonPrincipalInactive, false, err)
	case errors.Is(err, provision.ErrNotProvisioned):
		return rpcError(connect.CodeNotFound, "", false, err)
	case errors.Is(err, context.Canceled):
		return connect.NewError(connect.CodeCanceled, err)
	}
	slog.ErrorContext(ctx, "gateway call failed", "rpc", rpc, "error", err)
	var pgErr *pq.Error
	if errors.As(err, &pgErr) && pgErr.Code.Class() == "40" {
		return rpcError(connect.CodeAborted, "", true, errors.New("the gateway could not finish the request; repeat it"))
	}
	return rpcError(connect.CodeUnavailable, "", true, errors.New("the gateway could not evaluate the request"))
}
