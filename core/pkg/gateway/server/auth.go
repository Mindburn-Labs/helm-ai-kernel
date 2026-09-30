package server

// quantum_posture: bearer tokens are classical RS256 JWTs verified by
// pkg/auth/jwks against the Control Plane's JWKS (ADR-0005 §4); no
// post-quantum claim is made.

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"connectrpc.com/connect"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/auth/jwks"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/admission"
)

// The token scopes of the gateway effect API, one per authority class
// (protocols/proto/helm/gateway/v1/gateway.proto). ADR-0005 allows one scope
// per token.
const (
	ScopePropose = "helm.gateway.propose"
	ScopeDecide  = "helm.gateway.decide"
	ScopeRead    = "helm.gateway.read"
	ScopeStop    = "helm.gateway.stop"
	ScopeExecute = "helm.gateway.execute"
)

// TokenValidator verifies a token's signature, issuer, audience, algorithm
// and lifetime (jwks.JWKSValidator).
type TokenValidator interface {
	ValidateAuthorization(string) (*jwks.OAuthTokenClaims, error)
}

// Authenticator turns a request's bearer token into the caller's identity.
type Authenticator struct {
	Validator TokenValidator
	// Actor is the configured workload actor (HELM_CP_IDENTITY_ACTOR). A
	// token may name no actor, or this one.
	Actor string
	// RequireCNF requires the token's cnf.x5t#S256 to name the TLS client
	// certificate.
	RequireCNF bool
	// RequireEpisode is the worker listener's profile (HELM-752 K7): the token
	// must carry a helm_episode claim, the bounded worker run it was minted
	// for. The worker profile also sets no RequireCNF, validates a longer
	// lifetime and a different audience (jwks.WorkerValidator), and is only
	// ever mounted on the worker listener.
	RequireEpisode bool
}

// Identity is a verified token.
type Identity struct {
	admission.Caller
	Scope string
	// Issuer is the token's iss.
	Issuer string
	// TokenID is the jti.
	TokenID string
	// ExpiresAt is the token's exp.
	ExpiresAt time.Time
	// AuthorizationDetails is the RFC 9396 claim, when the token has one.
	AuthorizationDetails json.RawMessage
	// Episode is the token's helm_episode claim, when it has one.
	Episode *jwks.EpisodeClaim
}

type tlsStateKey struct{}

// withTLSState records the connection's TLS state for cnf checks; Connect
// handlers do not see the *http.Request.
func withTLSState(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS != nil {
			r = r.WithContext(context.WithValue(r.Context(), tlsStateKey{}, r.TLS))
		}
		next.ServeHTTP(w, r)
	})
}

// WithTLSState is the wrapper the API handler carries: it records the
// connection's TLS state in the request context for the certificate binding
// check. Any other handler that authenticates with an Authenticator on the same
// listener needs it too.
func WithTLSState(next http.Handler) http.Handler { return withTLSState(next) }

// Authenticate verifies the bearer token in header for an RPC that accepts
// one of scopes. Tenant, workspace and principal come from the token alone
// (R9, ADR-0005).
func (a *Authenticator) Authenticate(ctx context.Context, header http.Header, scopes ...string) (Identity, error) {
	raw := strings.TrimSpace(header.Get("Authorization"))
	scheme, token, ok := strings.Cut(raw, " ")
	token = strings.TrimSpace(token)
	if !ok || !strings.EqualFold(scheme, "Bearer") || token == "" {
		return Identity{}, unauthenticated("a bearer token is required")
	}
	claims, err := a.Validator.ValidateAuthorization(token)
	if err != nil {
		var validation *jwks.JWKSValidationError
		if errors.As(err, &validation) && validation.Kind == jwks.JWKSErrFetchFailed {
			return Identity{}, rpcError(connect.CodeUnavailable, "", true, errors.New("the token signing keys could not be loaded"))
		}
		return Identity{}, unauthenticated("the token is not valid")
	}
	// One audience (this environment's gateway): a token minted for several
	// cannot be replayed across them.
	if len(claims.RegisteredClaims.Audience) != 1 {
		return Identity{}, unauthenticated("the token must name exactly one audience")
	}
	id := Identity{
		Caller: admission.Caller{
			TenantID:    claims.TenantID,
			WorkspaceID: claims.WorkspaceID,
			PrincipalID: strings.TrimSpace(claims.RegisteredClaims.Subject),
			ActorID:     claims.Actor,
		},
		Issuer:               claims.RegisteredClaims.Issuer,
		TokenID:              strings.TrimSpace(claims.RegisteredClaims.ID),
		AuthorizationDetails: claims.AuthorizationDetails,
		Episode:              claims.Episode,
	}
	if claims.RegisteredClaims.ExpiresAt != nil {
		id.ExpiresAt = claims.RegisteredClaims.ExpiresAt.Time
	}
	if id.TenantID == "" || id.WorkspaceID == "" || id.PrincipalID == "" {
		return Identity{}, unauthenticated("the token lacks its principal, tenant or workspace")
	}
	if a.RequireCNF {
		state, _ := ctx.Value(tlsStateKey{}).(*tls.ConnectionState)
		if state == nil || len(state.PeerCertificates) == 0 ||
			!jwks.CertificateMatchesThumbprint(state.PeerCertificates[0], claims.CertificateThumbprint) {
			return Identity{}, unauthenticated("the token is not bound to this client certificate")
		}
	}
	if id.ActorID != "" && id.ActorID != a.Actor {
		return Identity{}, permissionDenied("the token's actor is not the configured workload actor")
	}
	if len(claims.Scopes) != 1 {
		return Identity{}, permissionDenied("the token must carry exactly one scope")
	}
	id.Scope = claims.Scopes[0]
	for _, scope := range scopes {
		if id.Scope == scope {
			if a.RequireEpisode && id.Episode == nil {
				return Identity{}, permissionDenied("the token names no episode; this listener serves episode tokens only")
			}
			return id, nil
		}
	}
	return Identity{}, permissionDenied("the token's scope does not cover this call")
}

func unauthenticated(message string) error {
	return rpcError(connect.CodeUnauthenticated, "", false, errors.New(message))
}

func permissionDenied(message string) error {
	return rpcError(connect.CodePermissionDenied, contracts.ReasonInsufficientPrivilege, false, errors.New(message))
}

// token is what a single-use decide or stop token contributes to admission.
func (id Identity) token() admission.Token {
	return admission.Token{Issuer: id.Issuer, ID: id.TokenID, Scope: id.Scope, ExpiresAt: id.ExpiresAt}
}

// checkDecisionBinding requires exactly one helm_effect_decision entry in the
// token's authorization_details, naming this attempt and action (proposed
// ADR-0005 §10). A decide token cannot approve another attempt, or reject
// where it was minted to approve.
func checkDecisionBinding(raw json.RawMessage, attemptID, action string) error {
	return checkBinding(raw, "helm_effect_decision", map[string]string{"attempt_id": attemptID, "action": action})
}

// checkBinding requires exactly one RFC 9396 authorization_details entry of
// detailType, whose fields equal want. A single-use decide or stop token
// names the one object it was minted for (ADR-0005 §10 amendment):
//
//	helm_effect_decision {attempt_id, action}  Approve, Reject
//	helm_stop_lift       {stop_id}             Lift
//	helm_effect_cancel   {attempt_id}          Cancel with a stop token
//	helm_stop            {idempotency_key, scope_kind, scope_key}  Stop
func checkBinding(raw json.RawMessage, detailType string, want map[string]string) error {
	var entries []map[string]any
	if len(raw) == 0 || json.Unmarshal(raw, &entries) != nil {
		return permissionDenied("the token must carry authorization_details naming its object")
	}
	var bound []map[string]any
	for _, entry := range entries {
		if entry["type"] == detailType {
			bound = append(bound, entry)
		}
	}
	if len(bound) != 1 {
		return permissionDenied("the token must carry exactly one " + detailType + " entry")
	}
	for key, value := range want {
		if got, ok := bound[0][key].(string); !ok || got != value {
			return permissionDenied("the token is bound to another object or action")
		}
	}
	return nil
}
