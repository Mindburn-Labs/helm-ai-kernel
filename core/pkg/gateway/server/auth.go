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
}

// Identity is a verified token.
type Identity struct {
	admission.Caller
	Scope string
	// TokenID is the jti.
	TokenID string
	// ExpiresAt is the token's exp.
	ExpiresAt time.Time
	// AuthorizationDetails is the RFC 9396 claim, when the token has one.
	AuthorizationDetails json.RawMessage
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
		TokenID:              strings.TrimSpace(claims.RegisteredClaims.ID),
		AuthorizationDetails: claims.AuthorizationDetails,
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
