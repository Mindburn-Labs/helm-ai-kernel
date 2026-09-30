package server

// quantum_posture: bearer tokens are classical RS256 JWTs verified by
// pkg/auth/jwks against the Control Plane's JWKS (ADR-0005 §4); no
// post-quantum claim is made.

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
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
	// ScopeProvision registers a tenant's first principals
	// (AuthorityAdminService.EnsurePrincipals). No other RPC takes it, and the
	// Control Plane's issuer mints it for its service principal only.
	ScopeProvision = "helm.gateway.provision"
	// ScopeStepUp is the scope of the step-up proof an Approve may carry
	// (ApproveRequest.step_up_proof). No RPC takes it as its own credential.
	ScopeStepUp = "helm.gateway.stepup"
)

// The step-up proof's method and lifetime (§10.1). The method is the one the
// Control Plane's issuer attests: it verified the approver's WebAuthn
// assertion over the approval digest. The lifetime bounds exp - iat of a proof
// whatever the validator's own limit is.
const (
	stepUpMethod      = "webauthn"
	stepUpMaxLifetime = 300 * time.Second
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

// Identity is a verified token. Its Caller carries the token's episode claim
// when it has one (Caller.Episode, the same claim as Episode below).
type Identity struct {
	admission.Caller
	Scope string
	// Issuer is the token's iss.
	Issuer string
	// TokenID is the jti.
	TokenID string
	// IssuedAt is the token's iat; zero when it has none.
	IssuedAt time.Time
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
	return a.verify(ctx, token, scopes...)
}

// verify checks one compact token for an RPC, or a proof, that accepts one of
// scopes.
func (a *Authenticator) verify(ctx context.Context, token string, scopes ...string) (Identity, error) {
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
	if claims.RegisteredClaims.IssuedAt != nil {
		id.IssuedAt = claims.RegisteredClaims.IssuedAt.Time
	}
	// The episode reaches admission through the caller, and only from the
	// verified claim: it is what an attempt records and what a read is held to.
	if e := claims.Episode; e != nil {
		id.Caller.Episode = &admission.Episode{EpisodeID: e.EpisodeID, WorkItemID: e.WorkItemID, OrganizationVersionID: e.OrganizationVersionID}
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

// token is what a single-use decide, stop or step-up token contributes to
// admission.
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

// checkStepUpBinding requires exactly one helm_step_up entry in a step-up
// proof's authorization_details, naming this attempt, the approval digest the
// approver was shown (lower-case hex) and the method the issuer attests, and
// stating that the issuer saw the authenticator's user-verification flag set:
// user_verified is exactly boolean true (§10.1). A proof cannot approve
// another attempt or another digest, nor one whose approver only touched a key.
func checkStepUpBinding(raw json.RawMessage, attemptID string, approvalDigest []byte) error {
	if err := checkBinding(raw, "helm_step_up", map[string]string{
		"attempt_id": attemptID, "approval_digest": hex.EncodeToString(approvalDigest), "method": stepUpMethod,
	}); err != nil {
		return err
	}
	if !stepUpUserVerified(raw) {
		return permissionDenied("the proof does not state that the approver was user-verified")
	}
	return nil
}

// stepUpUserVerified reports whether the helm_step_up entry of raw has
// user_verified set to boolean true. Missing, false and any other type is not
// verified. checkBinding has already found the one entry.
func stepUpUserVerified(raw json.RawMessage) bool {
	var entries []map[string]any
	if json.Unmarshal(raw, &entries) != nil {
		return false
	}
	for _, entry := range entries {
		if entry["type"] == "helm_step_up" {
			verified, ok := entry["user_verified"].(bool)
			return ok && verified
		}
	}
	return false
}

// stepUpFresh reports whether a proof is fresh (§10.1): it has an iat, and
// its exp is after it and at most stepUpMaxLifetime later. The validator has
// checked that the call falls between iat and exp, within its clock skew.
func stepUpFresh(id Identity) bool {
	return !id.IssuedAt.IsZero() && id.ExpiresAt.After(id.IssuedAt) && id.ExpiresAt.Sub(id.IssuedAt) <= stepUpMaxLifetime
}

// stepUp verifies the step-up proof of an Approve before its transaction, so
// no row lock is held while signing keys are fetched, and returns what
// admission spends: nil when there is no proof or it does not verify. A proof
// that does not verify is the same as none. Admission then refuses an effect
// that needs step-up (STEP_UP_REQUIRED), and ignores the proof of one that
// needs none, whatever that proof holds.
//
// The proof is a compact token like any other (one audience, the issuer's
// keys, the configured actor, the certificate binding when required), with
// the scope helm.gateway.stepup, the decide token's approver and tenant, a
// lifetime of at most 300 seconds from its iat, and one helm_step_up entry
// naming the attempt and the digest and stating user verification. The proof
// as received goes with the verified claims: the approval record keeps it.
func (a *Authenticator) stepUp(ctx context.Context, decide Identity, attemptID string, approvalDigest []byte, proof string) *admission.StepUp {
	if proof == "" {
		return nil
	}
	refused := func(reason string) *admission.StepUp {
		slog.WarnContext(ctx, "a step-up proof was not accepted", "attempt_id", attemptID, "reason", reason)
		return nil
	}
	if len(proof) > admission.MaxStepUpProofBytes {
		return refused("the proof is longer than the gateway keeps")
	}
	id, err := a.verify(ctx, proof, ScopeStepUp)
	if err != nil {
		return refused(err.Error())
	}
	if id.PrincipalID != decide.PrincipalID || id.TenantID != decide.TenantID {
		return refused("the proof names another approver or tenant than the decide token")
	}
	if !stepUpFresh(id) {
		return refused("the proof is not fresh: it needs an iat, and an exp at most 300 seconds after it")
	}
	if err := checkStepUpBinding(id.AuthorizationDetails, attemptID, approvalDigest); err != nil {
		return refused(err.Error())
	}
	return &admission.StepUp{Token: id.token(), Method: stepUpMethod, Raw: proof}
}

// checkBinding requires exactly one RFC 9396 authorization_details entry of
// detailType, whose fields equal want. A single-use decide or stop token
// names the one object it was minted for (ADR-0005 §10 amendment):
//
//	helm_effect_decision {attempt_id, action}  Approve, Reject
//	helm_stop_lift       {stop_id}             Lift
//	helm_effect_cancel   {attempt_id}          Cancel with a stop token
//	helm_stop            {idempotency_key, scope_kind, scope_key}  Stop
//	helm_step_up         {attempt_id, approval_digest, method, user_verified}  Approve's step-up proof
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
