package spendproxy

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"strings"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/inferencegateway"
)

// callerRefusal is a request the caller binding refuses before the governed
// gateway sees it.
type callerRefusal struct {
	status  int
	errType string
	message string
}

// MinCallerTokenBytes is the shortest caller token the proxy accepts. The
// config holds a token's unsalted SHA-256, which keeps a token of 32 random
// bytes or more out of reach of a guess; a shorter one is refused at use, so
// a config that hashed one is found at the first request (helm-tracker#313
// r2, finding 13).
const MinCallerTokenBytes = 32

// bindCaller decides which identity a request acts under (helm-tracker#313
// r1, F4) and sets the governance headers the gateway reads to it. It returns
// the caller whose credential the request presented, nil without callers.
//
// With callers configured, the request must present a configured bearer
// token, and any agent, envelope or workspace header must be one its caller
// covers; absent ones take the caller's. Without callers the proxy serves one
// principal (Config.validateCallers), and the only workspace a request may
// name is request_defaults.workspace_id: no credential covers another, so it
// would reach a signed quote on the caller's word alone.
func (s *Server) bindCaller(r *http.Request) (*CallerCfg, *callerRefusal) {
	h := r.Header
	if len(s.cfg.Callers) == 0 {
		if ws := strings.TrimSpace(h.Get(inferencegateway.HeaderWorkspace)); ws != "" && ws != s.cfg.Defaults.WorkspaceID {
			return nil, &callerRefusal{http.StatusForbidden, "permission_error", fmt.Sprintf(
				"%s %q is not covered: the spend proxy has no caller credentials, so a request may name only request_defaults.workspace_id", inferencegateway.HeaderWorkspace, ws)}
		}
		return nil, nil
	}
	caller, refused := s.authenticate(h)
	if refused != nil {
		return nil, refused
	}
	h.Del("Authorization")
	if agent := strings.TrimSpace(h.Get(inferencegateway.HeaderAgent)); agent != "" && agent != caller.AgentID {
		return nil, uncovered(caller, inferencegateway.HeaderAgent, agent)
	}
	h.Set(inferencegateway.HeaderAgent, caller.AgentID)
	envelope := strings.TrimSpace(h.Get(inferencegateway.HeaderSpendEnvelope))
	switch {
	case envelope == "":
		h.Set(inferencegateway.HeaderSpendEnvelope, caller.Envelopes[0])
	case !slices.Contains(caller.Envelopes, envelope):
		return nil, uncovered(caller, inferencegateway.HeaderSpendEnvelope, envelope)
	}
	workspace := strings.TrimSpace(h.Get(inferencegateway.HeaderWorkspace))
	switch {
	case workspace == "" && len(caller.Workspaces) > 0:
		h.Set(inferencegateway.HeaderWorkspace, caller.Workspaces[0])
	case workspace == "":
		h.Del(inferencegateway.HeaderWorkspace)
	case !slices.Contains(caller.Workspaces, workspace):
		return nil, uncovered(caller, inferencegateway.HeaderWorkspace, workspace)
	}
	return caller, nil
}

// scopeIdempotencyKey makes a request's idempotency key its caller's: the
// caller's id is part of the key the engine and the replay cache see, so one
// caller's key neither blocks nor reveals another's (helm-tracker#313 r2,
// finding 10). The id's length is part of it, so no two callers' keys meet.
func scopeIdempotencyKey(h http.Header, caller *CallerCfg) {
	if caller == nil {
		return
	}
	key := strings.TrimSpace(h.Get(inferencegateway.HeaderIdempotencyKey))
	h.Set(inferencegateway.HeaderIdempotencyKey, "caller:"+strconv.Itoa(len(caller.ID))+":"+caller.ID+":"+key)
}

// authenticate finds the caller whose token the request presents as its
// bearer. The scheme is matched without regard to case (RFC 7235).
func (s *Server) authenticate(h http.Header) (*CallerCfg, *callerRefusal) {
	scheme, token, _ := strings.Cut(strings.TrimSpace(h.Get("Authorization")), " ")
	token = strings.TrimSpace(token)
	if !strings.EqualFold(scheme, "Bearer") || token == "" {
		return nil, &callerRefusal{http.StatusUnauthorized, "authentication_error", "missing or invalid spend-proxy caller credential: send a configured token as the bearer"}
	}
	if len(token) < MinCallerTokenBytes {
		return nil, &callerRefusal{http.StatusUnauthorized, "authentication_error", fmt.Sprintf("a spend-proxy caller token is at least %d bytes: generate one with `openssl rand -hex 32`", MinCallerTokenBytes)}
	}
	caller := s.callerFor(token)
	if caller == nil {
		return nil, &callerRefusal{http.StatusUnauthorized, "authentication_error", "missing or invalid spend-proxy caller credential: send a configured token as the bearer"}
	}
	return caller, nil
}

func uncovered(caller *CallerCfg, header, value string) *callerRefusal {
	return &callerRefusal{http.StatusForbidden, "permission_error", fmt.Sprintf("%s %q is not covered by the credential of caller %q", header, value, caller.ID)}
}

// callerFor finds the caller whose token hash is the presented token's. Every
// configured hash is compared in constant time.
func (s *Server) callerFor(token string) *CallerCfg {
	if token == "" {
		return nil
	}
	sum := sha256.Sum256([]byte(token))
	presented := hex.EncodeToString(sum[:])
	var found *CallerCfg
	for i := range s.cfg.Callers {
		if subtle.ConstantTimeCompare([]byte(presented), []byte(s.cfg.Callers[i].TokenSHA256)) == 1 {
			found = &s.cfg.Callers[i]
		}
	}
	return found
}

// requireCaller wraps a route that serves callers only (/v1/models and
// /helm/spend/health, which shows the balance, the upstream, the receipt log
// path and the signing key): with callers configured it needs a configured
// credential.
func (s *Server) requireCaller(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if len(s.cfg.Callers) > 0 {
			if _, refused := s.authenticate(r.Header); refused != nil {
				w.Header().Set("WWW-Authenticate", `Bearer realm="helm-spend-proxy"`)
				writeJSONError(w, refused.status, refused.message, refused.errType, "helm_caller_credential")
				return
			}
		}
		next(w, r)
	}
}
