package spendproxy

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"net/http"
	"slices"
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

// bindCaller decides which identity a request acts under (helm-tracker#313
// r1, F4) and sets the governance headers the gateway reads to it.
//
// With callers configured, the request must present a configured bearer
// token, and any agent, envelope or workspace header must be one its caller
// covers; absent ones take the caller's. Without callers the proxy serves one
// principal (Config.validateCallers), and the only workspace a request may
// name is request_defaults.workspace_id: no credential covers another, so it
// would reach a signed quote on the caller's word alone.
func (s *Server) bindCaller(r *http.Request) *callerRefusal {
	h := r.Header
	if len(s.cfg.Callers) == 0 {
		if ws := strings.TrimSpace(h.Get(inferencegateway.HeaderWorkspace)); ws != "" && ws != s.cfg.Defaults.WorkspaceID {
			return &callerRefusal{http.StatusForbidden, "permission_error", fmt.Sprintf(
				"%s %q is not covered: the spend proxy has no caller credentials, so a request may name only request_defaults.workspace_id", inferencegateway.HeaderWorkspace, ws)}
		}
		return nil
	}
	token, ok := strings.CutPrefix(h.Get("Authorization"), "Bearer ")
	caller := s.callerFor(strings.TrimSpace(token))
	if !ok || caller == nil {
		return &callerRefusal{http.StatusUnauthorized, "authentication_error", "missing or invalid spend-proxy caller credential: send a configured token as the bearer"}
	}
	h.Del("Authorization")
	if agent := strings.TrimSpace(h.Get(inferencegateway.HeaderAgent)); agent != "" && agent != caller.AgentID {
		return uncovered(caller, inferencegateway.HeaderAgent, agent)
	}
	h.Set(inferencegateway.HeaderAgent, caller.AgentID)
	envelope := strings.TrimSpace(h.Get(inferencegateway.HeaderSpendEnvelope))
	switch {
	case envelope == "":
		h.Set(inferencegateway.HeaderSpendEnvelope, caller.Envelopes[0])
	case !slices.Contains(caller.Envelopes, envelope):
		return uncovered(caller, inferencegateway.HeaderSpendEnvelope, envelope)
	}
	workspace := strings.TrimSpace(h.Get(inferencegateway.HeaderWorkspace))
	switch {
	case workspace == "" && len(caller.Workspaces) > 0:
		h.Set(inferencegateway.HeaderWorkspace, caller.Workspaces[0])
	case workspace == "":
		h.Del(inferencegateway.HeaderWorkspace)
	case !slices.Contains(caller.Workspaces, workspace):
		return uncovered(caller, inferencegateway.HeaderWorkspace, workspace)
	}
	return nil
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

// requireCaller wraps a route that serves callers only: with callers
// configured it needs a configured credential.
func (s *Server) requireCaller(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if len(s.cfg.Callers) > 0 {
			token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
			if !ok || s.callerFor(strings.TrimSpace(token)) == nil {
				w.Header().Set("WWW-Authenticate", `Bearer realm="helm-spend-proxy"`)
				writeJSONError(w, http.StatusUnauthorized, "missing or invalid spend-proxy caller credential: send a configured token as the bearer", "authentication_error", "helm_caller_credential")
				return
			}
		}
		next(w, r)
	}
}
