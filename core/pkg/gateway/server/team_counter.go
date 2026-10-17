package server

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"

	"connectrpc.com/connect"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/adapters/provision"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/kernel/authority/authorityrows"
)

// TeamCounterPath is an internal, source-owned read surface on the gateway's
// main listener. It uses the same authenticated read scope and database role
// as AuthorityAdminService, without a second database credential in a caller.
const TeamCounterPath = "POST /v1/authority/team-counter:read"

const maxTeamCounterRequestBytes = 16 << 10

// TeamCounterHandler returns a read-only JSON handler. It is intentionally not
// mounted on the worker or executor listeners, which accept episode tokens.
func (s *AdminServer) TeamCounterHandler() (string, http.Handler) {
	return TeamCounterPath, withTLSState(http.HandlerFunc(s.readTeamCounter))
}

func (s *AdminServer) readTeamCounter(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	id, err := s.Auth.Authenticate(r.Context(), r.Header, ScopeRead)
	if err != nil {
		code := connect.CodeOf(err)
		if code == connect.CodeUnauthenticated {
			teamCounterError(w, http.StatusUnauthorized, "unauthenticated", "a valid read token is required")
		} else {
			teamCounterError(w, http.StatusForbidden, "permission_denied", "the read token is not authorized")
		}
		return
	}
	if ct := r.Header.Get("Content-Type"); ct != "application/json" && !strings.HasPrefix(ct, "application/json;") {
		teamCounterError(w, http.StatusUnsupportedMediaType, "invalid_argument", "Content-Type must be application/json")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxTeamCounterRequestBytes)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	var request struct {
		Binding provision.TeamCounterBinding `json:"binding"`
	}
	if err := decoder.Decode(&request); err != nil {
		teamCounterError(w, http.StatusBadRequest, "invalid_argument", "invalid team counter binding")
		return
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		teamCounterError(w, http.StatusBadRequest, "invalid_argument", "one JSON object is required")
		return
	}
	snapshot, err := provision.GetTeamCounter(r.Context(), s.Rows, id.TenantID, id.WorkspaceID, id.PrincipalID, request.Binding)
	if err != nil {
		switch {
		case errors.Is(err, authorityrows.ErrInvalid):
			teamCounterError(w, http.StatusBadRequest, "invalid_argument", "invalid team counter binding")
		case errors.Is(err, provision.ErrBudgetReader):
			teamCounterError(w, http.StatusForbidden, "permission_denied", "the reader is not authorized for this team counter")
		case errors.Is(err, provision.ErrNotProvisioned):
			teamCounterError(w, http.StatusNotFound, "not_found", "the organization is not provisioned in this scope")
		case errors.Is(err, provision.ErrTeamCounterBinding):
			teamCounterError(w, http.StatusPreconditionFailed, "stale_binding", "the team limit binding is not current")
		case errors.Is(err, provision.ErrTeamCounterAbsent):
			teamCounterError(w, http.StatusPreconditionFailed, "counter_not_materialized", "a current counter bucket is absent")
		case errors.Is(err, provision.ErrTeamCounterInvalid):
			teamCounterError(w, http.StatusServiceUnavailable, "unreportable_counter", "the team counter cannot be reported")
		default:
			slog.ErrorContext(r.Context(), "team counter read failed", "error", err)
			teamCounterError(w, http.StatusServiceUnavailable, "unavailable", "the team counter could not be read")
		}
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(snapshot)
}

func teamCounterError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	if status == http.StatusUnauthorized {
		w.Header().Set("WWW-Authenticate", "Bearer")
	}
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}{Error: struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	}{Code: code, Message: message}})
}
