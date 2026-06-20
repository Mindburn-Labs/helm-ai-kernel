package inferencegateway

import (
	"errors"
	"net/http"
	"strings"
)

// HELM request headers for the OpenAI-compatible governed gateway. Existing
// OpenAI clients reach Mindburn by adding these headers to their requests; the
// model, messages, and token fields stay in the standard OpenAI request body.
const (
	HeaderWorkspace      = "X-HELM-Workspace"
	HeaderAgent          = "X-HELM-Agent"
	HeaderPrincipal      = "X-HELM-Principal"
	HeaderSpendEnvelope  = "X-HELM-Spend-Envelope"
	HeaderIdempotencyKey = "X-HELM-Idempotency-Key"
	HeaderRoutePolicy    = "X-HELM-Route-Policy"
)

// RequestHeaders is the governance envelope parsed from the HELM request
// headers that an OpenAI-compatible client attaches.
type RequestHeaders struct {
	WorkspaceID    string
	AgentID        string
	PrincipalID    string
	SpendEnvelope  string
	IdempotencyKey string
	RoutePolicy    string
}

// ParseRequestHeaders extracts and validates the HELM governance headers. It
// fails closed: the agent, spend-envelope, and idempotency-key headers are
// mandatory because no dispatch may proceed without a scoped, replay-safe
// spend authority.
func ParseRequestHeaders(h http.Header) (RequestHeaders, error) {
	out := RequestHeaders{
		WorkspaceID:    strings.TrimSpace(h.Get(HeaderWorkspace)),
		AgentID:        strings.TrimSpace(h.Get(HeaderAgent)),
		PrincipalID:    strings.TrimSpace(h.Get(HeaderPrincipal)),
		SpendEnvelope:  strings.TrimSpace(h.Get(HeaderSpendEnvelope)),
		IdempotencyKey: strings.TrimSpace(h.Get(HeaderIdempotencyKey)),
		RoutePolicy:    strings.TrimSpace(h.Get(HeaderRoutePolicy)),
	}
	if out.AgentID == "" {
		return RequestHeaders{}, errors.New("inferencegateway: " + HeaderAgent + " header is required")
	}
	if out.SpendEnvelope == "" {
		return RequestHeaders{}, errors.New("inferencegateway: " + HeaderSpendEnvelope + " header is required")
	}
	if out.IdempotencyKey == "" {
		return RequestHeaders{}, errors.New("inferencegateway: " + HeaderIdempotencyKey + " header is required")
	}
	return out, nil
}
