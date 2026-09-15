package mcp

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/auth"
)

// Dual-era support.
//
// MCP revision 2026-07-28 removed the initialize handshake. A "modern" request
// declares its protocol version, client identity and client capabilities in
// per-request `_meta`, and the server answers it statelessly. A "legacy" request
// (2025-11-25 and earlier) opens with initialize and is scoped to the session the
// server issues. The specification calls a server that serves both dual-era, and
// it defines the selection rule this file implements: a request carrying modern
// `_meta` is served under the modern revision; an initialize request selects
// legacy semantics.
//
// Governance is not duplicated. Both eras reach the same ExecutionFirewall, the
// same permit checks and the same receipts. What differs is only what a governed
// call binds to, because the modern era supplies no session: see
// validatedGovernedIdentity.

// requestMeta is the `_meta` envelope a modern request carries in its params.
type requestMeta struct {
	Meta map[string]json.RawMessage `json:"_meta"`
}

// modernProtocolVersionFromParams returns the protocol version a request declares
// in `_meta`, and whether it declared one at all. An empty or malformed envelope
// is not an error here: it simply means the request is not modern, and the legacy
// path handles it.
func modernProtocolVersionFromParams(params json.RawMessage) (string, bool) {
	if len(params) == 0 {
		return "", false
	}
	var envelope requestMeta
	if err := json.Unmarshal(params, &envelope); err != nil || envelope.Meta == nil {
		return "", false
	}
	raw, ok := envelope.Meta[MetaProtocolVersionKey]
	if !ok {
		return "", false
	}
	var version string
	if err := json.Unmarshal(raw, &version); err != nil {
		return "", false
	}
	version = strings.TrimSpace(version)
	return version, version != ""
}

// requestEra decides which revision serves a request, following the
// specification's dual-era rule.
//
// The header is deliberately not enough on its own. A legacy client sends
// MCP-Protocol-Version too, so only the `_meta` declaration distinguishes a
// modern request; the header is checked for agreement and a disagreement is
// reported rather than silently resolved, because guessing which one the client
// meant is how an era-ambiguous request gets served under the wrong semantics.
func requestEra(params json.RawMessage, header string) (version string, modern bool, mismatch bool) {
	declared, ok := modernProtocolVersionFromParams(params)
	if !ok {
		return strings.TrimSpace(header), false, false
	}
	header = strings.TrimSpace(header)
	if header != "" && header != declared {
		return declared, true, true
	}
	return declared, true, false
}

// writeJSONRPCError emits a JSON-RPC error with an HTTP 200, which is what the
// modern revision expects: the transport succeeded, the request did not.
func writeJSONRPCError(w http.ResponseWriter, id any, errBody map[string]any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"jsonrpc": "2.0",
		"id":      id,
		"error":   errBody,
	})
}

// validatedGovernedIdentity is the modern counterpart of
// validatedGovernedSession. The modern era has no session to validate, so a
// governed call binds to the authenticated principal instead — the identity the
// firewall, the permit and the receipt already use.
//
// This is not a new governance model. evaluatePreparedToolExecution already
// prefers req.PrincipalID and only falls back to the session id when no principal
// is present; the run identity and tenant already fall back to the correlation id
// and the authenticated tenant. The session was the weaker of the two identities
// all along. What changes here is that a request without one is no longer refused
// at the door when it carries the stronger one.
func (g *Gateway) validatedGovernedIdentity(w http.ResponseWriter, r *http.Request) (string, bool) {
	principal, err := auth.GetPrincipal(r.Context())
	if err != nil || principal == nil || strings.TrimSpace(principal.GetID()) == "" {
		http.Error(w, "an authenticated principal is required for governed tool execution", http.StatusUnauthorized)
		return "", false
	}
	// No session id: the run identity falls back to the correlation id, which is
	// the client's handle for grouping a multi-call episode in evidence.
	return "", true
}

// DiscoverResult answers server/discover. The modern revision requires servers to
// implement it; clients use it to learn supported versions and capabilities in one
// request, and dual-era clients use it on stdio to decide which era they are
// talking to.
type DiscoverResult struct {
	ResultType        string         `json:"resultType"`
	SupportedVersions []string       `json:"supportedVersions"`
	Capabilities      map[string]any `json:"capabilities"`
	Instructions      string         `json:"instructions,omitempty"`
	Meta              map[string]any `json:"_meta,omitempty"`
}

// handleDiscover builds the server/discover result.
//
// It reports every revision this gateway serves, modern and legacy alike, which
// is what makes the answer useful to a dual-era client: it can see both that we
// speak 2026-07-28 and that we still speak 2025-11-25, and choose.
func (g *Gateway) handleDiscover(ctx context.Context) DiscoverResult {
	capabilities := map[string]any{
		"tools": map[string]any{},
	}
	if tools, err := g.catalog.Search(ctx, ""); err == nil && len(tools) > 0 {
		capabilities["tools"] = map[string]any{"listChanged": false}
	}
	return DiscoverResult{
		ResultType:        "complete",
		SupportedVersions: append([]string(nil), SupportedProtocolVersions...),
		Capabilities:      capabilities,
		Instructions:      "HELM governs every tool call: results carry a receipt id and a denial carries a reason code.",
		Meta: map[string]any{
			"io.modelcontextprotocol/serverInfo": map[string]any{
				"name":    "helm-mcp-gateway",
				"version": "1.0.0",
			},
		},
	}
}
