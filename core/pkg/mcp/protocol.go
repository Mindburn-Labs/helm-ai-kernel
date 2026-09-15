package mcp

import (
	"encoding/json"
	"strings"
)

const (
	// ModernProtocolVersion is the current MCP revision. It is "modern" in the
	// specification's own terms: version, client identity and client capabilities
	// travel in per-request `_meta` and there is no initialize handshake, so a
	// request under it is served statelessly.
	ModernProtocolVersion = "2026-07-28"

	// LatestProtocolVersion is the newest handshake-based ("legacy") revision:
	// the client calls initialize, the server issues a session, and later requests
	// carry MCP-Session-Id.
	LatestProtocolVersion = "2025-11-25"
	LegacyProtocolVersion = "2025-03-26"
)

// Per-request `_meta` keys defined by the modern revision.
const (
	MetaProtocolVersionKey    = "io.modelcontextprotocol/protocolVersion"
	MetaClientInfoKey         = "io.modelcontextprotocol/clientInfo"
	MetaClientCapabilitiesKey = "io.modelcontextprotocol/clientCapabilities"
)

// UnsupportedProtocolVersionCode is the JSON-RPC error code the modern revision
// requires when a server does not implement the requested version. The error's
// data names the versions the server does support so the client can retry.
const UnsupportedProtocolVersionCode = -32022

var SupportedProtocolVersions = []string{
	ModernProtocolVersion,
	LatestProtocolVersion,
	"2025-06-18",
	LegacyProtocolVersion,
}

// modernProtocolVersions are the revisions served statelessly from per-request
// metadata. Everything else in SupportedProtocolVersions is handshake-based.
var modernProtocolVersions = map[string]struct{}{
	ModernProtocolVersion: {},
}

// IsModernProtocolVersion reports whether a revision uses per-request metadata
// rather than an initialize handshake.
func IsModernProtocolVersion(version string) bool {
	_, ok := modernProtocolVersions[strings.TrimSpace(version)]
	return ok
}

// UnsupportedProtocolVersionError builds the JSON-RPC error body the modern
// revision requires, naming both what was asked for and what is on offer.
func UnsupportedProtocolVersionError(requested string) map[string]any {
	return map[string]any{
		"code":    UnsupportedProtocolVersionCode,
		"message": "Unsupported protocol version",
		"data": map[string]any{
			"supported": append([]string(nil), SupportedProtocolVersions...),
			"requested": requested,
		},
	}
}

type ToolAnnotations struct {
	ReadOnlyHint    bool `json:"readOnlyHint,omitempty"`
	DestructiveHint bool `json:"destructiveHint,omitempty"`
	IdempotentHint  bool `json:"idempotentHint,omitempty"`
	OpenWorldHint   bool `json:"openWorldHint,omitempty"`
}

type ToolContentItem struct {
	Type     string `json:"type"`
	Text     string `json:"text,omitempty"`
	URI      string `json:"uri,omitempty"`
	MimeType string `json:"mimeType,omitempty"`
	Name     string `json:"name,omitempty"`
}

// NegotiateProtocolVersion resolves the version of a handshake-based request.
//
// It deliberately refuses the modern revision. Negotiation is a legacy mechanism:
// it exists to answer an initialize call and bind the result to a session. A
// client that asks for 2026-07-28 through initialize is asking for stateless
// semantics over a stateful handshake, and accepting that would serve it under an
// era it did not choose. Modern requests declare their version in per-request
// _meta instead and never reach this function.
func NegotiateProtocolVersion(requested string) (string, bool) {
	if requested == "" {
		return LatestProtocolVersion, true
	}
	if IsModernProtocolVersion(requested) {
		return "", false
	}
	for _, version := range SupportedProtocolVersions {
		if requested == version {
			return version, true
		}
	}
	return "", false
}

func ToolDescriptorPayload(tool ToolRef) map[string]any {
	payload := map[string]any{
		"name":        tool.Name,
		"description": tool.Description,
		"inputSchema": tool.Schema,
	}
	if tool.Title != "" {
		payload["title"] = tool.Title
	}
	if tool.OutputSchema != nil {
		payload["outputSchema"] = tool.OutputSchema
	}
	if annotations := toolAnnotationsPayload(tool.Annotations); len(annotations) > 0 {
		payload["annotations"] = annotations
	}
	if len(tool.RequiredScopes) > 0 {
		payload["requiredScopes"] = append([]string(nil), tool.RequiredScopes...)
	}
	return payload
}

func ToolResultPayload(resp ToolExecutionResponse) map[string]any {
	content := resp.ContentItems
	if len(content) == 0 && resp.Content != "" {
		content = []ToolContentItem{{Type: "text", Text: resp.Content}}
	}

	payload := map[string]any{
		"content": content,
		"isError": resp.IsError,
	}
	if len(resp.StructuredContent) > 0 {
		payload["structuredContent"] = resp.StructuredContent
	}
	if resp.ReceiptID != "" {
		payload["receipt_id"] = resp.ReceiptID
	}
	if resp.ProtectedArgsHash != "" {
		payload["args_hash"] = resp.ProtectedArgsHash
	}
	return payload
}

func StructuredTextContent(payload map[string]any, fallback string) []ToolContentItem {
	if len(payload) == 0 {
		if fallback == "" {
			return nil
		}
		return []ToolContentItem{{Type: "text", Text: fallback}}
	}

	data, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return []ToolContentItem{{Type: "text", Text: fallback}}
	}
	return []ToolContentItem{{Type: "text", Text: string(data)}}
}

func toolAnnotationsPayload(annotations *ToolAnnotations) map[string]any {
	if annotations == nil {
		return nil
	}
	payload := map[string]any{}
	if annotations.ReadOnlyHint {
		payload["readOnlyHint"] = true
	}
	if annotations.DestructiveHint {
		payload["destructiveHint"] = true
	}
	if annotations.IdempotentHint {
		payload["idempotentHint"] = true
	}
	if annotations.OpenWorldHint {
		payload["openWorldHint"] = true
	}
	return payload
}
