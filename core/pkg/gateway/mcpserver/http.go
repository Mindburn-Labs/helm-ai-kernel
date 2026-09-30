// Package mcpserver exposes the effect gateway over stateless MCP Streamable
// HTTP. It carries no provider credential or authority store of its own.
package mcpserver

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"unicode/utf8"

	"connectrpc.com/connect"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/admission"
)

// Caller is supplied by the worker listener's verified identity. None of
// these fields is accepted from a tool request.
type Caller struct {
	admission.Caller
	EpisodeID, WorkItemID, OrganizationVersionID string
}

type Authenticate func(context.Context, http.Header) (Caller, error)

type Tool struct {
	Name        string          `json:"name"`
	Description string          `json:"description,omitempty"`
	InputSchema json.RawMessage `json:"inputSchema"`
}

type Call struct {
	RequestID json.RawMessage
	Name      string
	Arguments json.RawMessage
}

// Result separates a domain outcome from a transport/protocol failure.
// ESCALATED is a successful result with IsError false.
type Result struct {
	StructuredContent map[string]any
	IsError           bool
}

// Backend uses the same registered effects, admission transaction, permits
// and observations as the effect API. It must recheck current authority.
type Backend interface {
	Tools(context.Context, Caller) ([]Tool, error)
	Call(context.Context, Caller, Call) (Result, error)
}

type Handler struct {
	Authenticate Authenticate
	Backend      Backend
	Version      string
}

// MaxRequestBytes bounds one JSON-RPC envelope before authentication and
// decoding. The admission layer separately bounds the effect's arguments.
const MaxRequestBytes = 256 << 10

type envelope struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !validOrigin(r) {
		http.Error(w, "invalid MCP origin", http.StatusForbidden)
		return
	}
	if version := r.Header.Get("MCP-Protocol-Version"); version != "" && !supportedVersion(version) {
		http.Error(w, "unsupported MCP protocol version", http.StatusBadRequest)
		return
	}
	var body []byte
	if r.Method == http.MethodPost {
		kind, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if err != nil || kind != "application/json" || (r.Header.Get("Content-Encoding") != "" && r.Header.Get("Content-Encoding") != "identity") {
			http.Error(w, "MCP requires an uncompressed JSON request", http.StatusUnsupportedMediaType)
			return
		}
		if !accepts(r.Header.Get("Accept"), "application/json") || !accepts(r.Header.Get("Accept"), "text/event-stream") {
			http.Error(w, "MCP requires JSON and event-stream response support", http.StatusNotAcceptable)
			return
		}
		var err error
		body, err = io.ReadAll(http.MaxBytesReader(w, r.Body, MaxRequestBytes))
		if err != nil {
			http.Error(w, "MCP request exceeds its bound", http.StatusRequestEntityTooLarge)
			return
		}
	}
	if h.Authenticate == nil || h.Backend == nil {
		http.Error(w, "gateway unavailable", http.StatusServiceUnavailable)
		return
	}
	caller, err := h.Authenticate(r.Context(), r.Header)
	if err != nil {
		status := http.StatusServiceUnavailable
		switch connect.CodeOf(err) {
		case connect.CodeUnauthenticated:
			status = http.StatusUnauthorized
			w.Header().Set("WWW-Authenticate", "Bearer")
		case connect.CodePermissionDenied:
			status = http.StatusForbidden
		}
		http.Error(w, http.StatusText(status), status)
		return
	}
	if caller.TenantID == "" || caller.WorkspaceID == "" || caller.PrincipalID == "" || caller.EpisodeID == "" || caller.WorkItemID == "" || caller.OrganizationVersionID == "" {
		http.Error(w, "worker episode identity required", http.StatusUnauthorized)
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var req envelope
	if err := strictJSON(body, &req); err != nil || req.JSONRPC != "2.0" || req.Method == "" || (len(req.ID) > 0 && !validRequestID(req.ID)) {
		rpcError(w, http.StatusBadRequest, nil, -32600, "invalid JSON-RPC request")
		return
	}
	if len(req.ID) == 0 {
		switch req.Method {
		case "notifications/initialized", "notifications/cancelled":
			w.WriteHeader(http.StatusAccepted)
		default:
			rpcError(w, http.StatusBadRequest, nil, -32600, "requests require an id")
		}
		return
	}
	switch req.Method {
	case "initialize":
		var params struct {
			ProtocolVersion string          `json:"protocolVersion"`
			Capabilities    json.RawMessage `json:"capabilities"`
			ClientInfo      json.RawMessage `json:"clientInfo"`
			Meta            json.RawMessage `json:"_meta,omitempty"`
		}
		if strictJSON(req.Params, &params) != nil || params.ProtocolVersion == "" {
			rpcError(w, http.StatusOK, req.ID, -32602, "invalid initialize parameters")
			return
		}
		version := params.ProtocolVersion
		if !supportedVersion(version) {
			version = "2025-11-25"
		}
		build := h.Version
		if build == "" {
			build = "development"
		}
		rpcResult(w, req.ID, map[string]any{"protocolVersion": version, "capabilities": map[string]any{"tools": map[string]any{"listChanged": false}}, "serverInfo": map[string]string{"name": "helm-gateway", "version": build}})
	case "ping":
		rpcResult(w, req.ID, map[string]any{})
	case "tools/list":
		var params struct {
			Cursor string          `json:"cursor,omitempty"`
			Meta   json.RawMessage `json:"_meta,omitempty"`
		}
		if len(req.Params) > 0 && (strictJSON(req.Params, &params) != nil || params.Cursor != "") {
			rpcError(w, http.StatusOK, req.ID, -32602, "invalid tools/list parameters")
			return
		}
		tools, err := h.Backend.Tools(r.Context(), caller)
		if err != nil {
			backendError(w, req.ID, err)
			return
		}
		if tools == nil {
			tools = []Tool{}
		}
		sort.Slice(tools, func(i, j int) bool { return tools[i].Name < tools[j].Name })
		rpcResult(w, req.ID, map[string]any{"tools": tools})
	case "tools/call":
		var params struct {
			Name      string          `json:"name"`
			Arguments json.RawMessage `json:"arguments"`
			Meta      json.RawMessage `json:"_meta,omitempty"`
		}
		if strictJSON(req.Params, &params) != nil || params.Name == "" || len(params.Arguments) == 0 || params.Arguments[0] != '{' {
			rpcError(w, http.StatusOK, req.ID, -32602, "invalid tools/call parameters")
			return
		}
		result, err := h.Backend.Call(r.Context(), caller, Call{RequestID: req.ID, Name: params.Name, Arguments: params.Arguments})
		if err != nil {
			backendError(w, req.ID, err)
			return
		}
		text, err := json.Marshal(result.StructuredContent)
		if err != nil {
			rpcError(w, http.StatusOK, req.ID, -32603, "gateway result unavailable")
			return
		}
		rpcResult(w, req.ID, map[string]any{"content": []map[string]string{{"type": "text", "text": string(text)}}, "structuredContent": result.StructuredContent, "isError": result.IsError})
	default:
		rpcError(w, http.StatusOK, req.ID, -32601, "method not found")
	}
}

func supportedVersion(v string) bool {
	return v == "2025-03-26" || v == "2025-06-18" || v == "2025-11-25"
}

func validOrigin(r *http.Request) bool {
	values := r.Header.Values("Origin")
	if len(values) == 0 {
		return true
	}
	if len(values) != 1 {
		return false
	}
	u, err := url.Parse(values[0])
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return err == nil && u.Scheme == scheme && strings.EqualFold(u.Host, r.Host) && u.Host != "" && u.User == nil && u.Path == "" && u.RawQuery == "" && u.Fragment == ""
}

func accepts(header, want string) bool {
	for _, value := range strings.Split(header, ",") {
		kind, params, err := mime.ParseMediaType(strings.TrimSpace(value))
		if err == nil && kind == want && params["q"] != "0" {
			return true
		}
	}
	return false
}

func validRequestID(raw []byte) bool {
	var id any
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	if d.Decode(&id) != nil {
		return false
	}
	switch v := id.(type) {
	case string:
		return v != "" && len(v) <= 128
	case json.Number:
		_, err := v.Int64()
		return err == nil
	}
	return false
}

func strictJSON(raw []byte, dst any) error {
	if !utf8.Valid(raw) || uniqueJSON(raw) != nil {
		return errors.New("invalid JSON")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(dst); err != nil {
		return err
	}
	return nil
}

// uniqueJSON refuses duplicate keys at every depth and limits nesting before
// the ordinary decoder allocates the request structures.
func uniqueJSON(raw []byte) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var value func(int) error
	value = func(depth int) error {
		if depth > 64 {
			return errors.New("JSON nesting exceeds its bound")
		}
		t, err := d.Token()
		if err != nil {
			return err
		}
		open, ok := t.(json.Delim)
		if !ok {
			return nil
		}
		keys := map[string]bool{}
		for d.More() {
			if open == '{' {
				key, err := d.Token()
				name, ok := key.(string)
				if err != nil || !ok || keys[name] {
					return errors.New("duplicate or invalid JSON key")
				}
				keys[name] = true
			}
			if err := value(depth + 1); err != nil {
				return err
			}
		}
		_, err = d.Token()
		return err
	}
	if err := value(0); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return errors.New("extra JSON value")
	}
	return nil
}

func backendError(w http.ResponseWriter, id json.RawMessage, err error) {
	var refusal *admission.Error
	if errors.As(err, &refusal) && refusal.Code == admission.CodeInvalidArgument {
		rpcError(w, http.StatusOK, id, -32602, "tool parameters refused")
		return
	}
	rpcError(w, http.StatusOK, id, -32603, "gateway call unavailable")
}

func rpcResult(w http.ResponseWriter, id json.RawMessage, result any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": id, "result": result})
}

func rpcError(w http.ResponseWriter, status int, id json.RawMessage, code int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": id, "error": map[string]any{"code": code, "message": message}})
}
