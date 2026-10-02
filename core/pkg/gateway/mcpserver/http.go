// Package mcpserver serves the effect gateway to episode workers as MCP tools,
// over Streamable HTTP (docs/architecture/gateway-mcp.md). It carries no
// provider credential and no authority store of its own: a tool call is an
// effect proposal, admitted, dispatched and observed by the same admission
// service as every other effect, under the verified identity of the worker's
// token.
//
// The server is stateless and speaks two eras at once, as a dual-era server may
// (MCP versioning, "Backward Compatibility with Initialization-Based Versions"):
//
//   - 2026-07-28: no handshake and no session. Every request carries its
//     protocol version in _meta and in the MCP-Protocol-Version header, which
//     must agree, and the Mcp-Method (and, for tools/call, Mcp-Name) header,
//     which must match the body. server/discover answers what the server is.
//   - 2025-03-26 to 2025-11-25: the initialize handshake. Nothing is kept from
//     it. The server mints a random session id for the client to send back, which
//     is transport metadata only and is never looked up, and serves each request
//     on its own.
//
// This file is the protocol; gateway.go is what the tools do.
//
// quantum_posture: a session id is 128 random bits from crypto/rand that only
// correlates legacy transport requests; nothing here signs or verifies, and no
// post-quantum claim is made.
package mcpserver

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"connectrpc.com/connect"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/admission"
)

// The protocol revisions this server speaks.
const (
	// ProtocolModern is the stateless revision.
	ProtocolModern = "2026-07-28"
)

// legacyProtocols are the initialization-based revisions, newest first.
var legacyProtocols = []string{"2025-11-25", "2025-06-18", "2025-03-26"}

// supportedProtocols lists every revision, newest first: what an
// UnsupportedProtocolVersion error and server/discover tell a client.
func supportedProtocols() []string { return append([]string{ProtocolModern}, legacyProtocols...) }

// The per-request _meta keys of the stateless revision.
const (
	metaProtocolVersion    = "io.modelcontextprotocol/protocolVersion"
	metaClientCapabilities = "io.modelcontextprotocol/clientCapabilities"
	metaServerInfo         = "io.modelcontextprotocol/serverInfo"
)

// JSON-RPC and MCP error codes. The codes from -32020 up are the ones the
// 2026-07-28 revision reserves for itself; no other code in -32000..-32099 is
// used.
const (
	codeParse              = -32700
	codeInvalidRequest     = -32600
	codeMethodNotFound     = -32601
	codeInvalidParams      = -32602
	codeInternal           = -32603
	codeHeaderMismatch     = -32020
	codeUnsupportedVersion = -32022
)

// Caller is supplied by the worker listener's verified identity. None of these
// fields is accepted from a request.
type Caller struct {
	// Caller is the token's tenant, workspace, principal, actor and episode.
	admission.Caller
	// Scope is the token's one scope: helm.gateway.propose or helm.gateway.read.
	Scope string
}

// Authenticate verifies a request's credentials and returns the identity they
// carry, or a Connect error whose code says why not (unauthenticated,
// permission denied, unavailable).
type Authenticate func(context.Context, http.Header) (Caller, error)

// Tool is one entry of tools/list.
type Tool struct {
	Name        string          `json:"name"`
	Description string          `json:"description,omitempty"`
	InputSchema json.RawMessage `json:"inputSchema"`
	// Annotations are hints to the client about the tool (the MCP
	// ToolAnnotations): they change nothing the gateway enforces.
	Annotations map[string]any `json:"annotations,omitempty"`
}

// Call is one tools/call, as the transport parsed it.
type Call struct {
	// RequestID is the JSON-RPC id, as a valid string or integer literal.
	RequestID json.RawMessage
	// Session is the id this server minted when the client initialized, for the
	// eras that have an initialize handshake, or "" (the stateless revision keeps
	// none, and a client that sends a value that is not one of ours has none). It
	// names nothing the server remembers: it only tells two sessions of one
	// episode apart, so a client that restarts its request ids in every session
	// does not make its calls one.
	Session string
	Name    string
	// Arguments is the call's arguments object, byte for byte as the client
	// sent it.
	Arguments json.RawMessage
}

// Result separates a domain outcome from a transport or protocol failure.
// ESCALATED is a successful result with IsError false.
type Result struct {
	StructuredContent map[string]any
	IsError           bool
}

// Errors a Backend returns for a failure that is the client's, not the
// gateway's. Any other error is an internal failure and the client is told to
// retry.
var (
	// ErrUnknownTool: no such tool, a protocol error (-32602).
	ErrUnknownTool = errors.New("unknown tool")
	// ErrForbidden: the principal may not use this endpoint at all (HTTP 403).
	ErrForbidden = errors.New("this principal may not use the worker endpoint")
)

// Backend is what the tools do. It uses the same registered effects, admission
// transaction, permits and observations as the effect API, and rechecks the
// caller's current authority on every call.
type Backend interface {
	Tools(context.Context, Caller) ([]Tool, error)
	Call(context.Context, Caller, Call) (Result, error)
}

// Handler serves the MCP endpoint.
type Handler struct {
	Authenticate Authenticate
	Backend      Backend
	// Version is the build the server reports as its own; empty reports
	// "development".
	Version string
	// CallTimeout bounds a tools/call: its ledger steps run to their end even if
	// the client hangs up, so a permit that was issued is never left unclaimed,
	// and the response may take this long to write. Zero is five minutes.
	CallTimeout time.Duration
}

// MaxRequestBytes bounds one JSON-RPC envelope before authentication and
// decoding. The admission layer separately bounds the effect's arguments.
const MaxRequestBytes = 256 << 10

// defaultCallTimeout covers a dispatch (two minutes by default) and its
// read-back with room to spare.
const defaultCallTimeout = 5 * time.Minute

// instructions is what the server tells the model about itself, in discovery.
const instructions = "These tools propose effects to the HELM gateway under this seat's mandates. " +
	"A result with status \"escalated\" needs a human approval: stop and report it. " +
	"A result with status \"reconciling\" is still being confirmed: read it again with helm_attempt_get. " +
	"A result with isError true did not happen, and its reason_code says why."

type envelope struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

// failure is a protocol-level error: what the client gets in place of a result.
type failure struct {
	status  int
	code    int
	message string
	data    any
}

func (h *Handler) callTimeout() time.Duration {
	if h.CallTimeout > 0 {
		return h.CallTimeout
	}
	return defaultCallTimeout
}

func (h *Handler) build() string {
	if h.Version != "" {
		return h.Version
	}
	return "development"
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !validOrigin(r) {
		http.Error(w, "invalid MCP origin", http.StatusForbidden)
		return
	}
	// There is no GET stream and no session to delete: the server speaks only
	// when spoken to.
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "the MCP endpoint takes POST only", http.StatusMethodNotAllowed)
		return
	}
	kind, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || kind != "application/json" || (r.Header.Get("Content-Encoding") != "" && r.Header.Get("Content-Encoding") != "identity") {
		http.Error(w, "MCP requires an uncompressed JSON request", http.StatusUnsupportedMediaType)
		return
	}
	if !accepts(r.Header.Get("Accept"), "application/json") || !accepts(r.Header.Get("Accept"), "text/event-stream") {
		http.Error(w, "MCP requires JSON and event-stream response support", http.StatusNotAcceptable)
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, MaxRequestBytes))
	if err != nil {
		http.Error(w, "MCP request exceeds its bound", http.StatusRequestEntityTooLarge)
		return
	}
	if h.Authenticate == nil || h.Backend == nil {
		http.Error(w, "gateway unavailable", http.StatusServiceUnavailable)
		return
	}

	// What the request itself has to satisfy comes before any credential is
	// looked at: none of it reads a row.
	var req envelope
	if fail := parseEnvelope(body, &req); fail != nil {
		writeFailure(w, nil, fail)
		return
	}
	modern, fail := classify(req, r.Header)
	if fail != nil {
		writeFailure(w, idOf(req), fail)
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
	if caller.TenantID == "" || caller.WorkspaceID == "" || caller.PrincipalID == "" || caller.Episode == nil {
		http.Error(w, "worker episode identity required", http.StatusForbidden)
		return
	}

	if len(req.ID) == 0 {
		// A notification: nothing in either era asks the server to act on one.
		switch req.Method {
		case "notifications/initialized", "notifications/cancelled":
			w.WriteHeader(http.StatusAccepted)
		default:
			writeFailure(w, nil, &failure{http.StatusBadRequest, codeInvalidRequest, "requests require an id", nil})
		}
		return
	}
	h.serve(w, r, req, modern, caller)
}

// serve answers one request of either era.
func (h *Handler) serve(w http.ResponseWriter, r *http.Request, req envelope, modern bool, caller Caller) {
	id := req.ID
	switch {
	case req.Method == "initialize":
		h.initialize(w, req)
	case req.Method == "ping" && !modern:
		writeResult(w, id, map[string]any{})
	case req.Method == "server/discover" && modern:
		var params struct {
			Meta json.RawMessage `json:"_meta"`
		}
		if strictJSON(req.Params, &params) != nil {
			writeFailure(w, id, invalidParams(http.StatusOK, "invalid server/discover parameters"))
			return
		}
		writeResult(w, id, h.modernResult(map[string]any{
			"supportedVersions": supportedProtocols(),
			"capabilities":      capabilities(),
			"instructions":      instructions,
			// What the server is does not depend on who asks.
			"ttlMs": 300000, "cacheScope": "public",
		}))
	case req.Method == "tools/list":
		var params struct {
			Cursor string          `json:"cursor,omitempty"`
			Meta   json.RawMessage `json:"_meta,omitempty"`
		}
		if len(req.Params) > 0 && (strictJSON(req.Params, &params) != nil || params.Cursor != "") {
			writeFailure(w, id, invalidParams(http.StatusOK, "invalid tools/list parameters"))
			return
		}
		tools, err := h.Backend.Tools(r.Context(), caller)
		if err != nil {
			h.backendFailure(w, id, err)
			return
		}
		if tools == nil {
			tools = []Tool{}
		}
		// A deterministic order lets a client cache the list and its model
		// keep a stable prompt prefix.
		sort.Slice(tools, func(i, j int) bool { return tools[i].Name < tools[j].Name })
		result := map[string]any{"tools": tools}
		if modern {
			// The list varies with the caller's mandates, so it is private to
			// the credential that asked, and short-lived: the mandates change.
			result["ttlMs"], result["cacheScope"] = 60000, "private"
			result = h.modernResult(result)
		}
		writeResult(w, id, result)
	case req.Method == "tools/call":
		var params struct {
			Name      string          `json:"name"`
			Arguments json.RawMessage `json:"arguments"`
			Meta      json.RawMessage `json:"_meta,omitempty"`
		}
		if strictJSON(req.Params, &params) != nil || params.Name == "" {
			writeFailure(w, id, invalidParams(http.StatusOK, "invalid tools/call parameters"))
			return
		}
		if len(params.Arguments) == 0 {
			params.Arguments = json.RawMessage(`{}`)
		}
		if params.Arguments[0] != '{' {
			writeFailure(w, id, invalidParams(http.StatusOK, "tool arguments must be an object"))
			return
		}
		// From here the ledger steps run to their end whether or not the client
		// stays, and the response gets the time they may take.
		_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(h.callTimeout() + time.Minute))
		ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), h.callTimeout())
		defer cancel()
		call := Call{RequestID: id, Name: params.Name, Arguments: params.Arguments}
		if !modern {
			call.Session = sessionID(r.Header)
		}
		result, err := h.Backend.Call(ctx, caller, call)
		if err != nil {
			h.backendFailure(w, id, err)
			return
		}
		text, err := json.Marshal(result.StructuredContent)
		if err != nil {
			writeFailure(w, id, &failure{http.StatusOK, codeInternal, "gateway result unavailable", nil})
			return
		}
		// The text is the structured result serialized, which older clients
		// read instead of structuredContent.
		out := map[string]any{"content": []map[string]string{{"type": "text", "text": string(text)}},
			"structuredContent": result.StructuredContent, "isError": result.IsError}
		if modern {
			out = h.modernResult(out)
		}
		writeResult(w, id, out)
	default:
		status := http.StatusOK
		if modern {
			status = http.StatusNotFound
		}
		writeFailure(w, id, &failure{status, codeMethodNotFound, "method not found", nil})
	}
}

// initialize is the handshake of the legacy revisions. Nothing is kept from it.
func (h *Handler) initialize(w http.ResponseWriter, req envelope) {
	var params struct {
		ProtocolVersion string          `json:"protocolVersion"`
		Capabilities    json.RawMessage `json:"capabilities"`
		ClientInfo      json.RawMessage `json:"clientInfo"`
		Meta            json.RawMessage `json:"_meta,omitempty"`
	}
	if strictJSON(req.Params, &params) != nil || params.ProtocolVersion == "" {
		writeFailure(w, req.ID, invalidParams(http.StatusOK, "invalid initialize parameters"))
		return
	}
	// The version the client asks for, if it is one of ours and initialization
	// based; otherwise the newest of those, which the client may accept or leave.
	version := legacyProtocols[0]
	if slices.Contains(legacyProtocols, params.ProtocolVersion) {
		version = params.ProtocolVersion
	}
	w.Header().Set("Mcp-Session-Id", newSessionID())
	writeResult(w, req.ID, map[string]any{
		"protocolVersion": version, "capabilities": capabilities(),
		"serverInfo":   map[string]string{"name": "helm-gateway", "version": h.build()},
		"instructions": instructions,
	})
}

// sessionIDPattern is a session id as newSessionID makes it, base64url of 16
// random bytes.
var sessionIDPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{22}$`)

// newSessionID is a fresh id for a client that initialized.
func newSessionID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("mcpserver: no randomness: " + err.Error()) // crypto/rand does not fail on a healthy host
	}
	return base64.RawURLEncoding.EncodeToString(b[:])
}

// sessionID is the session a request names, or "" when it names none or one that
// is not shaped like ours.
func sessionID(h http.Header) string {
	if id := h.Get("Mcp-Session-Id"); sessionIDPattern.MatchString(id) {
		return id
	}
	return ""
}

func capabilities() map[string]any {
	// listChanged is false: the set of tools is a function of the credential,
	// and there is no stream to tell a client it changed.
	return map[string]any{"tools": map[string]any{"listChanged": false}}
}

// modernResult makes m a complete 2026-07-28 result: every result carries its
// type, and the server names itself.
func (h *Handler) modernResult(m map[string]any) map[string]any {
	m["resultType"] = "complete"
	m["_meta"] = map[string]any{metaServerInfo: map[string]string{"name": "helm-gateway", "version": h.build()}}
	return m
}

// backendFailure answers an error a Backend returned.
func (h *Handler) backendFailure(w http.ResponseWriter, id json.RawMessage, err error) {
	switch {
	case errors.Is(err, ErrForbidden):
		http.Error(w, "the worker endpoint serves agent principals of the token's tenant only", http.StatusForbidden)
	case errors.Is(err, ErrUnknownTool):
		writeFailure(w, id, invalidParams(http.StatusOK, "unknown tool"))
	default:
		writeFailure(w, id, &failure{http.StatusOK, codeInternal, "the gateway could not evaluate the call; repeat it", nil})
	}
}

// parseEnvelope reads the one JSON-RPC request or notification a POST carries.
// A response, a batch or anything else is not one.
func parseEnvelope(body []byte, req *envelope) *failure {
	if !json.Valid(body) {
		return &failure{http.StatusBadRequest, codeParse, "parse error", nil}
	}
	if err := strictJSON(body, req); err != nil || req.JSONRPC != "2.0" || req.Method == "" || (len(req.ID) > 0 && !validRequestID(req.ID)) {
		return &failure{http.StatusBadRequest, codeInvalidRequest, "invalid JSON-RPC request", nil}
	}
	return nil
}

// classify decides which era a request speaks, and checks what that era asks
// of the request itself, before any credential is looked at. It reports true
// for the stateless revision.
func classify(req envelope, header http.Header) (modern bool, _ *failure) {
	version := header.Get("MCP-Protocol-Version")
	if version != "" && !slices.Contains(supportedProtocols(), version) {
		return false, &failure{http.StatusBadRequest, codeUnsupportedVersion, "Unsupported protocol version",
			map[string]any{"supported": supportedProtocols(), "requested": version}}
	}
	switch {
	case req.Method == "initialize":
		// The handshake is the legacy revisions' own; the stateless one has none.
		if version == ProtocolModern {
			return false, &failure{http.StatusNotFound, codeMethodNotFound, "method not found", nil}
		}
		return false, nil
	case version == ProtocolModern:
		return true, modernRequest(req, header, version)
	}
	// No header, or a legacy revision's. A request that says, in its body, that
	// it is stateless and does not say so in its header is a mismatch, not a
	// legacy request: serving it as one would hide the error.
	if mentionsModernVersion(req.Params) {
		return false, headerMismatch("the body names protocol version %s and the MCP-Protocol-Version header does not match it", ProtocolModern)
	}
	return false, nil
}

// modernRequest checks a 2026-07-28 request: its per-request _meta, and that the
// headers mirror the body.
func modernRequest(req envelope, header http.Header, version string) *failure {
	var params struct {
		Meta map[string]json.RawMessage `json:"_meta"`
		Name string                     `json:"name"`
	}
	if len(req.Params) == 0 || json.Unmarshal(req.Params, &params) != nil || params.Meta == nil {
		return invalidParams(http.StatusBadRequest, "_meta with the protocol version and client capabilities is required")
	}
	var metaVersion string
	if json.Unmarshal(params.Meta[metaProtocolVersion], &metaVersion) != nil || metaVersion == "" {
		return invalidParams(http.StatusBadRequest, "_meta must carry "+metaProtocolVersion)
	}
	capabilities := bytes.TrimSpace(params.Meta[metaClientCapabilities])
	if len(capabilities) == 0 || capabilities[0] != '{' {
		return invalidParams(http.StatusBadRequest, "_meta must carry "+metaClientCapabilities+" as an object")
	}
	if metaVersion != version {
		return headerMismatch("the MCP-Protocol-Version header %q does not match the body's %q", version, metaVersion)
	}
	if header.Get("Mcp-Method") != req.Method {
		return headerMismatch("the Mcp-Method header does not match the body's method")
	}
	if req.Method == "tools/call" {
		if name, ok := headerValue(header.Get("Mcp-Name")); !ok || name != params.Name {
			return headerMismatch("the Mcp-Name header does not match the body's tool name")
		}
	}
	return nil
}

// mentionsModernVersion reports whether params carry the stateless revision's
// protocol version in _meta.
func mentionsModernVersion(params json.RawMessage) bool {
	var p struct {
		Meta map[string]json.RawMessage `json:"_meta"`
	}
	if json.Unmarshal(params, &p) != nil {
		return false
	}
	_, ok := p.Meta[metaProtocolVersion]
	return ok
}

// headerValue reads a mirrored header value, decoding the Base64 sentinel form
// a value that is not plain ASCII travels in (=?base64?...?=).
func headerValue(v string) (string, bool) {
	const prefix, suffix = "=?base64?", "?="
	if !strings.HasPrefix(v, prefix) || !strings.HasSuffix(v, suffix) || len(v) < len(prefix)+len(suffix) {
		return v, v != ""
	}
	raw, err := base64.StdEncoding.DecodeString(v[len(prefix) : len(v)-len(suffix)])
	if err != nil || !utf8.Valid(raw) {
		return "", false
	}
	return string(raw), true
}

func headerMismatch(format string, args ...any) *failure {
	return &failure{http.StatusBadRequest, codeHeaderMismatch, "Header mismatch: " + fmt.Sprintf(format, args...), nil}
}

func invalidParams(status int, message string) *failure {
	return &failure{status, codeInvalidParams, message, nil}
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

// validRequestID: a string of 1 to 128 bytes or an integer, never null.
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

// idOf is the id to answer with: the request's when it is a valid one, else
// null.
func idOf(req envelope) json.RawMessage {
	if len(req.ID) > 0 && validRequestID(req.ID) {
		return req.ID
	}
	return nil
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

func writeResult(w http.ResponseWriter, id json.RawMessage, result any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": id, "result": result})
}

func writeFailure(w http.ResponseWriter, id json.RawMessage, f *failure) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(f.status)
	e := map[string]any{"code": f.code, "message": f.message}
	if f.data != nil {
		e["data"] = f.data
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": id, "error": e})
}
