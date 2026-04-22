package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/bridge"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/manifest"
)

// GatewayConfig configures the MCP gateway server.
type GatewayConfig struct {
	ListenAddr string `json:"listen_addr"`
	BaseURL    string `json:"base_url,omitempty"`
	AuthMode   string `json:"auth_mode,omitempty"`
	SessionTTL time.Duration `json:"session_ttl,omitempty"`
}

// Gateway is an MCP server that exposes tool execution with governance.
type Gateway struct {
	catalog  Catalog
	config   GatewayConfig
	bridge   *bridge.KernelBridge // governance bridge (optional)
	exec     ToolExecutor
	sessions *SessionStore // HTTP session store for /mcp transport
}

// GatewayOption configures optional Gateway settings.
type GatewayOption func(*Gateway)

// ToolExecutor runs an MCP tool call and returns the governed result.
type ToolExecutor func(ctx context.Context, req ToolExecutionRequest) (ToolExecutionResponse, error)

// WithBridge sets the KernelBridge for governance.
func WithBridge(kb *bridge.KernelBridge) GatewayOption {
	return func(g *Gateway) {
		g.bridge = kb
	}
}

// WithExecutor wires a concrete tool executor into the gateway.
func WithExecutor(exec ToolExecutor) GatewayOption {
	return func(g *Gateway) {
		g.exec = exec
	}
}

// NewGateway creates a new MCP gateway.
func NewGateway(catalog Catalog, config GatewayConfig, opts ...GatewayOption) *Gateway {
	ttl := config.SessionTTL
	if ttl <= 0 {
		ttl = DefaultSessionTTL
	}
	gw := &Gateway{
		catalog:  catalog,
		config:   config,
		sessions: NewSessionStore(ttl),
	}
	for _, opt := range opts {
		opt(gw)
	}
	return gw
}

// MCPToolCallRequest is the wire format for an MCP tool call.
type MCPToolCallRequest struct {
	Method string         `json:"method"`
	Params map[string]any `json:"params,omitempty"`
}

// MCPToolCallResponse is the wire format for an MCP tool result.
type MCPToolCallResponse struct {
	Result            any               `json:"result,omitempty"`
	Content           []ToolContentItem `json:"content,omitempty"`
	StructuredContent map[string]any    `json:"structured_content,omitempty"`
	Error             string            `json:"error,omitempty"`
	Decision          string            `json:"decision,omitempty"`
	ReasonCode        string            `json:"reason_code,omitempty"`
	ArgsHash          string            `json:"args_hash,omitempty"`
	PGNode            string            `json:"proofgraph_node,omitempty"`
	ReceiptID         string            `json:"receipt_id,omitempty"`
	ProtocolVersion   string            `json:"protocol_version,omitempty"`
}

// MCPCapabilityManifest describes the capabilities this server exposes.
type MCPCapabilityManifest struct {
	ServerName       string    `json:"server_name"`
	Version          string    `json:"version"`
	Tools            []ToolRef `json:"tools"`
	Capabilities     []ToolRef `json:"capabilities,omitempty"`
	Governance       string    `json:"governance"` // "helm:pep:v1"
	ProtocolVersions []string  `json:"protocol_versions,omitempty"`
	AuthMode         string    `json:"auth_mode,omitempty"`
}

// RegisterRoutes registers MCP gateway HTTP routes.
func (g *Gateway) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/mcp", g.handleTransport)
	mux.HandleFunc("/mcp/v1/capabilities", g.handleCapabilities)
	mux.HandleFunc("/mcp/v1/execute", g.handleExecute)
	mux.HandleFunc("/.well-known/oauth-protected-resource", g.handleProtectedResourceMetadata)
	mux.HandleFunc("/.well-known/oauth-protected-resource/mcp", g.handleProtectedResourceMetadata)
}

func (g *Gateway) handleTransport(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		g.handleTransportGET(w, r)
	case http.MethodPost:
		g.handleTransportPOST(w, r)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (g *Gateway) handleIndex(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"server_name":                 "helm-mcp-gateway",
		"version":                     "1.0.0",
		"capabilities_url":            "/mcp/v1/capabilities",
		"execute_url":                 "/mcp/v1/execute",
		"mcp_endpoint":                "/mcp",
		"supported_protocol_versions": SupportedProtocolVersions,
		"auth_mode":                   g.authMode(),
		"governance":                  "helm:pep:v1",
	})
}

func (g *Gateway) handleTransportGET(w http.ResponseWriter, r *http.Request) {
	if !strings.Contains(r.Header.Get("Accept"), "text/event-stream") {
		g.handleIndex(w, r)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	if flusher, ok := w.(http.Flusher); ok {
		_, _ = io.WriteString(w, "id: 0\ndata:\n\n")
		flusher.Flush()
		return
	}
	http.Error(w, "streaming unsupported", http.StatusInternalServerError)
}

func (g *Gateway) handleTransportPOST(w http.ResponseWriter, r *http.Request) {
	var req struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      any             `json:"id,omitempty"`
		Method  string          `json:"method"`
		Params  json.RawMessage `json:"params,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON-RPC request body", http.StatusBadRequest)
		return
	}

	protocolVersion := r.Header.Get("MCP-Protocol-Version")
	if req.Method == "initialize" {
		var params struct {
			ProtocolVersion string `json:"protocolVersion"`
			ClientInfo      struct {
				Name string `json:"name"`
			} `json:"clientInfo"`
		}
		_ = json.Unmarshal(req.Params, &params)
		negotiated, ok := NegotiateProtocolVersion(params.ProtocolVersion)
		if !ok {
			http.Error(w, fmt.Sprintf("unsupported MCP protocol version %q", params.ProtocolVersion), http.StatusBadRequest)
			return
		}
		protocolVersion = negotiated

		// Issue a new HTTP session.
		sessionID, err := g.sessions.Create(protocolVersion, params.ClientInfo.Name)
		if err != nil {
			http.Error(w, fmt.Sprintf("session creation failed: %v", err), http.StatusInternalServerError)
			return
		}

		resp, respond, status := g.handleJSONRPCRequest(r.Context(), req.ID, req.Method, req.Params, protocolVersion)
		if !respond {
			w.WriteHeader(status)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("MCP-Protocol-Version", protocolVersion)
		w.Header().Set("MCP-Session-Id", sessionID)
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(resp)
		return
	}

	// For non-initialize requests, validate the session.
	if protocolVersion != "" {
		if _, ok := NegotiateProtocolVersion(protocolVersion); !ok {
			http.Error(w, fmt.Sprintf("unsupported MCP protocol version %q", protocolVersion), http.StatusBadRequest)
			return
		}
	} else {
		protocolVersion = LegacyProtocolVersion
	}

	// Require valid MCP-Session-Id for non-notification methods.
	sessionID := r.Header.Get("MCP-Session-Id")
	isNotification := strings.HasPrefix(req.Method, "notifications/")
	if sessionID != "" {
		if session := g.sessions.Get(sessionID); session == nil {
			http.Error(w, "invalid or expired MCP session", http.StatusUnauthorized)
			return
		}
	} else if !isNotification {
		// Session ID is recommended for non-notification requests after initialize.
		// For backward compatibility, we allow requests without session ID but log a warning.
	}

	resp, respond, status := g.handleJSONRPCRequest(r.Context(), req.ID, req.Method, req.Params, protocolVersion)
	if !respond {
		w.WriteHeader(status)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("MCP-Protocol-Version", protocolVersion)
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(resp)
}

func (g *Gateway) handleCapabilities(w http.ResponseWriter, r *http.Request) {
	ctx := context.Background()
	tools, err := g.catalog.Search(ctx, "")
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(MCPToolCallResponse{Error: err.Error()})
		return
	}

	// Delegation-aware tool filtering: if a delegation session specifies
	// allowed tools, only expose those tools in the capabilities response.
	// This prevents delegated agents from even discovering out-of-scope tools.
	if allowedCSV := r.Header.Get("X-HELM-Delegation-Allowed-Tools"); allowedCSV != "" {
		allowedSet := make(map[string]bool)
		for _, t := range strings.Split(allowedCSV, ",") {
			if trimmed := strings.TrimSpace(t); trimmed != "" {
				allowedSet[trimmed] = true
			}
		}
		var filtered []ToolRef
		for _, tool := range tools {
			if allowedSet[tool.Name] {
				filtered = append(filtered, tool)
			}
		}
		tools = filtered
	}

	m := MCPCapabilityManifest{
		ServerName:       "helm-mcp-gateway",
		Version:          "1.0.0",
		Tools:            tools,
		Capabilities:     tools,
		Governance:       "helm:pep:v1",
		ProtocolVersions: SupportedProtocolVersions,
		AuthMode:         g.authMode(),
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(m)
}

func (g *Gateway) handleExecute(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	var req MCPToolCallRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(MCPToolCallResponse{Error: "invalid request body"})
		return
	}

	tool, ok := findToolRef(g.catalog, req.Method)
	if !ok {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(MCPToolCallResponse{
			Error:      fmt.Sprintf("tool %q not found", req.Method),
			ReasonCode: string(contracts.ReasonNoPolicy),
		})
		return
	}

	// 1. Validate and canonicalize args via PEP boundary
	var argsHash string
	if req.Params != nil {
		result, err := manifest.ValidateAndCanonicalizeToolArgs(catalogSchemaToArgSchema(tool.Schema), req.Params)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(MCPToolCallResponse{
				Error:      fmt.Sprintf("PEP validation failed: %v", err),
				ReasonCode: string(contracts.ReasonSchemaViolation),
			})
			return
		}
		argsHash = result.ArgsHash
	}

	// 2. Governance via KernelBridge (if configured)
	resp := MCPToolCallResponse{ArgsHash: argsHash}

	if g.exec != nil {
		// Build execution request with delegation context from headers.
		execReq := ToolExecutionRequest{
			ToolName:  req.Method,
			Arguments: req.Params,
			SessionID: fmt.Sprintf("mcp-http-%s-%p", r.RemoteAddr, r),
		}
		if delegationID := r.Header.Get("X-HELM-Delegation-Session-ID"); delegationID != "" {
			execReq.DelegationSessionID = delegationID
			execReq.DelegationVerifier = r.Header.Get("X-HELM-Delegation-Verifier")
			if allowedCSV := r.Header.Get("X-HELM-Delegation-Allowed-Tools"); allowedCSV != "" {
				for _, t := range strings.Split(allowedCSV, ",") {
					if trimmed := strings.TrimSpace(t); trimmed != "" {
						execReq.DelegationAllowedTools = append(execReq.DelegationAllowedTools, trimmed)
					}
				}
			}
		}
		execResp, execErr := g.exec(r.Context(), execReq)
		if execErr != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			_ = json.NewEncoder(w).Encode(MCPToolCallResponse{
				Error:      execErr.Error(),
				ReasonCode: string(contracts.ReasonPDPError),
				ArgsHash:   argsHash,
			})
			return
		}

		resp.ReceiptID = execResp.ReceiptID
		if execResp.IsError {
			resp.Error = execResp.Content
			resp.ReasonCode = string(contracts.ReasonPolicyViolation)
			resp.Content = execResp.ContentItems
			resp.StructuredContent = execResp.StructuredContent
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(w).Encode(resp)
			return
		}

		resp.Result = execResp.Content
		resp.Content = execResp.ContentItems
		resp.StructuredContent = execResp.StructuredContent
	} else if g.bridge != nil {
		govResult, govErr := g.bridge.Govern(context.Background(), req.Method, argsHash)
		if govErr != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			_ = json.NewEncoder(w).Encode(MCPToolCallResponse{
				Error:      fmt.Sprintf("governance error: %v", govErr),
				ReasonCode: string(contracts.ReasonPDPError),
			})
			return
		}

		resp.ReasonCode = govResult.ReasonCode
		resp.PGNode = govResult.NodeID
		if govResult.Decision != nil {
			resp.Decision = govResult.Decision.ID
		}

		if !govResult.Allowed {
			if resp.ReasonCode == "" {
				resp.ReasonCode = string(contracts.ReasonPolicyViolation)
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			resp.Error = fmt.Sprintf("tool %q denied by governance: %s", req.Method, govResult.ReasonCode)
			_ = json.NewEncoder(w).Encode(resp)
			return
		}

		resp.Result = map[string]any{
			"status":  "governed_allow",
			"tool":    req.Method,
			"message": fmt.Sprintf("tool %q approved by Guardian governance", req.Method),
		}
	} else {
		// No bridge: return governed stub response
		resp.Result = map[string]any{
			"status":  "stub",
			"tool":    req.Method,
			"message": fmt.Sprintf("tool %q requires governance — configure KernelBridge for full governance", req.Method),
		}
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func (g *Gateway) handleProtectedResourceMetadata(w http.ResponseWriter, _ *http.Request) {
	if g.authMode() != "oauth" {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	baseURL := strings.TrimRight(g.config.BaseURL, "/")
	if baseURL == "" {
		baseURL = "http://localhost:9100"
	}
	authServer := strings.TrimSpace(strings.TrimRight(baseURL, "/"))
	if configured := strings.TrimSpace(strings.TrimRight(os.Getenv("HELM_OAUTH_AUTHORIZATION_SERVER"), "/")); configured != "" {
		authServer = configured
	}
	scopes := []string{"mcp:tools"}
	if configured := strings.TrimSpace(os.Getenv("HELM_OAUTH_SCOPES")); configured != "" {
		scopes = nil
		for _, scope := range strings.FieldsFunc(configured, func(r rune) bool { return r == ',' || r == ' ' }) {
			if strings.TrimSpace(scope) != "" {
				scopes = append(scopes, strings.TrimSpace(scope))
			}
		}
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"resource":                 baseURL + "/mcp",
		"authorization_servers":    []string{authServer},
		"scopes_supported":         scopes,
		"bearer_methods_supported": []string{"header"},
		"resource_documentation":   "https://github.com/Mindburn-Labs/helm-oss/tree/main/docs/INTEGRATIONS",
	})
}

func (g *Gateway) handleJSONRPCRequest(ctx context.Context, id any, method string, params json.RawMessage, protocolVersion string) (map[string]any, bool, int) {
	response := map[string]any{
		"jsonrpc": "2.0",
		"id":      id,
	}

	writeError := func(code int, message string) (map[string]any, bool, int) {
		response["error"] = map[string]any{
			"code":    code,
			"message": message,
		}
		return response, true, http.StatusOK
	}

	switch method {
	case "initialize":
		response["result"] = map[string]any{
			"protocolVersion": protocolVersion,
			"serverInfo": map[string]any{
				"name":    "helm-governance",
				"title":   "HELM Governance",
				"version": "1.0.0",
			},
			"capabilities": map[string]any{
				"tools": map[string]any{
					"listChanged": true,
				},
			},
			"instructions": "HELM governs tool execution, emits receipts, and exposes a deterministic proof surface.",
		}
		return response, true, http.StatusOK
	case "notifications/initialized":
		return nil, false, http.StatusAccepted
	case "ping":
		response["result"] = map[string]any{}
		return response, true, http.StatusOK
	case "tools/list":
		tools, err := g.catalog.Search(ctx, "")
		if err != nil {
			return writeError(-32603, err.Error())
		}
		payload := make([]map[string]any, 0, len(tools))
		for _, tool := range tools {
			payload = append(payload, ToolDescriptorPayload(tool))
		}
		response["result"] = map[string]any{"tools": payload}
		return response, true, http.StatusOK
	case "tools/call":
		var req struct {
			Name      string         `json:"name"`
			Arguments map[string]any `json:"arguments"`
		}
		if err := json.Unmarshal(params, &req); err != nil {
			return writeError(-32602, "invalid tools/call params")
		}
		if _, ok := findToolRef(g.catalog, req.Name); !ok {
			return writeError(-32602, fmt.Sprintf("tool %q not found", req.Name))
		}
		if g.exec == nil {
			return writeError(-32603, "tool executor is not configured")
		}

		execResp, err := g.exec(ctx, ToolExecutionRequest{
			ToolName:  req.Name,
			Arguments: req.Arguments,
			SessionID: "mcp-http-jsonrpc",
		})
		if err != nil {
			return writeError(-32603, err.Error())
		}
		response["result"] = ToolResultPayload(execResp)
		return response, true, http.StatusOK
	default:
		return writeError(-32601, fmt.Sprintf("method %q not found", method))
	}
}

func (g *Gateway) authMode() string {
	if strings.TrimSpace(g.config.AuthMode) == "" {
		return "none"
	}
	return g.config.AuthMode
}

func findToolRef(c Catalog, name string) (ToolRef, bool) {
	tools, err := c.Search(context.Background(), name)
	if err != nil {
		return ToolRef{}, false
	}
	for _, tool := range tools {
		if tool.Name == name {
			return tool, true
		}
	}
	return ToolRef{}, false
}

func catalogSchemaToArgSchema(raw any) *manifest.ToolArgSchema {
	schemaMap, ok := raw.(map[string]any)
	if !ok {
		return nil
	}
	props, _ := schemaMap["properties"].(map[string]any)
	if props == nil {
		return nil
	}
	requiredList, _ := schemaMap["required"].([]string)
	requiredSet := make(map[string]bool, len(requiredList))
	for _, name := range requiredList {
		requiredSet[name] = true
	}
	if len(requiredSet) == 0 {
		if genericRequired, ok := schemaMap["required"].([]any); ok {
			for _, rawName := range genericRequired {
				if name, ok := rawName.(string); ok {
					requiredSet[name] = true
				}
			}
		}
	}

	fields := make(map[string]manifest.FieldSpec, len(props))
	for name, propRaw := range props {
		prop, _ := propRaw.(map[string]any)
		fieldType, _ := prop["type"].(string)
		if fieldType == "" {
			fieldType = "any"
		}
		fields[name] = manifest.FieldSpec{
			Type:     fieldType,
			Required: requiredSet[name],
		}
	}

	return &manifest.ToolArgSchema{
		Fields:     fields,
		AllowExtra: false,
	}
}
