package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/bridge"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/manifest"
)

// GatewayConfig configures the MCP gateway server.
type GatewayConfig struct {
	ListenAddr string `json:"listen_addr"`
}

// Gateway is an MCP server that exposes tool execution with governance.
type Gateway struct {
	catalog Catalog
	config  GatewayConfig
	bridge  *bridge.KernelBridge // governance bridge (optional)
	exec    ToolExecutor
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
	gw := &Gateway{
		catalog: catalog,
		config:  config,
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
	Result     any    `json:"result,omitempty"`
	Error      string `json:"error,omitempty"`
	Decision   string `json:"decision,omitempty"`
	ReasonCode string `json:"reason_code,omitempty"`
	ArgsHash   string `json:"args_hash,omitempty"`
	PGNode     string `json:"proofgraph_node,omitempty"`
	ReceiptID  string `json:"receipt_id,omitempty"`
}

// MCPCapabilityManifest describes the capabilities this server exposes.
type MCPCapabilityManifest struct {
	ServerName   string    `json:"server_name"`
	Version      string    `json:"version"`
	Tools        []ToolRef `json:"tools"`
	Capabilities []ToolRef `json:"capabilities,omitempty"`
	Governance   string    `json:"governance"` // "helm:pep:v1"
}

// RegisterRoutes registers MCP gateway HTTP routes.
func (g *Gateway) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/mcp", g.handleIndex)
	mux.HandleFunc("/mcp/v1/capabilities", g.handleCapabilities)
	mux.HandleFunc("/mcp/v1/execute", g.handleExecute)
}

func (g *Gateway) handleIndex(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"server_name":      "helm-mcp-gateway",
		"version":          "1.0.0",
		"capabilities_url": "/mcp/v1/capabilities",
		"execute_url":      "/mcp/v1/execute",
		"governance":       "helm:pep:v1",
	})
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
		ServerName:   "helm-mcp-gateway",
		Version:      "1.0.0",
		Tools:        tools,
		Capabilities: tools,
		Governance:   "helm:pep:v1",
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
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(w).Encode(resp)
			return
		}

		resp.Result = execResp.Content
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
