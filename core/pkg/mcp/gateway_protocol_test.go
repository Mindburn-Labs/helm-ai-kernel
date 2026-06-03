package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/artifacts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/bridge"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/budget"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/guardian"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/prg"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/proofgraph"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGateway_StreamableInitializeNegotiatesProtocol(t *testing.T) {
	mux := newProtocolTestMux(t, GatewayConfig{}, nil)

	rec := performJSONRPCRequest(t, mux, http.MethodPost, "/mcp", map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "initialize",
		"params": map[string]any{
			"protocolVersion": LatestProtocolVersion,
		},
	}, nil)

	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, LatestProtocolVersion, rec.Header().Get("MCP-Protocol-Version"))

	var payload map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &payload))

	result := payload["result"].(map[string]any)
	assert.Equal(t, LatestProtocolVersion, result["protocolVersion"])

	serverInfo := result["serverInfo"].(map[string]any)
	assert.Equal(t, "helm-governance", serverInfo["name"])

	capabilities := result["capabilities"].(map[string]any)
	toolsCaps := capabilities["tools"].(map[string]any)
	assert.Equal(t, true, toolsCaps["listChanged"])
}

func TestGateway_StreamableGETReturnsSSEPrimer(t *testing.T) {
	mux := newProtocolTestMux(t, GatewayConfig{}, nil)

	req := httptest.NewRequest(http.MethodGet, "/mcp", nil)
	req.Header.Set("Accept", "text/event-stream")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Header().Get("Content-Type"), "text/event-stream")
	assert.Contains(t, rec.Body.String(), "id: 0")
}

func TestGateway_ToolsListIncludesStructuredToolMetadata(t *testing.T) {
	mux := newProtocolTestMux(t, GatewayConfig{}, nil)

	rec := performJSONRPCRequest(t, mux, http.MethodPost, "/mcp", map[string]any{
		"jsonrpc": "2.0",
		"id":      2,
		"method":  "tools/list",
	}, map[string]string{
		"MCP-Protocol-Version": LatestProtocolVersion,
	})

	require.Equal(t, http.StatusOK, rec.Code)

	var payload map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &payload))

	result := payload["result"].(map[string]any)
	tools := result["tools"].([]any)
	require.NotEmpty(t, tools)

	var fileRead map[string]any
	for _, raw := range tools {
		tool := raw.(map[string]any)
		if tool["name"] == "file_read" {
			fileRead = tool
			break
		}
	}
	require.NotNil(t, fileRead)
	assert.Equal(t, "Read File", fileRead["title"])
	assert.NotNil(t, fileRead["inputSchema"])
	assert.NotNil(t, fileRead["outputSchema"])

	annotations := fileRead["annotations"].(map[string]any)
	assert.Equal(t, true, annotations["readOnlyHint"])
	assert.Equal(t, true, annotations["idempotentHint"])
}

func TestGateway_ToolsListIncludesRequiredScopes(t *testing.T) {
	mux := newScopedProtocolTestMux(t, nil)

	rec := performJSONRPCRequest(t, mux, http.MethodPost, "/mcp", map[string]any{
		"jsonrpc": "2.0",
		"id":      20,
		"method":  "tools/list",
	}, map[string]string{
		"MCP-Protocol-Version": LatestProtocolVersion,
	})

	require.Equal(t, http.StatusOK, rec.Code)

	var payload map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &payload))
	result := payload["result"].(map[string]any)
	tools := result["tools"].([]any)
	require.Len(t, tools, 1)

	tool := tools[0].(map[string]any)
	assert.Equal(t, "scoped_tool", tool["name"])
	assert.Equal(t, []any{"mcp:tool:scoped"}, tool["requiredScopes"])
}

func TestGateway_ToolsCallReturnsStructuredContent(t *testing.T) {
	exec := func(_ context.Context, _ ToolExecutionRequest) (ToolExecutionResponse, error) {
		structured := map[string]any{
			"path":       "/tmp/demo.txt",
			"text":       "hello",
			"size_bytes": 5,
		}
		return ToolExecutionResponse{
			Content:           "hello",
			ContentItems:      StructuredTextContent(structured, "hello"),
			StructuredContent: structured,
			ReceiptID:         "rec_demo",
		}, nil
	}
	mux := newProtocolTestMux(t, GatewayConfig{}, exec)

	rec := performJSONRPCRequest(t, mux, http.MethodPost, "/mcp", map[string]any{
		"jsonrpc": "2.0",
		"id":      3,
		"method":  "tools/call",
		"params": map[string]any{
			"name":      "file_read",
			"arguments": map[string]any{"path": "/tmp/demo.txt"},
		},
	}, map[string]string{
		"MCP-Protocol-Version": LatestProtocolVersion,
	})

	require.Equal(t, http.StatusOK, rec.Code)

	var payload map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &payload))

	result := payload["result"].(map[string]any)
	assert.Equal(t, "rec_demo", result["receipt_id"])

	structured := result["structuredContent"].(map[string]any)
	assert.Equal(t, "/tmp/demo.txt", structured["path"])
	assert.Equal(t, "hello", structured["text"])

	content := result["content"].([]any)
	require.NotEmpty(t, content)
	textItem := content[0].(map[string]any)
	assert.Equal(t, "text", textItem["type"])
	assert.Contains(t, textItem["text"], "\"path\": \"/tmp/demo.txt\"")
}

func TestGateway_ToolsCallRejectsMissingRequiredOAuthScope(t *testing.T) {
	exec := func(_ context.Context, _ ToolExecutionRequest) (ToolExecutionResponse, error) {
		return ToolExecutionResponse{Content: "ok"}, nil
	}
	mux := newScopedProtocolTestMux(t, exec)

	rec := performJSONRPCRequest(t, mux, http.MethodPost, "/mcp", map[string]any{
		"jsonrpc": "2.0",
		"id":      21,
		"method":  "tools/call",
		"params": map[string]any{
			"name": "scoped_tool",
		},
	}, map[string]string{
		"MCP-Protocol-Version": LatestProtocolVersion,
	})

	require.Equal(t, http.StatusOK, rec.Code)

	var payload map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &payload))
	errPayload := payload["error"].(map[string]any)
	assert.Equal(t, float64(-32001), errPayload["code"])
	assert.Contains(t, errPayload["message"], "mcp:tool:scoped")
}

func TestGateway_RESTExecuteEnforcesRequiredOAuthScope(t *testing.T) {
	exec := func(_ context.Context, req ToolExecutionRequest) (ToolExecutionResponse, error) {
		assert.Equal(t, "scoped_tool", req.ToolName)
		assert.Equal(t, []string{"mcp:tool:scoped"}, req.RequiredScopes)
		assert.Equal(t, []string{"mcp:tool:scoped"}, req.OAuthScopes)
		assert.Equal(t, []string{"http://localhost/mcp"}, req.OAuthResources)
		return ToolExecutionResponse{Content: "ok"}, nil
	}
	mux := newScopedProtocolTestMux(t, exec)

	body, err := json.Marshal(MCPToolCallRequest{Method: "scoped_tool"})
	require.NoError(t, err)

	missingReq := httptest.NewRequest(http.MethodPost, "/mcp/v1/execute", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, missingReq)

	require.Equal(t, http.StatusForbidden, rec.Code)
	assert.Contains(t, rec.Body.String(), "MCP.OAUTH.INSUFFICIENT_SCOPE")

	allowedReq := httptest.NewRequest(http.MethodPost, "/mcp/v1/execute", bytes.NewReader(body))
	allowedReq = allowedReq.WithContext(WithOAuthAuthorization(allowedReq.Context(), OAuthAuthorization{
		Scopes:    []string{"mcp:tool:scoped"},
		Resources: []string{"http://localhost/mcp"},
	}))
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, allowedReq)

	require.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "ok")
}

func TestGateway_UnsupportedProtocolVersionRejected(t *testing.T) {
	mux := newProtocolTestMux(t, GatewayConfig{}, nil)

	rec := performJSONRPCRequest(t, mux, http.MethodPost, "/mcp", map[string]any{
		"jsonrpc": "2.0",
		"id":      4,
		"method":  "tools/list",
	}, map[string]string{
		"MCP-Protocol-Version": "1999-01-01",
	})

	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, rec.Body.String(), "unsupported MCP protocol version")
}

func TestGateway_OAuthProtectedResourceMetadata(t *testing.T) {
	mux := newProtocolTestMux(t, GatewayConfig{
		BaseURL:  "http://localhost:9100",
		AuthMode: "oauth",
	}, nil)

	req := httptest.NewRequest(http.MethodGet, "/.well-known/oauth-protected-resource/mcp", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)

	var payload map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &payload))
	assert.Equal(t, "http://localhost:9100/mcp", payload["resource"])

	authServers := payload["authorization_servers"].([]any)
	require.Len(t, authServers, 1)
	assert.Equal(t, "http://localhost:9100", authServers[0])
}

func newProtocolTestMux(t *testing.T, cfg GatewayConfig, exec ToolExecutor) *http.ServeMux {
	t.Helper()

	catalog := NewInMemoryCatalog()
	catalog.RegisterCommonTools()

	gw := NewGateway(catalog, cfg)
	if exec != nil {
		WithExecutor(exec)(gw)
	}

	mux := http.NewServeMux()
	gw.RegisterRoutes(mux)
	return mux
}

func newScopedProtocolTestMux(t *testing.T, exec ToolExecutor) *http.ServeMux {
	t.Helper()

	catalog := NewInMemoryCatalog()
	require.NoError(t, catalog.Register(context.Background(), ToolRef{
		Name:           "scoped_tool",
		Description:    "requires a delegated MCP OAuth scope",
		Schema:         map[string]any{"type": "object"},
		RequiredScopes: []string{"mcp:tool:scoped"},
	}))

	gw := NewGateway(catalog, GatewayConfig{})
	if exec != nil {
		WithExecutor(exec)(gw)
	}

	mux := http.NewServeMux()
	gw.RegisterRoutes(mux)
	return mux
}

func performJSONRPCRequest(t *testing.T, mux *http.ServeMux, method, path string, payload map[string]any, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()

	body, err := json.Marshal(payload)
	require.NoError(t, err)

	req := httptest.NewRequest(method, path, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	for key, value := range headers {
		req.Header.Set(key, value)
	}

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec
}

func TestGateway_InitializeIssuesSessionId(t *testing.T) {
	mux := newProtocolTestMux(t, GatewayConfig{}, nil)

	rec := performJSONRPCRequest(t, mux, http.MethodPost, "/mcp", map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "initialize",
		"params": map[string]any{
			"protocolVersion": LatestProtocolVersion,
		},
	}, nil)

	require.Equal(t, http.StatusOK, rec.Code)
	sessionID := rec.Header().Get("MCP-Session-Id")
	assert.NotEmpty(t, sessionID, "initialize must return MCP-Session-Id header")
	assert.Len(t, sessionID, 32, "session ID should be 32 hex characters")
}

func TestGateway_SubsequentRequestAcceptsValidSessionId(t *testing.T) {
	mux := newProtocolTestMux(t, GatewayConfig{}, nil)

	// First: initialize to get a session ID.
	initRec := performJSONRPCRequest(t, mux, http.MethodPost, "/mcp", map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "initialize",
		"params": map[string]any{
			"protocolVersion": LatestProtocolVersion,
		},
	}, nil)
	require.Equal(t, http.StatusOK, initRec.Code)
	sessionID := initRec.Header().Get("MCP-Session-Id")
	require.NotEmpty(t, sessionID)

	// Then: use the session ID for tools/list.
	listRec := performJSONRPCRequest(t, mux, http.MethodPost, "/mcp", map[string]any{
		"jsonrpc": "2.0",
		"id":      2,
		"method":  "tools/list",
	}, map[string]string{
		"MCP-Protocol-Version": LatestProtocolVersion,
		"MCP-Session-Id":       sessionID,
	})

	require.Equal(t, http.StatusOK, listRec.Code)
}

func TestGateway_InvalidSessionIdRejected(t *testing.T) {
	mux := newProtocolTestMux(t, GatewayConfig{}, nil)

	rec := performJSONRPCRequest(t, mux, http.MethodPost, "/mcp", map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "tools/list",
	}, map[string]string{
		"MCP-Protocol-Version": LatestProtocolVersion,
		"MCP-Session-Id":       "bogus-session-id",
	})

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Contains(t, rec.Body.String(), "invalid or expired MCP session")
}

func TestGateway_TransportEdgeBranches(t *testing.T) {
	catalog := NewInMemoryCatalog()
	gateway := NewGateway(catalog, GatewayConfig{})

	nonFlushing := &gatewayNonFlushingWriter{header: http.Header{}}
	req := httptest.NewRequest(http.MethodGet, "/mcp", nil)
	req.Header.Set("Accept", "text/event-stream")
	gateway.handleTransportGET(nonFlushing, req)
	assert.Equal(t, http.StatusInternalServerError, nonFlushing.status)
	assert.Contains(t, nonFlushing.body.String(), "streaming unsupported")

	mux := newProtocolTestMux(t, GatewayConfig{}, nil)
	badJSON := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewBufferString("{"))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, badJSON)
	assert.Equal(t, http.StatusBadRequest, rec.Code)

	initUnsupported := performJSONRPCRequest(t, mux, http.MethodPost, "/mcp", map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "initialize",
		"params": map[string]any{
			"protocolVersion": "1900-01-01",
		},
	}, nil)
	assert.Equal(t, http.StatusBadRequest, initUnsupported.Code)

	notification := performJSONRPCRequest(t, mux, http.MethodPost, "/mcp", map[string]any{
		"jsonrpc": "2.0",
		"method":  "notifications/initialized",
	}, nil)
	assert.Equal(t, http.StatusAccepted, notification.Code)
	assert.Empty(t, notification.Body.String())
}

func TestGateway_RESTExecutePropagatesDelegationHeaders(t *testing.T) {
	exec := func(_ context.Context, req ToolExecutionRequest) (ToolExecutionResponse, error) {
		assert.Equal(t, "file_read", req.ToolName)
		assert.Equal(t, "delegation-1", req.DelegationSessionID)
		assert.Equal(t, "did:example:verifier", req.DelegationVerifier)
		assert.Equal(t, []string{"file_read", "file_write"}, req.DelegationAllowedTools)
		return ToolExecutionResponse{Content: "delegated"}, nil
	}
	mux := newProtocolTestMux(t, GatewayConfig{}, exec)

	body, err := json.Marshal(MCPToolCallRequest{
		Method: "file_read",
		Params: map[string]any{"path": "/tmp/demo.txt"},
	})
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPost, "/mcp/v1/execute", bytes.NewReader(body))
	req.Header.Set("X-HELM-Delegation-Session-ID", "delegation-1")
	req.Header.Set("X-HELM-Delegation-Verifier", "did:example:verifier")
	req.Header.Set("X-HELM-Delegation-Allowed-Tools", " file_read, ,file_write ")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "delegated")
}

func TestGateway_JSONRPCAndSchemaFallbackEdges(t *testing.T) {
	errGateway := NewGateway(errorCatalog{}, GatewayConfig{})
	resp, respond, status := errGateway.handleJSONRPCRequest(context.Background(), 1, "tools/list", nil, LatestProtocolVersion)
	require.True(t, respond)
	assert.Equal(t, http.StatusOK, status)
	assert.Contains(t, marshalMCPTestValue(t, resp), "catalog failed")

	catalog := NewInMemoryCatalog()
	require.NoError(t, catalog.Register(context.Background(), ToolRef{
		Name:           "scoped",
		Description:    "scoped jsonrpc tool",
		Schema:         map[string]any{"type": "object"},
		RequiredScopes: []string{"mcp:tool:scoped"},
	}))
	execGateway := NewGateway(catalog, GatewayConfig{}, WithExecutor(func(_ context.Context, req ToolExecutionRequest) (ToolExecutionResponse, error) {
		assert.Equal(t, []string{"mcp:tool:scoped"}, req.RequiredScopes)
		assert.Equal(t, []string{"mcp:tool:scoped"}, req.OAuthScopes)
		assert.Equal(t, []string{"https://resource.example/mcp"}, req.OAuthResources)
		return ToolExecutionResponse{Content: "ok"}, nil
	}))
	ctx := WithOAuthAuthorization(context.Background(), OAuthAuthorization{
		Scopes:    []string{"mcp:tool:scoped"},
		Resources: []string{"https://resource.example/mcp"},
	})
	resp, respond, status = execGateway.handleJSONRPCRequest(ctx, 2, "tools/call", json.RawMessage(`{"name":"scoped","arguments":{}}`), LatestProtocolVersion)
	require.True(t, respond)
	assert.Equal(t, http.StatusOK, status)
	assert.Contains(t, marshalMCPTestValue(t, resp), "ok")

	schema := catalogSchemaToArgSchema(map[string]any{
		"properties": map[string]any{
			"payload": map[string]any{},
		},
		"required": []any{"payload", 42},
	})
	require.NotNil(t, schema)
	field := schema.Fields["payload"]
	assert.Equal(t, "any", field.Type)
	assert.True(t, field.Required)
}

func TestGateway_RESTExecuteBridgeGovernanceBranches(t *testing.T) {
	catalog := NewInMemoryCatalog()
	require.NoError(t, catalog.Register(context.Background(), ToolRef{
		Name:        "bridge_tool",
		Description: "bridge governed tool",
		Schema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"text": map[string]any{"type": "string"},
			},
			"required": []any{"text"},
		},
	}))
	body, err := json.Marshal(MCPToolCallRequest{
		Method: "bridge_tool",
		Params: map[string]any{"text": "hello"},
	})
	require.NoError(t, err)

	allowGateway := NewGateway(catalog, GatewayConfig{}, WithBridge(newGatewayTestBridge(t, "tenant-allow", nil)))
	rec := httptest.NewRecorder()
	allowGateway.handleExecute(rec, httptest.NewRequest(http.MethodPost, "/mcp/v1/execute", bytes.NewReader(body)))
	require.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "governed_allow")
	assert.Contains(t, rec.Body.String(), "proofgraph_node")

	store := budget.NewMemoryStorage()
	enforcer := budget.NewSimpleEnforcer(store)
	require.NoError(t, enforcer.SetLimits(context.Background(), "tenant-deny", 0, 0))
	denyGateway := NewGateway(catalog, GatewayConfig{}, WithBridge(newGatewayTestBridge(t, "tenant-deny", enforcer)))
	rec = httptest.NewRecorder()
	denyGateway.handleExecute(rec, httptest.NewRequest(http.MethodPost, "/mcp/v1/execute", bytes.NewReader(body)))
	require.Equal(t, http.StatusForbidden, rec.Code)
	assert.Contains(t, rec.Body.String(), "denied by governance")
}

func newGatewayTestBridge(t *testing.T, tenantID string, enforcer budget.Enforcer) *bridge.KernelBridge {
	t.Helper()

	signer, err := crypto.NewEd25519Signer("test-mcp-gateway")
	require.NoError(t, err)
	prgGraph := prg.NewGraph()
	store, err := artifacts.NewFileStore(t.TempDir())
	require.NoError(t, err)
	registry := artifacts.NewRegistry(store, signer)
	return bridge.NewKernelBridge(
		guardian.NewGuardian(signer, prgGraph, registry),
		prgGraph,
		proofgraph.NewGraph(),
		enforcer,
		tenantID,
	)
}

type gatewayNonFlushingWriter struct {
	header http.Header
	status int
	body   bytes.Buffer
}

func (w *gatewayNonFlushingWriter) Header() http.Header {
	return w.header
}

func (w *gatewayNonFlushingWriter) Write(data []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return w.body.Write(data)
}

func (w *gatewayNonFlushingWriter) WriteHeader(statusCode int) {
	w.status = statusCode
}
