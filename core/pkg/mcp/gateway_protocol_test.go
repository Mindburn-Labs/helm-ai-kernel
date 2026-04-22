package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

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
