package main

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	launchpadmcp "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/launchpad/mcp"
	mcppkg "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/mcp"
)

func TestMCPMediationProofTransportsRouteToolCallsThroughExecutor(t *testing.T) {
	catalog := proofCatalog(t)
	var calls []mcppkg.ToolExecutionRequest
	executor := func(_ context.Context, req mcppkg.ToolExecutionRequest) (mcppkg.ToolExecutionResponse, error) {
		calls = append(calls, req)
		return mcppkg.ToolExecutionResponse{Content: "mediated", ReceiptID: "receipt://proof"}, nil
	}

	params, _ := json.Marshal(map[string]any{
		"name":      "proof.echo",
		"arguments": map[string]any{"message": "hello"},
	})
	stdioResp, err := handleMCPRPCRequest(&mcpRPCRequest{
		JSONRPC: "2.0",
		ID:      float64(1),
		Method:  "tools/call",
		Params:  params,
	}, catalog, executor)
	if err != nil {
		t.Fatalf("stdio tools/call: %v", err)
	}
	if stdioResp.Error != nil || len(calls) != 1 || calls[0].ToolName != "proof.echo" {
		t.Fatalf("stdio did not route through executor: resp=%#v calls=%#v", stdioResp, calls)
	}

	gateway := mcppkg.NewGateway(catalog, mcppkg.GatewayConfig{}, mcppkg.WithExecutor(executor))
	mux := http.NewServeMux()
	gateway.RegisterRoutes(mux)

	executeBody, _ := json.Marshal(mcppkg.MCPToolCallRequest{Method: "proof.echo", Params: map[string]any{"message": "hello"}})
	executeReq := httptest.NewRequest(http.MethodPost, "/mcp/v1/execute", bytes.NewReader(executeBody))
	executeRec := httptest.NewRecorder()
	mux.ServeHTTP(executeRec, executeReq)
	if executeRec.Code != http.StatusOK || len(calls) != 2 {
		t.Fatalf("/mcp/v1/execute did not route through executor: status=%d body=%s calls=%#v", executeRec.Code, executeRec.Body.String(), calls)
	}

	jsonrpcBody, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      2,
		"method":  "tools/call",
		"params": map[string]any{
			"name":      "proof.echo",
			"arguments": map[string]any{"message": "hello"},
		},
	})
	jsonrpcReq := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewReader(jsonrpcBody))
	jsonrpcReq.Header.Set("MCP-Protocol-Version", mcppkg.LatestProtocolVersion)
	jsonrpcRec := httptest.NewRecorder()
	mux.ServeHTTP(jsonrpcRec, jsonrpcReq)
	if jsonrpcRec.Code != http.StatusOK || len(calls) != 3 {
		t.Fatalf("HTTP JSON-RPC tools/call did not route through executor: status=%d body=%s calls=%#v", jsonrpcRec.Code, jsonrpcRec.Body.String(), calls)
	}

	sseReq := httptest.NewRequest(http.MethodGet, "/mcp", nil)
	sseReq.Header.Set("Accept", "text/event-stream")
	sseRec := httptest.NewRecorder()
	mux.ServeHTTP(sseRec, sseReq)
	if sseRec.Code != http.StatusOK || !strings.Contains(sseRec.Header().Get("Content-Type"), "text/event-stream") {
		t.Fatalf("SSE primer failed: status=%d content-type=%s", sseRec.Code, sseRec.Header().Get("Content-Type"))
	}
	if len(calls) != 3 {
		t.Fatalf("SSE capability path dispatched a tool call: %#v", calls)
	}
}

func TestMCPMediationProofInstallArtifactsUseGovernedStdioServer(t *testing.T) {
	tmp := t.TempDir()
	t.Chdir(tmp)

	var stdout, stderr bytes.Buffer
	if code := generateClaudeCodePlugin(&stdout, &stderr); code != 0 {
		t.Fatalf("generateClaudeCodePlugin code=%d stderr=%s", code, stderr.String())
	}
	assertJSONArgs(t, filepath.Join(tmp, "helm-ai-kernel-mcp-plugin", ".mcp.json"), "mcp", "serve", "--transport", "stdio")

	stdout.Reset()
	stderr.Reset()
	bundle := filepath.Join(tmp, "helm-ai-kernel.mcpb")
	if code := generateMCPBundle(bundle, &stdout, &stderr); code != 0 {
		t.Fatalf("generateMCPBundle code=%d stderr=%s", code, stderr.String())
	}
	assertZipManifestArgs(t, bundle, "mcp", "serve", "--transport", "stdio")

	for _, client := range []string{"windsurf", "codex", "vscode", "cursor"} {
		stdout.Reset()
		stderr.Reset()
		if code := runMCPPrintConfig([]string{"--client", client}, &stdout, &stderr); code != 0 {
			t.Fatalf("print-config %s code=%d stderr=%s", client, code, stderr.String())
		}
		if !strings.Contains(stdout.String(), "mcp") || !strings.Contains(stdout.String(), "serve") || !strings.Contains(stdout.String(), "stdio") {
			t.Fatalf("print-config %s does not use governed stdio server: %s", client, stdout.String())
		}
	}
}

func TestMCPMediationProofSchemaErrorsBlockBeforeExecutor(t *testing.T) {
	catalog := proofCatalog(t)
	var calls []mcppkg.ToolExecutionRequest
	executor := func(_ context.Context, req mcppkg.ToolExecutionRequest) (mcppkg.ToolExecutionResponse, error) {
		calls = append(calls, req)
		return mcppkg.ToolExecutionResponse{Content: "should-not-dispatch"}, nil
	}
	gateway := mcppkg.NewGateway(catalog, mcppkg.GatewayConfig{}, mcppkg.WithExecutor(executor))
	mux := http.NewServeMux()
	gateway.RegisterRoutes(mux)

	unknownParams, _ := json.Marshal(map[string]any{
		"name":      "proof.missing",
		"arguments": map[string]any{"message": "hello"},
	})
	unknownStdioResp, err := handleMCPRPCRequest(&mcpRPCRequest{
		JSONRPC: "2.0",
		ID:      float64(0),
		Method:  "tools/call",
		Params:  unknownParams,
	}, catalog, executor)
	if err != nil {
		t.Fatalf("stdio unknown tools/call: %v", err)
	}
	if unknownStdioResp.Error == nil || len(calls) != 0 {
		t.Fatalf("stdio unknown tool reached executor: resp=%#v calls=%#v", unknownStdioResp, calls)
	}

	unknownExecuteBody, _ := json.Marshal(mcppkg.MCPToolCallRequest{Method: "proof.missing", Params: map[string]any{"message": "hello"}})
	unknownExecuteReq := httptest.NewRequest(http.MethodPost, "/mcp/v1/execute", bytes.NewReader(unknownExecuteBody))
	unknownExecuteRec := httptest.NewRecorder()
	mux.ServeHTTP(unknownExecuteRec, unknownExecuteReq)
	if unknownExecuteRec.Code != http.StatusNotFound || len(calls) != 0 {
		t.Fatalf("/mcp/v1/execute unknown tool reached executor: status=%d body=%s calls=%#v", unknownExecuteRec.Code, unknownExecuteRec.Body.String(), calls)
	}

	unknownJSONRPCBody, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "tools/call",
		"params": map[string]any{
			"name":      "proof.missing",
			"arguments": map[string]any{"message": "hello"},
		},
	})
	unknownJSONRPCReq := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewReader(unknownJSONRPCBody))
	unknownJSONRPCReq.Header.Set("MCP-Protocol-Version", mcppkg.LatestProtocolVersion)
	unknownJSONRPCRec := httptest.NewRecorder()
	mux.ServeHTTP(unknownJSONRPCRec, unknownJSONRPCReq)
	if unknownJSONRPCRec.Code != http.StatusOK || !strings.Contains(unknownJSONRPCRec.Body.String(), "tool \\\"proof.missing\\\" not found") || len(calls) != 0 {
		t.Fatalf("HTTP JSON-RPC unknown tool reached executor: status=%d body=%s calls=%#v", unknownJSONRPCRec.Code, unknownJSONRPCRec.Body.String(), calls)
	}

	params, _ := json.Marshal(map[string]any{
		"name":      "proof.echo",
		"arguments": map[string]any{"unexpected": "field"},
	})
	stdioResp, err := handleMCPRPCRequest(&mcpRPCRequest{
		JSONRPC: "2.0",
		ID:      float64(1),
		Method:  "tools/call",
		Params:  params,
	}, catalog, executor)
	if err != nil {
		t.Fatalf("stdio tools/call: %v", err)
	}
	if stdioResp.Error == nil || len(calls) != 0 {
		t.Fatalf("stdio schema drift reached executor: resp=%#v calls=%#v", stdioResp, calls)
	}

	executeBody, _ := json.Marshal(mcppkg.MCPToolCallRequest{Method: "proof.echo", Params: map[string]any{"unexpected": "field"}})
	executeReq := httptest.NewRequest(http.MethodPost, "/mcp/v1/execute", bytes.NewReader(executeBody))
	executeRec := httptest.NewRecorder()
	mux.ServeHTTP(executeRec, executeReq)
	if executeRec.Code != http.StatusBadRequest || len(calls) != 0 {
		t.Fatalf("/mcp/v1/execute schema drift reached executor: status=%d body=%s calls=%#v", executeRec.Code, executeRec.Body.String(), calls)
	}

	jsonrpcBody, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      2,
		"method":  "tools/call",
		"params": map[string]any{
			"name":      "proof.echo",
			"arguments": map[string]any{"unexpected": "field"},
		},
	})
	jsonrpcReq := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewReader(jsonrpcBody))
	jsonrpcReq.Header.Set("MCP-Protocol-Version", mcppkg.LatestProtocolVersion)
	jsonrpcRec := httptest.NewRecorder()
	mux.ServeHTTP(jsonrpcRec, jsonrpcReq)
	if jsonrpcRec.Code != http.StatusOK || !strings.Contains(jsonrpcRec.Body.String(), "PEP validation failed") || len(calls) != 0 {
		t.Fatalf("HTTP JSON-RPC schema drift reached executor: status=%d body=%s calls=%#v", jsonrpcRec.Code, jsonrpcRec.Body.String(), calls)
	}
}

func TestMCPMediationProofPolicyDenialsBlockDispatchAcrossTransports(t *testing.T) {
	catalog := proofCatalog(t)
	var dispatches []mcppkg.ToolExecutionRequest
	executor := func(_ context.Context, req mcppkg.ToolExecutionRequest) (mcppkg.ToolExecutionResponse, error) {
		decision := launchpadmcp.Authorize(launchpadmcp.ServerRecord{
			ServerID:   "srv",
			LaunchID:   "launch-1",
			AppID:      "openclaw",
			Principal:  "test.operator",
			PolicyHash: "sha256:policy",
			Approved:   true,
			SchemaPins: map[string]string{"proof.write": "sha256:write"},
		}, launchpadmcp.CallRequest{
			ServerID:   "srv",
			LaunchID:   "launch-1",
			AppID:      "openclaw",
			Principal:  "test.operator",
			PolicyHash: "sha256:policy",
			ToolName:   req.ToolName,
			SchemaHash: "sha256:write",
			Effect:     launchpadmcp.EffectSideEffect,
		})
		if decision.Verdict != "ALLOW" {
			return mcppkg.ToolExecutionResponse{Content: decision.Reason, IsError: true, Evaluated: true}, nil
		}
		dispatches = append(dispatches, req)
		return mcppkg.ToolExecutionResponse{Content: "dispatched", Evaluated: true}, nil
	}

	params, _ := json.Marshal(map[string]any{
		"name":      "proof.write",
		"arguments": map[string]any{"path": "out.txt", "content": "hello"},
	})
	stdioResp, err := handleMCPRPCRequest(&mcpRPCRequest{
		JSONRPC: "2.0",
		ID:      float64(1),
		Method:  "tools/call",
		Params:  params,
	}, catalog, executor)
	if err != nil {
		t.Fatalf("stdio side-effect tools/call: %v", err)
	}
	if stdioResp.Error != nil || !strings.Contains(string(mustJSON(t, stdioResp.Result)), "ERR_MCP_APPROVAL_RECEIPT_REQUIRED") || len(dispatches) != 0 {
		t.Fatalf("stdio side-effect denial dispatched: resp=%#v dispatches=%#v", stdioResp, dispatches)
	}

	gateway := mcppkg.NewGateway(catalog, mcppkg.GatewayConfig{}, mcppkg.WithExecutor(executor))
	mux := http.NewServeMux()
	gateway.RegisterRoutes(mux)

	executeBody, _ := json.Marshal(mcppkg.MCPToolCallRequest{Method: "proof.write", Params: map[string]any{"path": "out.txt", "content": "hello"}})
	executeReq := httptest.NewRequest(http.MethodPost, "/mcp/v1/execute", bytes.NewReader(executeBody))
	executeRec := httptest.NewRecorder()
	mux.ServeHTTP(executeRec, executeReq)
	if executeRec.Code != http.StatusForbidden || !strings.Contains(executeRec.Body.String(), "ERR_MCP_APPROVAL_RECEIPT_REQUIRED") || len(dispatches) != 0 {
		t.Fatalf("/mcp/v1/execute side-effect denial dispatched: status=%d body=%s dispatches=%#v", executeRec.Code, executeRec.Body.String(), dispatches)
	}

	jsonrpcBody, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      2,
		"method":  "tools/call",
		"params": map[string]any{
			"name":      "proof.write",
			"arguments": map[string]any{"path": "out.txt", "content": "hello"},
		},
	})
	jsonrpcReq := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewReader(jsonrpcBody))
	jsonrpcReq.Header.Set("MCP-Protocol-Version", mcppkg.LatestProtocolVersion)
	jsonrpcRec := httptest.NewRecorder()
	mux.ServeHTTP(jsonrpcRec, jsonrpcReq)
	if jsonrpcRec.Code != http.StatusOK || !strings.Contains(jsonrpcRec.Body.String(), "ERR_MCP_APPROVAL_RECEIPT_REQUIRED") || len(dispatches) != 0 {
		t.Fatalf("HTTP JSON-RPC side-effect denial dispatched: status=%d body=%s dispatches=%#v", jsonrpcRec.Code, jsonrpcRec.Body.String(), dispatches)
	}
}

func TestMCPMediationProofUnapprovedServersBlockDispatchAcrossTransports(t *testing.T) {
	catalog := proofCatalog(t)
	var dispatches []mcppkg.ToolExecutionRequest
	executor := func(_ context.Context, req mcppkg.ToolExecutionRequest) (mcppkg.ToolExecutionResponse, error) {
		decision := launchpadmcp.Authorize(launchpadmcp.ServerRecord{}, launchpadmcp.CallRequest{
			ServerID:   "srv-unapproved",
			LaunchID:   "launch-1",
			AppID:      "openclaw",
			Principal:  "test.operator",
			PolicyHash: "sha256:policy",
			ToolName:   req.ToolName,
			SchemaHash: "sha256:read",
			Effect:     launchpadmcp.EffectRead,
		})
		if decision.Verdict != "ALLOW" {
			return mcppkg.ToolExecutionResponse{Content: decision.Reason, IsError: true, Evaluated: true}, nil
		}
		dispatches = append(dispatches, req)
		return mcppkg.ToolExecutionResponse{Content: "dispatched", Evaluated: true}, nil
	}

	params, _ := json.Marshal(map[string]any{
		"name":      "proof.echo",
		"arguments": map[string]any{"message": "hello"},
	})
	stdioResp, err := handleMCPRPCRequest(&mcpRPCRequest{
		JSONRPC: "2.0",
		ID:      float64(1),
		Method:  "tools/call",
		Params:  params,
	}, catalog, executor)
	if err != nil {
		t.Fatalf("stdio unapproved-server tools/call: %v", err)
	}
	if stdioResp.Error != nil || !strings.Contains(string(mustJSON(t, stdioResp.Result)), "ERR_MCP_SERVER_QUARANTINED") || len(dispatches) != 0 {
		t.Fatalf("stdio unapproved-server denial dispatched: resp=%#v dispatches=%#v", stdioResp, dispatches)
	}

	gateway := mcppkg.NewGateway(catalog, mcppkg.GatewayConfig{}, mcppkg.WithExecutor(executor))
	mux := http.NewServeMux()
	gateway.RegisterRoutes(mux)

	executeBody, _ := json.Marshal(mcppkg.MCPToolCallRequest{Method: "proof.echo", Params: map[string]any{"message": "hello"}})
	executeReq := httptest.NewRequest(http.MethodPost, "/mcp/v1/execute", bytes.NewReader(executeBody))
	executeRec := httptest.NewRecorder()
	mux.ServeHTTP(executeRec, executeReq)
	if executeRec.Code != http.StatusForbidden || !strings.Contains(executeRec.Body.String(), "ERR_MCP_SERVER_QUARANTINED") || len(dispatches) != 0 {
		t.Fatalf("/mcp/v1/execute unapproved-server denial dispatched: status=%d body=%s dispatches=%#v", executeRec.Code, executeRec.Body.String(), dispatches)
	}

	jsonrpcBody, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      2,
		"method":  "tools/call",
		"params": map[string]any{
			"name":      "proof.echo",
			"arguments": map[string]any{"message": "hello"},
		},
	})
	jsonrpcReq := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewReader(jsonrpcBody))
	jsonrpcReq.Header.Set("MCP-Protocol-Version", mcppkg.LatestProtocolVersion)
	jsonrpcRec := httptest.NewRecorder()
	mux.ServeHTTP(jsonrpcRec, jsonrpcReq)
	if jsonrpcRec.Code != http.StatusOK || !strings.Contains(jsonrpcRec.Body.String(), "ERR_MCP_SERVER_QUARANTINED") || len(dispatches) != 0 {
		t.Fatalf("HTTP JSON-RPC unapproved-server denial dispatched: status=%d body=%s dispatches=%#v", jsonrpcRec.Code, jsonrpcRec.Body.String(), dispatches)
	}
}

func TestMCPMediationProofUnsupportedWebSocketTransportFailsClosed(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runMCPServe([]string{"--transport", "websocket"}, &stdout, &stderr)
	if code == 0 || !strings.Contains(stderr.String(), "unknown transport") {
		t.Fatalf("websocket transport must fail closed, code=%d stderr=%s", code, stderr.String())
	}
}

func TestMCPServeStdioUsesExplicitDataDir(t *testing.T) {
	dir := chdirTempDir(t)
	stateDir := filepath.Join(dir, "kernel-state")
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	oldStdin := os.Stdin
	os.Stdin = reader
	t.Cleanup(func() {
		os.Stdin = oldStdin
		_ = reader.Close()
	})
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	code := runMCPServe([]string{"--transport", "stdio", "--data-dir", stateDir}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("mcp serve exit = %d stderr = %s", code, stderr.String())
	}
	if _, err := os.Stat(filepath.Join(stateDir, "root.key")); err != nil {
		t.Fatalf("mcp serve did not use explicit data dir for signer state: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "data", "root.key")); !os.IsNotExist(err) {
		t.Fatalf("mcp serve unexpectedly used default data dir: %v", err)
	}
}

func proofCatalog(t *testing.T) *mcppkg.ToolCatalog {
	t.Helper()
	catalog := mcppkg.NewToolCatalog()
	if err := catalog.Register(context.Background(), mcppkg.ToolRef{
		Name:        "proof.echo",
		Description: "Proof harness echo tool",
		Schema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"message": map[string]any{"type": "string"},
			},
			"required": []string{"message"},
		},
	}); err != nil {
		t.Fatalf("register proof tool: %v", err)
	}
	if err := catalog.Register(context.Background(), mcppkg.ToolRef{
		Name:        "proof.write",
		Description: "Proof harness side-effect tool",
		Schema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"path":    map[string]any{"type": "string"},
				"content": map[string]any{"type": "string"},
			},
			"required": []string{"path", "content"},
		},
		Annotations: &mcppkg.ToolAnnotations{DestructiveHint: true},
	}); err != nil {
		t.Fatalf("register proof write tool: %v", err)
	}
	return catalog
}

func assertJSONArgs(t *testing.T, path string, want ...string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var payload struct {
		MCPServers map[string]struct {
			Args []string `json:"args"`
		} `json:"mcpServers"`
	}
	if err := json.Unmarshal(data, &payload); err != nil {
		t.Fatalf("decode %s: %v", path, err)
	}
	for _, server := range payload.MCPServers {
		assertArgs(t, server.Args, want...)
		return
	}
	t.Fatalf("no MCP server in %s", path)
}

func assertZipManifestArgs(t *testing.T, path string, want ...string) {
	t.Helper()
	reader, err := zip.OpenReader(path)
	if err != nil {
		t.Fatalf("open bundle: %v", err)
	}
	defer reader.Close()
	for _, file := range reader.File {
		if file.Name != "manifest.json" {
			continue
		}
		rc, err := file.Open()
		if err != nil {
			t.Fatalf("open manifest: %v", err)
		}
		defer rc.Close()
		var payload struct {
			Server struct {
				Args []string `json:"args"`
			} `json:"server"`
		}
		if err := json.NewDecoder(rc).Decode(&payload); err != nil {
			t.Fatalf("decode manifest: %v", err)
		}
		assertArgs(t, payload.Server.Args, want...)
		return
	}
	t.Fatalf("manifest.json missing from %s", path)
}

func assertArgs(t *testing.T, got []string, want ...string) {
	t.Helper()
	if strings.Join(got, "\x00") != strings.Join(want, "\x00") {
		t.Fatalf("args = %#v, want %#v", got, want)
	}
}

func mustJSON(t *testing.T, value any) []byte {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal value: %v", err)
	}
	return data
}
