package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/a2a"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	mcppkg "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/mcp"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/prg"
)

// A compiled serve policy authorizes execution: with a graph that carries an
// EXECUTE_TOOL rule (what the governance firewall evaluates), the same file_read
// that fails closed under the empty-graph default now succeeds. This is the
// behavior `mcp serve --policy` wires in.
func TestLocalMCPRuntimeAuthorizesExecutionWithPolicyGraph(t *testing.T) {
	dir := chdirTempDir(t)
	target := filepath.Join(dir, "allowed.txt")
	if err := os.WriteFile(target, []byte("authorized-content"), 0600); err != nil {
		t.Fatal(err)
	}

	graph := prg.NewGraph()
	// The guardian keys the policy lookup on the tool action (the firewall
	// passes ToolName as the decision Resource), so a serve policy authorizes
	// specific tools by name. An empty requirement set is vacuously satisfied,
	// so this rule allows file_read while every other tool stays fail-closed.
	if err := graph.AddRule("file_read", prg.RequirementSet{ID: "serve-policy:file_read", Logic: prg.AND}); err != nil {
		t.Fatal(err)
	}

	_, executor, err := newLocalMCPRuntimeWithDataDirAndPolicy(dir, graph)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := executor.Execute(context.Background(), mcppkg.ToolExecutionRequest{
		ToolName:  "file_read",
		SessionID: "mcp-test",
		Arguments: map[string]any{"path": target},
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.IsError {
		t.Fatalf("expected policy-authorized execution to succeed, got error: %q", resp.Content)
	}
	if !strings.Contains(resp.Content, "authorized-content") {
		t.Fatalf("expected authorized file content, got %q", resp.Content)
	}
}

func TestLocalMCPRuntimeFailsClosedWithoutPolicyGraph(t *testing.T) {
	dir := chdirTempDir(t)
	target := filepath.Join(dir, "secret.txt")
	if err := os.WriteFile(target, []byte("sensitive"), 0600); err != nil {
		t.Fatal(err)
	}

	_, executor, err := newLocalMCPRuntime()
	if err != nil {
		t.Fatal(err)
	}
	resp, err := executor.Execute(context.Background(), mcppkg.ToolExecutionRequest{
		ToolName:  "file_read",
		SessionID: "mcp-test",
		Arguments: map[string]any{"path": target},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !resp.IsError {
		t.Fatalf("expected local MCP execution to fail closed, got %+v", resp)
	}
	if strings.Contains(resp.Content, "sensitive") {
		t.Fatalf("blocked MCP response leaked file content: %q", resp.Content)
	}
}

func TestStdioMCPRejectsUnattestedGovernedSuccess(t *testing.T) {
	catalog := mcppkg.NewInMemoryCatalog()
	if err := catalog.Register(context.Background(), mcppkg.ToolRef{Name: "tool", Schema: map[string]any{"type": "object"}}); err != nil {
		t.Fatal(err)
	}
	response, err := handleMCPRPCRequest(&mcpRPCRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "tools/call",
		Params:  json.RawMessage(`{"name":"tool","arguments":{}}`),
	}, catalog, func(context.Context, mcppkg.ToolExecutionRequest) (mcppkg.ToolExecutionResponse, error) {
		return mcppkg.ToolExecutionResponse{Content: "unattested"}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if response.Error == nil || response.Error.Message != "governed execution did not attest protected arguments" || response.Result != nil {
		t.Fatalf("stdio accepted unattested governed response: %#v", response)
	}
}

func TestLocalMCPRuntimeExecutesAdvertisedGovernanceTools(t *testing.T) {
	evaluator := fixedMCPDecisionEvaluator{decision: &contracts.DecisionRecord{
		ID:                 "decision-governance-tool",
		Verdict:            string(contracts.VerdictAllow),
		RequirementSetHash: "sha256:requirements",
	}}
	catalog, executor, err := newLocalMCPRuntimeWithEvaluator(evaluator)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"helm.verify", "helm.evaluate"} {
		if _, ok := catalog.Lookup(name); !ok {
			t.Fatalf("implemented tool %q was not advertised", name)
		}
	}

	gateway := mcppkg.NewGateway(catalog, mcppkg.GatewayConfig{}, mcppkg.WithGovernedExecutor(executor))
	mux := http.NewServeMux()
	gateway.RegisterRoutes(mux)
	sessionID := initializeLocalMCPTestSession(t, mux)

	verify := callLocalMCPTool(t, mux, sessionID, "helm.verify", map[string]any{
		"action":    "file_read",
		"principal": "agent-test",
		"resource":  "allowed.txt",
		"args_hash": "sha256:args",
	})
	if verify["verdict"] != string(contracts.VerdictAllow) || verify["receipt_id"] != "decision-governance-tool" {
		t.Fatalf("helm.verify result = %#v", verify)
	}

	now := time.Now().UTC()
	evaluate := callLocalMCPTool(t, mux, sessionID, "helm.evaluate", map[string]any{
		"envelope": map[string]any{
			"envelope_id":       "envelope-test",
			"schema_version":    a2a.CurrentVersion,
			"origin_agent_id":   "agent-a",
			"target_agent_id":   "agent-b",
			"required_features": []string{string(a2a.FeatureEvidenceExport)},
			"offered_features":  []string{string(a2a.FeatureEvidenceExport)},
			"payload_hash":      "sha256:payload",
			"created_at":        now,
			"expires_at":        now.Add(time.Hour),
		},
		"local_features": []string{string(a2a.FeatureEvidenceExport)},
	})
	if evaluate["accepted"] != true || evaluate["receipt_id"] == "" {
		t.Fatalf("helm.evaluate result = %#v", evaluate)
	}
}

func initializeLocalMCPTestSession(t *testing.T, mux *http.ServeMux) string {
	t.Helper()
	body, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "initialize",
		"params": map[string]any{
			"protocolVersion": mcppkg.LatestProtocolVersion,
			"clientInfo":      map[string]any{"name": "kernel-test-client"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("initialize status=%d body=%s", rec.Code, rec.Body.String())
	}
	sessionID := rec.Header().Get("MCP-Session-Id")
	if sessionID == "" {
		t.Fatal("initialize did not return MCP-Session-Id")
	}
	return sessionID
}

func callLocalMCPTool(t *testing.T, mux *http.ServeMux, sessionID, name string, arguments map[string]any) map[string]any {
	t.Helper()
	body, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "tools/call",
		"params":  map[string]any{"name": name, "arguments": arguments},
	})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewReader(body))
	req.Header.Set("MCP-Protocol-Version", mcppkg.LatestProtocolVersion)
	req.Header.Set("MCP-Session-Id", sessionID)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("%s status=%d body=%s", name, rec.Code, rec.Body.String())
	}
	var response struct {
		Result struct {
			StructuredContent map[string]any `json:"structuredContent"`
		} `json:"result"`
		Error any `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.Error != nil {
		t.Fatalf("%s error=%v body=%s", name, response.Error, rec.Body.String())
	}
	return response.Result.StructuredContent
}
