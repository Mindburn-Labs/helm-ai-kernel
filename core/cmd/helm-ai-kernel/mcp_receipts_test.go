package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	helmauth "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/auth"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/executor"
	mcppkg "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/mcp"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/prg"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/receiptverify"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/store"
	"github.com/stretchr/testify/require"
)

func mcpReceiptTestPolicy(t *testing.T, actions ...string) *prg.Graph {
	t.Helper()
	graph := prg.NewGraph()
	for _, action := range actions {
		require.NoError(t, graph.AddRule(action, prg.RequirementSet{ID: "receipt-test:" + action, Logic: prg.AND}))
	}
	return graph
}

func mcpReceiptTestRPC(t *testing.T, tool string, args map[string]any) []byte {
	t.Helper()
	data, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": map[string]any{"name": tool, "arguments": args, "tenant_id": "attacker-tenant", "principal_id": "attacker-principal"}})
	require.NoError(t, err)
	return append(data, '\n')
}

func mcpReceiptTestResult(t *testing.T, response []byte) map[string]any {
	t.Helper()
	var rpc struct {
		Result map[string]any `json:"result"`
		Error  any            `json:"error"`
	}
	require.NoError(t, json.Unmarshal(response, &rpc))
	require.Nil(t, rpc.Error, string(response))
	require.NotNil(t, rpc.Result, string(response))
	return rpc.Result
}

func readMCPTestReceipt(t *testing.T, dataDir, receiptID, tenant, verdict string) *contracts.Receipt {
	t.Helper()
	raw, err := os.ReadFile(portableEvaluateReceiptPath(dataDir, receiptID))
	require.NoError(t, err)
	receipt, err := receiptverify.ParseReceipt(raw)
	require.NoError(t, err)
	require.Equal(t, contracts.ReceiptSignatureV5, receipt.SignatureVersion)
	require.Equal(t, verdict, receipt.Verdict)
	require.Equal(t, executor.ReceiptIDForDecision(tenant, receipt.DecisionID), receiptID)
	publicKey, err := os.ReadFile(filepath.Join(dataDir, "root.pub"))
	require.NoError(t, err)
	result := receiptverify.Verify([]*contracts.Receipt{receipt}, receiptverify.TrustRoot{Keys: map[string]string{receipt.KeyID: strings.TrimSpace(string(publicKey))}})
	require.True(t, result.Valid, "%+v", result)
	// Reopen a separate durable connection: the response ID must resolve to the
	// canonical stored envelope, not merely the exported JSON or catalog audit.
	db, err := sql.Open("sqlite", filepath.Join(dataDir, "helm.db"))
	require.NoError(t, err)
	defer db.Close()
	receipts, err := store.NewSQLiteReceiptStore(db)
	require.NoError(t, err)
	stored, err := receipts.GetCanonicalReceiptByIDForTenant(context.Background(), tenant, receiptID)
	require.NoError(t, err)
	require.Equal(t, receipt.Signature, stored.Signature)
	require.Equal(t, receipt.PrevHash, stored.PrevHash)
	_, err = receipts.GetCanonicalReceiptByIDForTenant(context.Background(), "other-tenant", receiptID)
	require.Error(t, err)
	return receipt
}

func TestMCPStdioPersistsVerifiableAllowDenyAndNoPolicy(t *testing.T) {
	t.Setenv(runtimeTenantIDEnv, "local-receipt-tenant")
	t.Setenv("HELM_PRODUCTION", "0")
	t.Setenv("HELM_RECEIPT_PROFILE", "classical")
	target := filepath.Join(t.TempDir(), "readable.txt")
	require.NoError(t, os.WriteFile(target, []byte("receipt-backed-content"), 0600))
	writeTarget := filepath.Join(t.TempDir(), "must-not-exist.txt")
	dataDir := t.TempDir()
	policyPath, _ := writeMountedServePolicyFixture(t, t.TempDir(), `{"pack_id":"mcp-receipts","version":1,"runtime_actions":[{"action":"file_read","expression":"true"}]}`)
	for _, tc := range []struct {
		name, tool, verdict string
		args                map[string]any
		policy              bool
	}{
		{"allow", "file_read", "ALLOW", map[string]any{"path": target}, true},
		{"deny-write", "file_write", "DENY", map[string]any{"path": writeTarget, "content": "blocked"}, true},
		{"deny-no-policy", "file_read", "DENY", map[string]any{"path": target}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Exercise the actual CLI parser and newline tools/call serving loop.
			input, err := os.CreateTemp(t.TempDir(), "stdio")
			require.NoError(t, err)
			defer input.Close()
			_, err = input.Write(mcpReceiptTestRPC(t, tc.tool, tc.args))
			require.NoError(t, err)
			_, err = input.Seek(0, 0)
			require.NoError(t, err)
			original := os.Stdin
			os.Stdin = input
			defer func() { os.Stdin = original }()
			args := []string{"--transport", "stdio", "--data-dir", dataDir}
			if tc.policy {
				args = append(args, "--policy", policyPath)
			}
			var stdout, stderr bytes.Buffer
			require.Equal(t, 0, runMCPServe(args, &stdout, &stderr), stderr.String())
			result := mcpReceiptTestResult(t, stdout.Bytes())
			require.Equal(t, tc.verdict != "ALLOW", result["isError"])
			receiptID, ok := result["receipt_id"].(string)
			require.True(t, ok, string(stdout.Bytes()))
			receipt := readMCPTestReceipt(t, dataDir, receiptID, "local-receipt-tenant", tc.verdict)
			require.Equal(t, "mcp-stdio", receipt.ExecutorID)
			if tc.verdict == "ALLOW" {
				require.Contains(t, stdout.String(), "receipt-backed-content")
			} else {
				require.NotContains(t, stdout.String(), "receipt-backed-content")
			}
			// The existing independent CLI verifier accepts the exported receipt and
			// rejects a changed signed verdict under the retained trust anchor.
			var verified, diagnostics bytes.Buffer
			verifyArgs := []string{"--receipt", portableEvaluateReceiptPath(dataDir, receiptID), "--trusted-public-key-file", filepath.Join(dataDir, "root.pub"), "--json"}
			require.Equal(t, 0, runVerifyReceiptCmd(verifyArgs, &verified, &diagnostics), diagnostics.String())
			receipt.Verdict = "TAMPERED"
			tampered, err := json.Marshal(receipt)
			require.NoError(t, err)
			tamperedPath := filepath.Join(t.TempDir(), "tampered.json")
			require.NoError(t, os.WriteFile(tamperedPath, tampered, 0600))
			verifyArgs[1] = tamperedPath
			require.NotEqual(t, 0, runVerifyReceiptCmd(verifyArgs, &verified, &diagnostics))
		})
	}
	_, err := os.Stat(writeTarget)
	require.ErrorIs(t, err, os.ErrNotExist)
}

func TestMCPReceiptPersistenceFailurePreventsDispatch(t *testing.T) {
	t.Setenv(runtimeTenantIDEnv, "local-receipt-tenant")
	for _, failure := range []string{"database", "portable-export"} {
		t.Run(failure, func(t *testing.T) {
			dataDir := t.TempDir()
			runtime, err := openLocalMCPRuntime(dataDir, mcpReceiptTestPolicy(t, "file_write"))
			require.NoError(t, err)
			defer runtime.Close()
			target := filepath.Join(t.TempDir(), "must-not-exist.txt")
			// Both the durable append and the portable export are required by this
			// serving path. Force a real I/O failure after initialization.
			if failure == "database" {
				require.NoError(t, runtime.db.Close())
			} else {
				require.NoError(t, os.WriteFile(filepath.Join(dataDir, "receipts"), []byte("blocks export directory"), 0600))
			}
			ctx := withMCPTransportIdentity(context.Background(), "mcp-stdio", "mcp-stdio-transport")
			resp, err := runtime.executor.Execute(ctx, mcppkg.ToolExecutionRequest{ToolName: "file_write", SessionID: "mcp-stdio", PrincipalID: "mcp-stdio", CredentialHash: "trusted-credential", Arguments: map[string]any{"path": target, "content": "must not dispatch"}})
			require.NoError(t, err)
			require.True(t, resp.IsError)
			require.Empty(t, resp.ReceiptID)
			_, err = os.Stat(target)
			require.ErrorIs(t, err, os.ErrNotExist)
		})
	}
}

func TestMCPHTTPReceiptsPreserveCredentialTenantAuthority(t *testing.T) {
	t.Setenv(runtimeTenantIDEnv, "http-receipt-tenant")
	t.Setenv("MINDBURN_HELM_API_KEY", "receipt-test-key")
	t.Setenv(mcpBindAddrEnv, "127.0.0.1")
	dataDir := t.TempDir()
	target := filepath.Join(t.TempDir(), "readable.txt")
	require.NoError(t, os.WriteFile(target, []byte("http-receipt-content"), 0600))
	server, err := newLocalMCPHTTPServerWithDataDirAndPolicy(0, "static-header", dataDir, mcpReceiptTestPolicy(t, "file_read"))
	require.NoError(t, err)
	defer server.Shutdown(context.Background())
	initialize := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2025-11-25"}}`))
	initialize.Header.Set("X-HELM-API-Key", "receipt-test-key")
	initialized := httptest.NewRecorder()
	server.Handler.ServeHTTP(initialized, initialize)
	require.Equal(t, http.StatusOK, initialized.Code, initialized.Body.String())
	sessionID := initialized.Header().Get("MCP-Session-Id")
	require.NotEmpty(t, sessionID)
	for _, tc := range []struct {
		name, key, tenant string
		status            int
	}{
		{"missing", "", "", http.StatusUnauthorized},
		{"wrong", "wrong-key", "", http.StatusUnauthorized},
		{"foreign-tenant", "receipt-test-key", "other-tenant", http.StatusForbidden},
		{"allow", "receipt-test-key", "http-receipt-tenant", http.StatusOK},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body, err := json.Marshal(mcppkg.MCPToolCallRequest{Method: "file_read", Params: map[string]any{"path": target}})
			require.NoError(t, err)
			req := httptest.NewRequest(http.MethodPost, "/mcp/v1/execute", bytes.NewReader(body))
			req.Header.Set("MCP-Session-Id", sessionID)
			req.Header.Set("X-HELM-API-Key", tc.key)
			req.Header.Set(tenantHeader, tc.tenant)
			rec := httptest.NewRecorder()
			server.Handler.ServeHTTP(rec, req)
			require.Equal(t, tc.status, rec.Code, rec.Body.String())
			if tc.status != http.StatusOK {
				require.NotContains(t, rec.Body.String(), "http-receipt-content")
				return
			}
			var response mcppkg.MCPToolCallResponse
			require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &response))
			require.Empty(t, response.Error, rec.Body.String())
			require.Contains(t, rec.Body.String(), "http-receipt-content")
			receipt := readMCPTestReceipt(t, dataDir, response.ReceiptID, "http-receipt-tenant", "ALLOW")
			require.Equal(t, "mcp-static", receipt.ExecutorID)
		})
	}
	paths, err := filepath.Glob(filepath.Join(portableEvaluateReceiptDir(dataDir), "*", "*.json"))
	require.NoError(t, err)
	require.Len(t, paths, 1, "unauthenticated or tenant-spoofed calls must not acquire decision authority")
}

func TestMCPReceiptKeyStableAcrossRestartAndMissingPublicExport(t *testing.T) {
	dataDir := t.TempDir()
	runtime, err := openLocalMCPRuntime(dataDir, nil)
	require.NoError(t, err)
	require.NoError(t, runtime.Close())
	first, err := os.ReadFile(filepath.Join(dataDir, "root.pub"))
	require.NoError(t, err)
	require.NoError(t, os.Remove(filepath.Join(dataDir, "root.pub")))
	runtime, err = openLocalMCPRuntime(dataDir, nil)
	require.NoError(t, err)
	require.NoError(t, runtime.Close())
	second, err := os.ReadFile(filepath.Join(dataDir, "root.pub"))
	require.NoError(t, err)
	require.Equal(t, strings.TrimSpace(string(first)), strings.TrimSpace(string(second)))
	require.NoError(t, os.WriteFile(filepath.Join(dataDir, "root.pub"), []byte(strings.Repeat("0", 64)), 0644))
	_, err = openLocalMCPRuntime(dataDir, nil)
	require.ErrorContains(t, err, "does not match")
}

func TestMCPAuthBindsConfiguredTenantWithoutTrustingHeaders(t *testing.T) {
	t.Setenv(runtimeTenantIDEnv, "trusted-configured-tenant")
	t.Setenv("HELM_OAUTH_BEARER_TOKEN", "dev-token")
	t.Setenv("HELM_OAUTH_JWKS_URL", "")
	handler, err := wrapMCPAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		principal, err := helmauth.GetPrincipal(r.Context())
		require.NoError(t, err)
		require.Equal(t, "trusted-configured-tenant", principal.GetTenantID())
		require.Equal(t, "mcp-oauth-dev", principal.GetID())
		w.WriteHeader(http.StatusNoContent)
	}), "oauth", "http://localhost:9100")
	require.NoError(t, err)
	for _, tenant := range []string{"", "trusted-configured-tenant", "foreign-tenant"} {
		req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
		req.Header.Set("Authorization", "Bearer dev-token")
		req.Header.Set(tenantHeader, tenant)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		expected := http.StatusNoContent
		if tenant == "foreign-tenant" {
			expected = http.StatusForbidden
		}
		require.Equal(t, expected, rec.Code, fmt.Sprint(tenant))
	}
}

// The local TLS issuer supplies genuinely signed tokens through the production
// JWKS validator, including a valid foreign-tenant token that must be refused.
func TestMCPAuthRejectsOAuthTokenForAnotherTenant(t *testing.T) {
	issuer := newTestCPIssuer(t, "mcp-auth")
	originalTransport := http.DefaultTransport
	http.DefaultTransport = issuer.server.Client().Transport
	defer func() { http.DefaultTransport = originalTransport }()
	t.Setenv(runtimeTenantIDEnv, "oauth-tenant")
	t.Setenv("HELM_OAUTH_JWKS_URL", issuer.server.URL)
	t.Setenv("HELM_OAUTH_ISSUER", testCPIssuer)
	t.Setenv("HELM_OAUTH_AUDIENCE", testCPAudience)
	t.Setenv("HELM_OAUTH_RESOURCE", "http://localhost:9100/mcp")
	t.Setenv("HELM_OAUTH_SCOPES", "read")
	calls := 0
	handler, err := wrapMCPAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		principal, err := helmauth.GetPrincipal(r.Context())
		require.NoError(t, err)
		require.Equal(t, "oauth-principal", principal.GetID())
		require.Equal(t, "oauth-tenant", principal.GetTenantID())
		w.WriteHeader(http.StatusNoContent)
	}), "oauth", "http://localhost:9100")
	require.NoError(t, err)
	for _, tc := range []struct {
		tenant string
		status int
	}{
		{"oauth-tenant", http.StatusNoContent}, {"foreign-tenant", http.StatusForbidden},
	} {
		claims := baseTokenClaims(tc.tenant, "oauth-principal", "workspace", "read").with("resource", "http://localhost:9100/mcp")
		token := issuer.mint(t, "mcp-auth", claims)
		req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		// A header naming this listener's tenant cannot repair a foreign token.
		req.Header.Set(tenantHeader, "oauth-tenant")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		require.Equal(t, tc.status, rec.Code, rec.Body.String())
	}
	require.Equal(t, 1, calls)
}

func TestMCPReceiptRetainedAnchorSurvivesPrivateKeyLoss(t *testing.T) {
	t.Setenv("HELM_PRODUCTION", "0")
	t.Setenv("HELM_RECEIPT_PROFILE", "classical")
	dir := t.TempDir()
	runtime, err := openLocalMCPRuntime(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := runtime.Close(); err != nil {
		t.Fatal(err)
	}
	anchor, err := os.ReadFile(filepath.Join(dir, "root.pub"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(dir, "root.key")); err != nil {
		t.Fatal(err)
	}
	runtime, err = openLocalMCPRuntime(dir, nil)
	if runtime != nil {
		defer runtime.Close()
	}
	after, readErr := os.ReadFile(filepath.Join(dir, "root.pub"))
	if readErr != nil {
		t.Fatal(readErr)
	}
	if err == nil || string(anchor) != string(after) {
		t.Fatalf("retained trust anchor must survive private-key loss with startup refused: startup_error=%v anchor_changed=%t", err, string(anchor) != string(after))
	}
}
