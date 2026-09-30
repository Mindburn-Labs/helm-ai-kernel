package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/api"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	helmcrypto "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/guardian"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/kernel"
	mcppkg "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/mcp"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/prg"
)

// HELM-780: the scoped emergency-stop fence is one mechanism (R4). A fence
// recorded in the kernel database must deny through serve, proxy and mcp
// serve alike, and a caller must not escape it by naming another scope.

const (
	fencedTestTenant    = "tenant-a"
	fencedTestWorkspace = "workspace-a"
	fencedTestPrincipal = "principal-a"
)

// enableEmergencyStopFenceForTest turns the fence on for the scope
// tenant-a/workspace-a and configures the command authority serve requires.
func enableEmergencyStopFenceForTest(t *testing.T) {
	t.Helper()
	newEmergencyStopFenceRouteForTest(t) // sets the command audience and key
	t.Setenv(emergencyStopFenceEnabledEnv, "1")
	t.Setenv(runtimeTenantIDEnv, fencedTestTenant)
	t.Setenv(runtimeWorkspaceIDEnv, fencedTestWorkspace)
	t.Setenv(runtimePrincipalIDEnv, fencedTestPrincipal)
	t.Setenv("DATABASE_URL", "")
}

// recordFenceInDataDir writes a fence into the Lite Mode database in dataDir,
// through a handle of its own, as another kernel process would.
func recordFenceInDataDir(t *testing.T, dataDir, commandID, workspaceID string) {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(dataDir, "helm.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	stops := kernel.NewScopedStopStore(db, time.Now)
	if err := stops.Init(context.Background()); err != nil {
		t.Fatal(err)
	}
	command := newEmergencyStopFenceCommand(time.Now().UTC())
	command.CommandID = commandID
	command.TenantID = fencedTestTenant
	command.WorkspaceID = workspaceID
	if _, _, err := stops.Fence(context.Background(), command, emergencyStopAcknowledgementIdentityForTest()); err != nil {
		t.Fatal(err)
	}
}

func newProductionGuardianTestSigner(t *testing.T) helmcrypto.Signer {
	t.Helper()
	signer, err := loadOrGenerateSignerWithDataDir(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return signer
}

func isEmergencyStopReason(reasonCode string) bool {
	return strings.HasPrefix(reasonCode, "EMERGENCY_STOP_")
}

func TestEmergencyStopFenceDeniesThroughEveryEntryPoint(t *testing.T) {
	t.Run("serve", func(t *testing.T) {
		enableEmergencyStopFenceForTest(t)
		dataDir := t.TempDir()
		base := startInProcessServeForTest(t, dataDir)
		recordFenceInDataDir(t, dataDir, "stop-other-workspace", "workspace-other")

		evaluate := func(t *testing.T) api.EvaluateResponse {
			t.Helper()
			// The body names an unfenced workspace; the route binds the
			// configured one.
			return postServeEvaluate(t, base, fencedTestTenant, fencedTestPrincipal, fencedTestWorkspace,
				`{"action":"EXECUTE_TOOL","resource":"local.echo","session_id":"fence-session","context":{"workspace_id":"workspace-other","tenant_id":"tenant-other"}}`)
		}
		if response := evaluate(t); isEmergencyStopReason(response.ReasonCode) {
			t.Fatalf("an unfenced scope was denied by the fence: %+v", response)
		}
		recordFenceInDataDir(t, dataDir, "stop-serve", fencedTestWorkspace)
		if response := evaluate(t); response.Verdict != string(contracts.VerdictDeny) || response.ReasonCode != string(contracts.ReasonEmergencyStopFenced) {
			t.Fatalf("fenced serve evaluation = %+v, want DENY/%s", response, contracts.ReasonEmergencyStopFenced)
		}
	})

	t.Run("proxy", func(t *testing.T) {
		enableEmergencyStopFenceForTest(t)
		upstream, _ := newFakeUpstream(t, chatToolCallReply("get_weather", `{"city":"Berlin","tenant_id":"tenant-other"}`))
		proxySrv, _ := startTestProxy(t, upstream.URL, allowPolicyGraph(t, "get_weather"), func(cfg *proxyConfig) {
			cfg.tenantID = fencedTestTenant
		})
		dataDir := os.Getenv("HELM_DATA_DIR") // startTestProxy points the proxy at a fresh one
		recordFenceInDataDir(t, dataDir, "stop-other-workspace", "workspace-other")

		if resp := postToProxy(t, proxySrv.URL, toolRequest, nil); resp.header.Get("X-Helm-Status") != "APPROVED" {
			t.Fatalf("unfenced proxy tool call: status=%q reason=%q body=%s", resp.header.Get("X-Helm-Status"), resp.header.Get("X-Helm-Reason-Code"), resp.body)
		}
		recordFenceInDataDir(t, dataDir, "stop-proxy", fencedTestWorkspace)
		resp := postToProxy(t, proxySrv.URL, toolRequest, nil)
		if resp.header.Get("X-Helm-Status") != "DENIED" || resp.header.Get("X-Helm-Reason-Code") != string(contracts.ReasonEmergencyStopFenced) {
			t.Fatalf("fenced proxy tool call: status=%q reason=%q body=%s", resp.header.Get("X-Helm-Status"), resp.header.Get("X-Helm-Reason-Code"), resp.body)
		}
	})

	t.Run("mcp serve", func(t *testing.T) {
		enableEmergencyStopFenceForTest(t)
		dir := chdirTempDir(t)
		target := filepath.Join(dir, "allowed.txt")
		if err := os.WriteFile(target, []byte("authorized-content"), 0600); err != nil {
			t.Fatal(err)
		}
		graph := prg.NewGraph()
		if err := graph.AddRule("file_read", prg.RequirementSet{ID: "serve-policy:file_read", Logic: prg.AND}); err != nil {
			t.Fatal(err)
		}
		dataDir := t.TempDir()
		_, executor, err := newLocalMCPRuntimeWithDataDirAndPolicy(dataDir, graph)
		if err != nil {
			t.Fatal(err)
		}
		readFile := func() mcppkg.ToolExecutionResponse {
			resp, err := executor.Execute(context.Background(), mcppkg.ToolExecutionRequest{
				ToolName:       "file_read",
				SessionID:      "mcp-fence",
				PrincipalID:    "mcp-fence",
				CredentialHash: "trusted-local-test-credential",
				Arguments:      map[string]any{"path": target},
			})
			if err != nil {
				t.Fatal(err)
			}
			return resp
		}
		recordFenceInDataDir(t, dataDir, "stop-other-workspace", "workspace-other")
		if resp := readFile(); resp.IsError || !strings.Contains(resp.Content, "authorized-content") {
			t.Fatalf("unfenced mcp serve call was not allowed: %+v", resp)
		}
		recordFenceInDataDir(t, dataDir, "stop-mcp", fencedTestWorkspace)
		if resp := readFile(); !resp.IsError || strings.Contains(resp.Content, "authorized-content") {
			t.Fatalf("fenced mcp serve call was not denied: %+v", resp)
		}
	})
}

// The MCP decision context is built from tool arguments. With the fence on,
// the configured scope replaces every tenant and workspace alias in it, so a
// caller cannot pick an unfenced scope; the server's MCP gateway and mcp serve
// both decide through this binding.
func TestFencedMCPDecisionsBindTheConfiguredScope(t *testing.T) {
	enableEmergencyStopFenceForTest(t)
	dataDir := t.TempDir()
	recordFenceInDataDir(t, dataDir, "stop-mcp-scope", fencedTestWorkspace)
	fence, err := openStandaloneEmergencyStopFence(context.Background(), dataDir)
	if err != nil {
		t.Fatal(err)
	}
	defer fence.Close()
	signer := newProductionGuardianTestSigner(t)
	guard, err := newProductionGuardian(signer, prg.NewGraph(), nil, utcRuntimeClock{}, fence.guardianState(dataDir))
	if err != nil {
		t.Fatal(err)
	}
	evaluator, err := bindEmergencyStopScope(guard)
	if err != nil {
		t.Fatal(err)
	}
	decision, err := evaluator.EvaluateDecision(context.Background(), guardian.DecisionRequest{
		Principal: "mcp-caller",
		Action:    "EXECUTE_TOOL",
		Resource:  "file_read",
		Context: map[string]any{
			"tenant":       "tenant-other",
			"tenantId":     "tenant-other",
			"tenant_id":    "tenant-other",
			"workspace":    "workspace-other",
			"workspaceId":  "workspace-other",
			"workspace_id": "workspace-other",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if decision.ReasonCode != string(contracts.ReasonEmergencyStopFenced) {
		t.Fatalf("caller-named scope escaped the fence: %+v", decision)
	}

	bound := emergencyStopScope{TenantID: fencedTestTenant, WorkspaceID: fencedTestWorkspace}.bind(map[string]any{"tenantId": "x", "workspace": "y", "path": "a.txt"})
	want := map[string]any{"tenant_id": fencedTestTenant, "workspace_id": fencedTestWorkspace, "path": "a.txt"}
	if fmt.Sprint(bound) != fmt.Sprint(want) {
		t.Fatalf("bound context = %v, want %v", bound, want)
	}
}

// No entry point can build a Guardian that skips the fence: with the fence on,
// the factory refuses a missing store, and proxy and mcp serve refuse to start
// without the scope the fence covers.
func TestFencedEntryPointsRefuseToRunWithoutTheFence(t *testing.T) {
	enableEmergencyStopFenceForTest(t)
	signer := newProductionGuardianTestSigner(t)
	if g, err := newProductionGuardian(signer, nil, nil, utcRuntimeClock{}, productionGuardianState{DataDir: t.TempDir()}); err == nil || g != nil {
		t.Fatalf("fenced factory without a stop store = (%v, %v), want an error", g, err)
	}

	t.Run("proxy tenant differs from the fenced tenant", func(t *testing.T) {
		t.Setenv("HELM_DATA_DIR", t.TempDir())
		_, err := newProxyRuntime(proxyConfig{upstream: "http://127.0.0.1:1/v1", receiptsDir: t.TempDir(), tenantID: "tenant-other"}, io.Discard)
		if err == nil || !strings.Contains(err.Error(), runtimeTenantIDEnv) {
			t.Fatalf("proxy with a mismatched tenant: err = %v", err)
		}
	})

	t.Run("mcp serve without a configured workspace", func(t *testing.T) {
		t.Setenv(runtimeWorkspaceIDEnv, "")
		if _, _, err := newLocalMCPRuntimeWithDataDirAndPolicy(t.TempDir(), nil); err == nil || !strings.Contains(err.Error(), runtimeWorkspaceIDEnv) {
			t.Fatalf("mcp serve without a fenced scope: err = %v", err)
		}
	})
}

// HELM-780: serve --data-dir did not export HELM_DATA_DIR, so the server read
// the freeze from ./data under its working directory. It now reads the data
// directory it was configured with, whatever the working directory is.
func TestServeReadsTheFreezeFromItsDataDir(t *testing.T) {
	cwd := chdirTempDir(t)
	t.Setenv("HELM_DATA_DIR", "")
	t.Setenv(runtimePrincipalIDEnv, "principal-freeze")
	// The freeze file serve used to read: ./data under the working directory.
	if err := saveFreezeState(filepath.Join(cwd, "data"), &persistedFreezeState{Frozen: true, FrozenBy: "stale", FrozenAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	dataDir := t.TempDir()
	base := startInProcessServeForTest(t, dataDir)
	evaluate := func() api.EvaluateResponse {
		return postServeEvaluate(t, base, defaultRuntimeTenantID, "principal-freeze", "",
			`{"action":"EXECUTE_TOOL","resource":"local.echo","session_id":"freeze-session"}`)
	}
	if response := evaluate(); response.ReasonCode == string(contracts.ReasonSystemFrozen) {
		t.Fatalf("serve read the freeze under its working directory: %+v", response)
	}

	var stdout, stderr bytes.Buffer
	if code := runFreezeCmd([]string{"--principal", "operator", "--data-dir", dataDir}, &stdout, &stderr, "freeze"); code != 0 {
		t.Fatalf("freeze --data-dir exit %d: %s", code, stderr.String())
	}
	if response := evaluate(); response.ReasonCode != string(contracts.ReasonSystemFrozen) {
		t.Fatalf("serve ignored the freeze in its data dir: %+v", response)
	}
	if code := runFreezeCmd([]string{"--principal", "operator", "--data-dir", dataDir}, &stdout, &stderr, "unfreeze"); code != 0 {
		t.Fatalf("unfreeze --data-dir exit %d: %s", code, stderr.String())
	}
	if response := evaluate(); response.ReasonCode == string(contracts.ReasonSystemFrozen) {
		t.Fatalf("serve did not observe the unfreeze: %+v", response)
	}
}

// startInProcessServeForTest runs `serve --data-dir dataDir` in this process
// on free ports and stops it when the test ends.
func startInProcessServeForTest(t *testing.T, dataDir string) string {
	t.Helper()
	t.Setenv("HELM_ADMIN_API_KEY", testAdminAPIKey)
	t.Setenv(serviceAPIKeyEnv, "service-serve-test")
	t.Setenv("HELM_HEALTH_PORT", strconv.Itoa(freeServeTestPort(t)))
	t.Cleanup(func() { SetPrincipalBindingStore(nil) })
	port := freeServeTestPort(t)
	exit := make(chan struct{})
	ready := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- runServerWithOptions(serverOptions{
			Mode:        "serve",
			BindAddr:    "127.0.0.1",
			Port:        port,
			DataDir:     dataDir,
			OnReady:     func(string, int) error { close(ready); return nil },
			RuntimeExit: exit,
			Stdout:      io.Discard,
			Stderr:      io.Discard,
		})
	}()
	select {
	case <-ready:
	case err := <-done:
		t.Fatalf("serve exited before it was ready: %v", err)
	case <-time.After(60 * time.Second):
		t.Fatal("serve was not ready within 60s")
	}
	t.Cleanup(func() {
		close(exit)
		<-done
	})
	return fmt.Sprintf("http://127.0.0.1:%d", port)
}

func freeServeTestPort(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("allocate port: %v", err)
	}
	defer listener.Close()
	return listener.Addr().(*net.TCPAddr).Port
}

func postServeEvaluate(t *testing.T, base, tenantID, principalID, workspaceID, body string) api.EvaluateResponse {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, base+"/api/v1/evaluate", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+testAdminAPIKey)
	req.Header.Set(tenantHeader, tenantID)
	req.Header.Set(principalHeader, principalID)
	if workspaceID != "" {
		req.Header.Set(workspaceHeader, workspaceID)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("evaluate status = %d body=%s", resp.StatusCode, data)
	}
	var response api.EvaluateResponse
	if err := json.Unmarshal(data, &response); err != nil {
		t.Fatal(err)
	}
	return response
}
