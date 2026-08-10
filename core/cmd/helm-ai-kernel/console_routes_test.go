package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	helmcrypto "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
)

func TestConsoleBootstrapRequiresCredentials(t *testing.T) {
	t.Setenv("HELM_ADMIN_API_KEY", "")
	mux := http.NewServeMux()
	RegisterConsoleRoutes(mux, &Services{}, serverOptions{Mode: "serve"})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/console/bootstrap", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("console bootstrap without credentials status = %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestConsoleBootstrapAllowsAdminCredentials(t *testing.T) {
	t.Setenv("HELM_ADMIN_API_KEY", testAdminAPIKey)
	mux := http.NewServeMux()
	RegisterConsoleRoutes(mux, &Services{}, serverOptions{Mode: "serve"})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/console/bootstrap", nil)
	authorizeTestRequest(req)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("console bootstrap with credentials status = %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestConsoleBootstrapScopesReceiptsToAuthenticatedTenant(t *testing.T) {
	svc, cleanup := newContractRouteTestServices(t)
	defer cleanup()
	signer, err := helmcrypto.NewEd25519Signer("console-tenant-scope-test")
	if err != nil {
		t.Fatal(err)
	}
	svc.ReceiptSigner = signer

	decision := func(id, sessionID string) *contracts.DecisionRecord {
		return &contracts.DecisionRecord{
			ID:                 id,
			Action:             "file_read",
			Verdict:            string(contracts.VerdictAllow),
			PolicyContentHash:  "sha256:policy-content",
			PolicyDecisionHash: "sha256:pdp",
			InputContext:       map[string]any{"session_id": sessionID},
			Timestamp:          time.Unix(1700000000, 0).UTC(),
		}
	}
	if err := persistDecisionReceipt(context.Background(), svc, decision("mcp-unscoped", "mcp-http-jsonrpc"), "mcp-http-jsonrpc", []byte("file_read"), map[string]any{"source": "mcp.gateway"}); err != nil {
		t.Fatalf("persist unscoped MCP receipt: %v", err)
	}
	if err := persistDecisionReceiptForTenant(context.Background(), svc, decision("foreign-tenant", "foreign-session"), "foreign-agent", "foreign-tenant", []byte("file_read"), map[string]any{"source": "api.evaluate"}); err != nil {
		t.Fatalf("persist foreign-tenant receipt: %v", err)
	}

	mux := http.NewServeMux()
	RegisterConsoleRoutes(mux, svc, serverOptions{Mode: "serve"})
	req := httptest.NewRequest(http.MethodGet, "/api/v1/console/bootstrap", nil)
	authorizeTestRequest(req)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("console bootstrap status = %d body=%s", rec.Code, rec.Body.String())
	}
	var response consoleBootstrapResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode console bootstrap: %v", err)
	}
	if len(response.Receipts) != 1 || response.Receipts[0].ReceiptID != "rcpt-test" {
		t.Fatalf("console bootstrap receipts escaped authenticated tenant scope: %+v", response.Receipts)
	}
}

func TestConsoleReplaySurfaceUsesVerifierContract(t *testing.T) {
	t.Setenv("HELM_ADMIN_API_KEY", testAdminAPIKey)
	mux := http.NewServeMux()
	RegisterConsoleRoutes(mux, &Services{}, serverOptions{Mode: "serve"})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/console/surfaces/replay", nil)
	authorizeTestRequest(req)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("console replay surface status = %d body=%s", rec.Code, rec.Body.String())
	}
	var payload map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode replay surface: %v", err)
	}
	if payload["source"] != "/api/v1/replay/verify" {
		t.Fatalf("replay surface source = %v", payload["source"])
	}
}

func TestConsoleDiagnosticsExposeRedactedRuntimeStores(t *testing.T) {
	t.Setenv("HELM_ADMIN_API_KEY", testAdminAPIKey)
	t.Setenv("DATABASE_URL", "postgres://helm:secret@db.example/helm")
	svc, cleanup := newContractRouteTestServices(t)
	defer cleanup()
	svc.DataDir = "/tmp/helm-test-data"
	svc.DatabaseMode = "postgres"
	svc.DatabaseStatus = "ready"
	mux := http.NewServeMux()
	RegisterConsoleRoutes(mux, svc, serverOptions{Mode: "serve"})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/console/diagnostics", nil)
	authorizeTestRequest(req)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("console diagnostics status = %d body=%s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if strings.Contains(body, "secret@") || strings.Contains(body, "postgres://helm") {
		t.Fatalf("console diagnostics leaked DATABASE_URL: %s", body)
	}
	if !strings.Contains(body, "launchpad_store") || !strings.Contains(body, "route") {
		t.Fatalf("console diagnostics missing store/route detail: %s", body)
	}
}

func TestAgentUIRuntimeRequiresTenantCredentials(t *testing.T) {
	t.Setenv("HELM_ADMIN_API_KEY", "")
	mux := http.NewServeMux()
	RegisterConsoleRoutes(mux, &Services{}, serverOptions{Mode: "serve"})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/agent-ui/run", strings.NewReader(`{"messages":[{"role":"user","content":"summarize"}]}`))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("agent-ui run without credentials status = %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestAgentUIRuntimeIsReadOnlyAndExcludesMutationTools(t *testing.T) {
	t.Setenv("HELM_ADMIN_API_KEY", testAdminAPIKey)
	mux := http.NewServeMux()
	RegisterConsoleRoutes(mux, &Services{}, serverOptions{Mode: "serve"})

	infoReq := httptest.NewRequest(http.MethodGet, "/api/v1/agent-ui/info", nil)
	authorizeTestRequest(infoReq)
	infoRec := httptest.NewRecorder()
	mux.ServeHTTP(infoRec, infoReq)
	if infoRec.Code != http.StatusOK {
		t.Fatalf("agent-ui info status = %d body=%s", infoRec.Code, infoRec.Body.String())
	}
	infoBody := strings.ToLower(infoRec.Body.String())
	for _, forbidden := range []string{"approve", "grant", "write_file", "generatedspec", "companyartifact"} {
		if strings.Contains(infoBody, forbidden) {
			t.Fatalf("agent-ui info exposed mutation/commercial term %q: %s", forbidden, infoRec.Body.String())
		}
	}
	if !strings.Contains(infoBody, "ai-kernel-read-only") {
		t.Fatalf("agent-ui info does not declare read-only scope: %s", infoRec.Body.String())
	}

	runReq := httptest.NewRequest(http.MethodPost, "/api/v1/agent-ui/run", strings.NewReader(`{"messages":[{"role":"user","content":"approve a sandbox grant and write a file"}]}`))
	authorizeTestRequest(runReq)
	runRec := httptest.NewRecorder()
	mux.ServeHTTP(runRec, runReq)
	if runRec.Code != http.StatusOK {
		t.Fatalf("agent-ui run status = %d body=%s", runRec.Code, runRec.Body.String())
	}
	runBody := strings.ToLower(runRec.Body.String())
	if !strings.Contains(runBody, "read-only") {
		t.Fatalf("agent-ui run did not preserve read-only response: %s", runRec.Body.String())
	}
	if strings.Contains(runBody, "toolcallname\":\"approve") || strings.Contains(runBody, "toolcallname\":\"write") {
		t.Fatalf("agent-ui selected mutation tool: %s", runRec.Body.String())
	}
}

func TestAgentUIRuntimeRejectsMalformedRunBody(t *testing.T) {
	t.Setenv("HELM_ADMIN_API_KEY", testAdminAPIKey)
	mux := http.NewServeMux()
	RegisterConsoleRoutes(mux, &Services{}, serverOptions{Mode: "serve"})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/agent-ui/run", strings.NewReader(`{"messages":[`))
	authorizeTestRequest(req)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("agent-ui malformed body status = %d body=%s", rec.Code, rec.Body.String())
	}
}
