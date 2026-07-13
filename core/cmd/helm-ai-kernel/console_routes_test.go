package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
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
	summary, ok := payload["summary"].(map[string]any)
	if !ok {
		t.Fatalf("replay surface summary = %#v", payload["summary"])
	}
	if summary["replay_verification"] != "not_run" {
		t.Fatalf("replay verification = %v, want not_run", summary["replay_verification"])
	}
	if strings.Contains(strings.ToLower(summary["console_record_scope"].(string)), "bundle") && summary["verification_io"] == "operator-provided evidence bundle" {
		t.Fatalf("replay surface still implies that the console performed bundle verification: %#v", summary)
	}
}

func TestConsoleSeparatesReceiptTypesAndDoesNotClaimReplayVerification(t *testing.T) {
	now := time.Date(2026, time.July, 13, 12, 0, 0, 0, time.UTC)
	receipts := []*contracts.Receipt{
		{ReceiptID: "decision-allow", Type: contracts.ReceiptTypeDecision, ExecutorID: "agent-a", Status: "ALLOW", Timestamp: now},
		{ReceiptID: "decision-deny", Type: contracts.ReceiptTypeDecision, ExecutorID: "agent-a", Status: "DENY", Timestamp: now.Add(time.Second)},
		{ReceiptID: "execution", Type: contracts.ReceiptTypeExecution, ExecutorID: "agent-a", EffectID: "tool.send", Status: "SUCCESS", Timestamp: now.Add(2 * time.Second)},
		{ReceiptID: "local", Type: contracts.ReceiptTypeLocalActivity, ExecutorID: "agent-a", Status: "RECORDED", Timestamp: now.Add(3 * time.Second)},
		{ReceiptID: "simulation", Type: contracts.ReceiptTypeSimulation, ExecutorID: "agent-a", EffectID: "demo.action", Status: "SIMULATED", Timestamp: now.Add(4 * time.Second)},
	}

	actions := aggregateActions(receipts)
	if len(actions) != 1 || actions[0]["action"] != "tool.send" || actions[0]["count"] != 1 {
		t.Fatalf("actions should include only dispatched execution receipts, got %#v", actions)
	}

	agents := aggregateAgents(receipts)
	if len(agents) != 1 {
		t.Fatalf("agent records = %#v", agents)
	}
	agent := agents[0]
	for key, want := range map[string]int{
		"receipts":         5,
		"evaluated":        2,
		"executed":         1,
		"denied":           1,
		"local_activities": 1,
		"simulations":      1,
		"unclassified":     0,
	} {
		if got, ok := agent[key].(int); !ok || got != want {
			t.Fatalf("agent %s = %#v, want %d in %#v", key, agent[key], want, agent)
		}
	}
	if agent["last_event_type"] != "simulation" || agent["last_status"] != "SIMULATED" {
		t.Fatalf("agent last event = %#v", agent)
	}

	audit := receiptAuditRecords(receipts)
	if audit[0]["event_type"] != "decision" || audit[2]["event_type"] != "execution" || audit[3]["event_type"] != "local_activity" || audit[4]["event_type"] != "simulation" {
		t.Fatalf("audit receipt types = %#v", audit)
	}

	replay := replayConsoleRecords(nil, receipts)
	if len(replay) != len(receipts) {
		t.Fatalf("replay records = %#v", replay)
	}
	for _, record := range replay {
		if _, legacy := record["signature"]; legacy {
			t.Fatalf("replay record still treats signature presence as verification: %#v", record)
		}
		if record["signature_verification"] != "not_configured" || record["replay_verification"] != "not_run" {
			t.Fatalf("replay record claims verification without a trusted verifier: %#v", record)
		}
	}

	summary := receiptTypeSummary(receipts)
	if summary["decisions"] != 2 || summary["executions"] != 1 || summary["local_activities"] != 1 || summary["simulations"] != 1 || summary["unclassified"] != 0 {
		t.Fatalf("receipt type summary = %#v", summary)
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
