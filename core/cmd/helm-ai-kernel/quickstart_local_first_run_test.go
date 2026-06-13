package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	helmcrypto "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
)

func TestQuickstartDryRunJSONPreparesLocalOSSFirstRun(t *testing.T) {
	consoleAssets := makeConsoleAssets(t)
	dataDir := t.TempDir()
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := runQuickstartCmd([]string{
		"--dry-run",
		"--json",
		"--no-open",
		"--data-dir", dataDir,
		"--console-assets", consoleAssets,
		"--profile", "claude",
	}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("quickstart code=%d stderr=%s", code, stderr.String())
	}

	var summary map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &summary); err != nil {
		t.Fatalf("summary json: %v\n%s", err, stdout.String())
	}
	if summary["kernel_url"] != "http://127.0.0.1:7714" {
		t.Fatalf("kernel_url = %v", summary["kernel_url"])
	}
	if !strings.Contains(summary["console_url"].(string), "/console/onboarding?helm_bootstrap_token=") {
		t.Fatalf("console_url missing bootstrap token: %v", summary["console_url"])
	}
	if summary["requires_cloud"] != false || summary["requires_docker"] != false || summary["requires_model_key"] != false {
		t.Fatalf("unexpected first-run requirements: %+v", summary)
	}
	entitlements, _ := summary["entitlements"].([]any)
	if len(entitlements) != 1 || entitlements[0] != "OSS_CORE" {
		t.Fatalf("entitlements = %+v", summary["entitlements"])
	}
	policyPath, _ := summary["policy_path"].(string)
	if policyPath == "" {
		t.Fatal("policy_path missing")
	}
	if _, err := os.Stat(policyPath); err != nil {
		t.Fatalf("policy was not created: %v", err)
	}
}

func TestQuickstartRejectsNonLoopbackBind(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := runQuickstartCmd([]string{"--dry-run", "--addr", "0.0.0.0"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	if !strings.Contains(stderr.String(), "loopback") {
		t.Fatalf("stderr did not explain loopback requirement: %s", stderr.String())
	}
}

func TestQuickstartRejectsInvalidExplicitConsoleAssets(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := runQuickstartCmd([]string{
		"--dry-run",
		"--console-assets", t.TempDir(),
		"--data-dir", t.TempDir(),
	}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	if !strings.Contains(stderr.String(), "index.html") {
		t.Fatalf("stderr did not explain missing index.html: %s", stderr.String())
	}
}

func TestQuickstartLocalSessionExchangeLoopbackOneTimeAndExpiry(t *testing.T) {
	runtime := &quickstartRuntime{
		BootstrapToken: "bootstrap-token",
		SessionToken:   "session-token",
		TenantID:       "tenant-local",
		PrincipalID:    "principal-local",
		Profile:        "mcp",
		ExpiresAt:      time.Now().UTC().Add(time.Hour),
	}
	mux := http.NewServeMux()
	RegisterLocalFirstRunRoutes(mux, &Services{}, serverOptions{BindAddr: "127.0.0.1", Port: 7714, Quickstart: runtime})

	first := postLocalExchange(t, mux, "bootstrap-token", "127.0.0.1:49152")
	if first.Code != http.StatusOK {
		t.Fatalf("first exchange status=%d body=%s", first.Code, first.Body.String())
	}
	var session map[string]any
	if err := json.Unmarshal(first.Body.Bytes(), &session); err != nil {
		t.Fatal(err)
	}
	if session["session_token"] != "session-token" || session["tenant_id"] != "tenant-local" || session["principal_id"] != "principal-local" {
		t.Fatalf("session document = %+v", session)
	}

	reuse := postLocalExchange(t, mux, "bootstrap-token", "127.0.0.1:49152")
	if reuse.Code != http.StatusUnauthorized {
		t.Fatalf("reused token status=%d body=%s", reuse.Code, reuse.Body.String())
	}

	expired := &quickstartRuntime{
		BootstrapToken: "expired-token",
		SessionToken:   "expired-session",
		TenantID:       "tenant-local",
		PrincipalID:    "principal-local",
		Profile:        "mcp",
		ExpiresAt:      time.Now().UTC().Add(-time.Minute),
	}
	expiredMux := http.NewServeMux()
	RegisterLocalFirstRunRoutes(expiredMux, &Services{}, serverOptions{Quickstart: expired})
	expiredRec := postLocalExchange(t, expiredMux, "expired-token", "127.0.0.1:49152")
	if expiredRec.Code != http.StatusUnauthorized {
		t.Fatalf("expired token status=%d body=%s", expiredRec.Code, expiredRec.Body.String())
	}
}

func TestQuickstartLocalSessionExchangeRejectsNonLoopback(t *testing.T) {
	runtime := &quickstartRuntime{
		BootstrapToken: "bootstrap-token",
		SessionToken:   "session-token",
		TenantID:       "tenant-local",
		PrincipalID:    "principal-local",
		Profile:        "mcp",
		ExpiresAt:      time.Now().UTC().Add(time.Hour),
	}
	mux := http.NewServeMux()
	RegisterLocalFirstRunRoutes(mux, &Services{}, serverOptions{Quickstart: runtime})

	rec := postLocalExchange(t, mux, "bootstrap-token", "192.0.2.10:49152")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("non-loopback status=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestQuickstartOnboardingRequiresTenantPrincipalBinding(t *testing.T) {
	runtime := quickstartRouteRuntime()
	t.Setenv("HELM_ADMIN_API_KEY", runtime.SessionToken)
	t.Setenv(runtimeTenantIDEnv, runtime.TenantID)
	t.Setenv(runtimePrincipalIDEnv, runtime.PrincipalID)

	mux := http.NewServeMux()
	RegisterLocalFirstRunRoutes(mux, &Services{}, serverOptions{Quickstart: runtime})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/onboarding/state", nil)
	req.Header.Set("Authorization", "Bearer "+runtime.SessionToken)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("state without tenant/principal status=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestQuickstartOnboardingRejectsExpiredSession(t *testing.T) {
	runtime := quickstartRouteRuntime()
	runtime.ExpiresAt = time.Now().UTC().Add(-time.Minute)
	t.Setenv("HELM_ADMIN_API_KEY", runtime.SessionToken)
	t.Setenv(runtimeTenantIDEnv, runtime.TenantID)
	t.Setenv(runtimePrincipalIDEnv, runtime.PrincipalID)

	mux := http.NewServeMux()
	RegisterLocalFirstRunRoutes(mux, &Services{}, serverOptions{Quickstart: runtime})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/onboarding/state", nil)
	authorizeQuickstartRequest(req, runtime)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expired-session onboarding status=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestQuickstartOnboardingRunStepSignsReceiptAndExportsEvidence(t *testing.T) {
	runtime := quickstartRouteRuntime()
	svc, cleanup := newContractRouteTestServices(t)
	defer cleanup()
	signer, err := helmcrypto.NewEd25519Signer("quickstart-onboarding-test")
	if err != nil {
		t.Fatal(err)
	}
	svc.ReceiptSigner = signer

	t.Setenv("HELM_ADMIN_API_KEY", runtime.SessionToken)
	t.Setenv(runtimeTenantIDEnv, runtime.TenantID)
	t.Setenv(runtimePrincipalIDEnv, runtime.PrincipalID)

	dataDir := t.TempDir()
	mux := http.NewServeMux()
	RegisterLocalFirstRunRoutes(mux, svc, serverOptions{
		PolicyPath: filepath.Join(dataDir, "quickstart", "oss_local_first_run.toml"),
		DataDir:    dataDir,
		Quickstart: runtime,
		BindAddr:   "127.0.0.1",
		Port:       7714,
	})

	body := bytes.NewReader([]byte(`{"step_id":"deny"}`))
	req := httptest.NewRequest(http.MethodPost, "/api/v1/onboarding/run-step", body)
	authorizeQuickstartRequest(req, runtime)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("run-step status=%d body=%s", rec.Code, rec.Body.String())
	}
	var state map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &state); err != nil {
		t.Fatal(err)
	}
	if state["mode"] != "self-hosted-oss" {
		t.Fatalf("state mode = %+v", state)
	}

	receipts, err := svc.ReceiptStore.List(req.Context(), 50)
	if err != nil {
		t.Fatal(err)
	}
	var onboardingReceiptID string
	for _, receipt := range receipts {
		if receipt == nil || receipt.Metadata == nil {
			continue
		}
		if receipt.Metadata["onboarding_step"] == "deny" {
			onboardingReceiptID = receipt.ReceiptID
			if receipt.Status != "DENY" {
				t.Fatalf("receipt status = %q", receipt.Status)
			}
			if receipt.Signature == "" {
				t.Fatal("onboarding receipt was not signed")
			}
			valid, err := signer.VerifyReceipt(receipt)
			if err != nil || !valid {
				t.Fatalf("receipt signature invalid valid=%v err=%v", valid, err)
			}
		}
	}
	if onboardingReceiptID == "" {
		t.Fatalf("signed onboarding receipt not found in %+v", receipts)
	}

	exportReq := httptest.NewRequest(http.MethodGet, "/api/v1/onboarding/export", nil)
	authorizeQuickstartRequest(exportReq, runtime)
	exportRec := httptest.NewRecorder()
	mux.ServeHTTP(exportRec, exportReq)
	if exportRec.Code != http.StatusOK {
		t.Fatalf("export status=%d body=%s", exportRec.Code, exportRec.Body.String())
	}
	var export map[string]any
	if err := json.Unmarshal(exportRec.Body.Bytes(), &export); err != nil {
		t.Fatal(err)
	}
	if export["evidence_pack_ref"] == "" || export["sha256"] == "" {
		t.Fatalf("export missing evidence fields: %+v", export)
	}
	if _, err := os.Stat(filepath.Join(dataDir, "evidence", "onboarding-evidence.json")); err != nil {
		t.Fatalf("evidencepack file not written: %v", err)
	}
}

func TestQuickstartServesSameOriginConsoleSPA(t *testing.T) {
	consoleAssets := makeConsoleAssets(t)
	mux := http.NewServeMux()
	RegisterLocalConsoleAssetRoutes(mux, serverOptions{ConsoleAssetsPath: consoleAssets}, "127.0.0.1", 7714)

	req := httptest.NewRequest(http.MethodGet, "/console/onboarding", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("console status=%d body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "HELM Console") {
		t.Fatalf("console did not serve index.html: %s", rec.Body.String())
	}

	assetReq := httptest.NewRequest(http.MethodGet, "/console/assets/app.js", nil)
	assetRec := httptest.NewRecorder()
	mux.ServeHTTP(assetRec, assetReq)
	if assetRec.Code != http.StatusOK {
		t.Fatalf("asset status=%d body=%s", assetRec.Code, assetRec.Body.String())
	}
	if !strings.Contains(assetRec.Body.String(), "console asset") {
		t.Fatalf("console did not serve nested asset: %s", assetRec.Body.String())
	}
}

func TestQuickstartConsoleAssetServerRejectsTraversal(t *testing.T) {
	consoleAssets := makeConsoleAssets(t)
	if err := os.WriteFile(filepath.Join(filepath.Dir(consoleAssets), "secret.txt"), []byte("outside root"), 0600); err != nil {
		t.Fatal(err)
	}
	bundle, err := loadConsoleAssetBundle(consoleAssets)
	if err != nil {
		t.Fatal(err)
	}
	handler := spaFileServer(bundle)

	req := httptest.NewRequest(http.MethodGet, "/../secret.txt", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("traversal fallback status=%d body=%s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "outside root") {
		t.Fatalf("traversal request served file outside console root: %s", rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "HELM Console") {
		t.Fatalf("traversal request did not fall back to index.html: %s", rec.Body.String())
	}
}

func postLocalExchange(t *testing.T, mux *http.ServeMux, token string, remoteAddr string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/local-session/exchange", strings.NewReader(`{"token":"`+token+`"}`))
	req.RemoteAddr = remoteAddr
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec
}

func quickstartRouteRuntime() *quickstartRuntime {
	return &quickstartRuntime{
		BootstrapToken: "bootstrap-token",
		SessionToken:   "session-token",
		TenantID:       "tenant-local",
		PrincipalID:    "principal-local",
		Profile:        "mcp",
		ExpiresAt:      time.Now().UTC().Add(time.Hour),
	}
}

func authorizeQuickstartRequest(req *http.Request, runtime *quickstartRuntime) {
	req.Header.Set("Authorization", "Bearer "+runtime.SessionToken)
	req.Header.Set(tenantHeader, runtime.TenantID)
	req.Header.Set(principalHeader, runtime.PrincipalID)
}

func makeConsoleAssets(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "index.html"), []byte("<!doctype html><title>HELM Console</title>"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "assets"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "assets", "app.js"), []byte("console asset"), 0600); err != nil {
		t.Fatal(err)
	}
	return dir
}
