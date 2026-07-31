package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	helmcrypto "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
)

func TestQuickstartDryRunJSONIsPurePreview(t *testing.T) {
	dataDir := filepath.Join(t.TempDir(), "new-state")
	resolvedDataDir, err := resolveQuickstartDataDir(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("HELM_ADMIN_API_KEY", "external-admin-key")
	t.Setenv(runtimeTenantIDEnv, "external-tenant")
	t.Setenv(runtimePrincipalIDEnv, "external-principal")
	t.Setenv(quickstartExpiresAtEnv, "external-expiry")
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := runQuickstartCmd([]string{
		"--dry-run",
		"--json",
		"--data-dir", dataDir,
		"--profile", "claude",
	}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("quickstart code=%d stderr=%s", code, stderr.String())
	}

	var summary map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &summary); err != nil {
		t.Fatalf("summary json: %v\n%s", err, stdout.String())
	}
	if summary["operation"] != "preview" {
		t.Fatalf("operation = %v", summary["operation"])
	}
	if summary["kernel_url"] != "http://127.0.0.1:7714" {
		t.Fatalf("kernel_url = %v", summary["kernel_url"])
	}
	if summary["data_dir"] != resolvedDataDir {
		t.Fatalf("data_dir = %v, want %s", summary["data_dir"], resolvedDataDir)
	}
	if actions, _ := summary["planned_actions"].([]any); len(actions) == 0 {
		t.Fatalf("planned_actions missing: %+v", summary)
	}
	for _, field := range []string{"bootstrap_token", "session_token", "token"} {
		if _, ok := summary[field]; ok {
			t.Fatalf("quickstart preview exposed %s: %+v", field, summary)
		}
	}
	if strings.Contains(strings.ToLower(stdout.String()), "token") {
		t.Fatalf("quickstart preview contains token-like output: %s", stdout.String())
	}
	if summary["requires_cloud"] != false || summary["requires_docker"] != false || summary["requires_model_key"] != false {
		t.Fatalf("unexpected first-run requirements: %+v", summary)
	}
	entitlements, _ := summary["entitlements"].([]any)
	if len(entitlements) != 1 || entitlements[0] != "OSS_CORE" {
		t.Fatalf("entitlements = %+v", summary["entitlements"])
	}
	if policyPath, _ := summary["policy_path"].(string); policyPath != filepath.Join(resolvedDataDir, "quickstart", "oss_local_first_run.toml") {
		t.Fatalf("policy_path = %q", policyPath)
	}
	if _, err := os.Stat(dataDir); !os.IsNotExist(err) {
		t.Fatalf("dry-run created data dir: %v", err)
	}
	if got := os.Getenv("HELM_ADMIN_API_KEY"); got != "external-admin-key" {
		t.Fatalf("admin key changed during dry-run: %q", got)
	}
	if got := os.Getenv(runtimeTenantIDEnv); got != "external-tenant" {
		t.Fatalf("tenant changed during dry-run: %q", got)
	}
	if got := os.Getenv(runtimePrincipalIDEnv); got != "external-principal" {
		t.Fatalf("principal changed during dry-run: %q", got)
	}
	if got := os.Getenv(quickstartExpiresAtEnv); got != "external-expiry" {
		t.Fatalf("expiry changed during dry-run: %q", got)
	}
	if stderr.Len() != 0 {
		t.Fatalf("unexpected dry-run stderr: %s", stderr.String())
	}
	if _, err := os.Stat(filepath.Join(dataDir, quickstartOwnershipMarker)); !os.IsNotExist(err) {
		t.Fatalf("dry-run created ownership marker: %v", err)
	}
	if summary["policy_path"] == "" {
		t.Fatal("policy_path missing")
	}
}

func TestQuickstartDryRunResetRunsOwnershipPreflight(t *testing.T) {
	dataDir := filepath.Join(t.TempDir(), "state")
	if err := os.MkdirAll(dataDir, 0750); err != nil {
		t.Fatal(err)
	}
	sentinel := filepath.Join(dataDir, "keep")
	if err := os.WriteFile(sentinel, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	args := []string{"--reset", "--yes", "--dry-run", "--json", "--data-dir", dataDir}
	var stdout, stderr bytes.Buffer

	code := runQuickstartCmd(args, &stdout, &stderr)
	if code != 1 || stdout.Len() != 0 || !strings.Contains(stderr.String(), "unmarked target") {
		t.Fatalf("unmarked reset preview code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	if _, err := os.Stat(sentinel); err != nil {
		t.Fatalf("unsafe dry-run reset touched sentinel: %v", err)
	}

	if err := writeQuickstartOwnershipMarker(dataDir); err != nil {
		t.Fatal(err)
	}
	stdout.Reset()
	stderr.Reset()
	code = runQuickstartCmd(args, &stdout, &stderr)
	if code != 0 || stderr.Len() != 0 {
		t.Fatalf("marked reset preview code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	var summary map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &summary); err != nil || summary["operation"] != "preview" {
		t.Fatalf("marked reset preview = %q, summary=%+v, err=%v", stdout.String(), summary, err)
	}
	if _, err := os.Stat(sentinel); err != nil {
		t.Fatalf("safe dry-run reset touched sentinel: %v", err)
	}
}

func TestQuickstartLiveSummaryDoesNotExposeBootstrapToken(t *testing.T) {
	prepared := quickstartPrepared{
		KernelURL:                  "http://127.0.0.1:7714",
		Profile:                    "mcp",
		LocalSessionCredentialPath: "/private/state/.helm-local-session.json",
		Runtime: &quickstartRuntime{
			BootstrapToken: "live-bootstrap-token",
			TenantID:       "tenant-local",
			PrincipalID:    "principal-local",
			Profile:        "mcp",
			ExpiresAt:      time.Now().UTC().Add(time.Hour),
		},
	}
	summary := prepared.summary("start")
	if _, ok := summary["bootstrap_token"]; ok {
		t.Fatalf("live summary exposed bootstrap token: %+v", summary)
	}
	encoded, err := json.Marshal(summary)
	if err != nil {
		t.Fatalf("marshal live summary: %v", err)
	}
	if strings.Contains(string(encoded), "live-bootstrap-token") {
		t.Fatalf("live summary contains bootstrap token: %s", encoded)
	}
	if summary["local_session_exchange_url"] != "http://127.0.0.1:7714/api/v1/local-session/exchange" {
		t.Fatalf("live summary exchange URL = %v", summary["local_session_exchange_url"])
	}
	if summary["local_session_credential_path"] != prepared.LocalSessionCredentialPath {
		t.Fatalf("live summary credential path = %v", summary["local_session_credential_path"])
	}
}

func TestQuickstartJSONStdoutIsSingleReadyDocument(t *testing.T) {
	t.Setenv("HELM_ADMIN_API_KEY", "previous-admin-key")
	t.Setenv(runtimeTenantIDEnv, "previous-tenant")
	t.Setenv(runtimePrincipalIDEnv, "previous-principal")
	t.Setenv(quickstartExpiresAtEnv, "previous-expiry")
	originalRunQuickstartServer := runQuickstartServer
	t.Cleanup(func() { runQuickstartServer = originalRunQuickstartServer })
	runQuickstartServer = func(opts serverOptions) error {
		if !opts.JSON {
			t.Fatal("quickstart did not propagate JSON mode to the server")
		}
		// Exercise the same production output boundary that runtime startup uses:
		// human narration must be redirected while the ready callback owns stdout.
		_, _ = fmt.Fprintf(serverNarrationWriter(opts), "%sstartup narration%s\n", ColorBold, ColorReset)
		writeServerReady(opts, opts.BindAddr, opts.Port)
		return nil
	}

	dataDir := filepath.Join(t.TempDir(), "state")
	var stdout, stderr bytes.Buffer
	code := runQuickstartCmd([]string{"--json", "--data-dir", dataDir}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("quickstart code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	if strings.Contains(stdout.String(), "\x1b") || strings.Contains(stdout.String(), "startup narration") {
		t.Fatalf("quickstart JSON stdout contains terminal narration: %q", stdout.String())
	}
	if !strings.Contains(stderr.String(), "startup narration") {
		t.Fatalf("quickstart JSON did not route narration to stderr: %q", stderr.String())
	}

	decoder := json.NewDecoder(&stdout)
	var summary map[string]any
	if err := decoder.Decode(&summary); err != nil {
		t.Fatalf("quickstart JSON stdout is not parseable: %v\n%s", err, stdout.String())
	}
	if summary["operation"] != "start" || summary["bootstrap_token"] != nil {
		t.Fatalf("quickstart ready summary = %+v", summary)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		t.Fatalf("quickstart JSON stdout contains more than one document: extra=%+v err=%v", extra, err)
	}
}

func TestQuickstartResetGuardRejectsUnsafeTargets(t *testing.T) {
	home := t.TempDir()
	workspaceRoot := t.TempDir()
	workspace := filepath.Join(workspaceRoot, "workspace")
	if err := os.MkdirAll(workspace, 0750); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	t.Chdir(workspace)

	unmarked := filepath.Join(t.TempDir(), "unmarked")
	if err := os.MkdirAll(unmarked, 0750); err != nil {
		t.Fatal(err)
	}
	unmarkedSentinel := filepath.Join(unmarked, "keep")
	if err := os.WriteFile(unmarkedSentinel, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}

	markedNoYes := filepath.Join(t.TempDir(), "marked-no-yes")
	if err := os.MkdirAll(markedNoYes, 0750); err != nil {
		t.Fatal(err)
	}
	if err := writeQuickstartOwnershipMarker(markedNoYes); err != nil {
		t.Fatal(err)
	}
	markedSentinel := filepath.Join(markedNoYes, "keep")
	if err := os.WriteFile(markedSentinel, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}

	symlinkPath := filepath.Join(t.TempDir(), "home-link")
	if err := os.Symlink(home, symlinkPath); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}

	for _, test := range []struct {
		name     string
		dataDir  string
		yes      bool
		sentinel string
	}{
		{"empty", "", true, ""},
		{"dot", ".", true, ""},
		{"filesystem root", filesystemRoot(workspace), true, ""},
		{"home", home, true, ""},
		{"workspace", workspace, true, ""},
		{"workspace parent", workspaceRoot, true, ""},
		{"symlink escape", symlinkPath, true, ""},
		{"unmarked target", unmarked, true, unmarkedSentinel},
		{"missing yes", markedNoYes, false, markedSentinel},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := validateQuickstartResetTarget(quickstartOptions{DataDir: test.dataDir, Reset: true, Yes: test.yes}); err == nil {
				t.Fatal("expected reset target rejection")
			}
			if test.sentinel != "" {
				if _, err := os.Stat(test.sentinel); err != nil {
					t.Fatalf("unsafe reset touched sentinel: %v", err)
				}
			}
		})
	}
}

func TestQuickstartResetRequiresYesBeforeMutation(t *testing.T) {
	dataDir := filepath.Join(t.TempDir(), "state")
	if err := os.MkdirAll(dataDir, 0750); err != nil {
		t.Fatal(err)
	}
	if err := writeQuickstartOwnershipMarker(dataDir); err != nil {
		t.Fatal(err)
	}
	sentinel := filepath.Join(dataDir, "keep")
	if err := os.WriteFile(sentinel, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	code := runQuickstartCmd([]string{"--reset", "--data-dir", dataDir}, &stdout, &stderr)
	if code != 2 || !strings.Contains(stderr.String(), "--reset requires --yes") {
		t.Fatalf("code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	if _, err := os.Stat(sentinel); err != nil {
		t.Fatalf("missing --yes removed state: %v", err)
	}
}

func TestPrepareQuickstartResetReplacesMarkedState(t *testing.T) {
	dataDir := filepath.Join(t.TempDir(), "state")
	if err := os.MkdirAll(dataDir, 0750); err != nil {
		t.Fatal(err)
	}
	if err := writeQuickstartOwnershipMarker(dataDir); err != nil {
		t.Fatal(err)
	}
	stale := filepath.Join(dataDir, "stale")
	if err := os.WriteFile(stale, []byte("old"), 0600); err != nil {
		t.Fatal(err)
	}

	prepared, err := prepareQuickstart(quickstartOptions{
		Addr:    "127.0.0.1",
		Port:    7714,
		DataDir: dataDir,
		Profile: "mcp",
		Reset:   true,
		Yes:     true,
	})
	if err != nil {
		t.Fatalf("prepare quickstart reset: %v", err)
	}
	if prepared.Runtime == nil || prepared.PolicyPath == "" {
		t.Fatalf("missing prepared runtime: %+v", prepared)
	}
	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Fatalf("stale file survived reset: %v", err)
	}
	if marker, err := os.ReadFile(filepath.Join(dataDir, quickstartOwnershipMarker)); err != nil || string(marker) != quickstartOwnershipMarkerContents {
		t.Fatalf("quickstart ownership marker = %q, err=%v", marker, err)
	}
}

func TestPrepareQuickstartRefusesToClaimExistingDataDirectory(t *testing.T) {
	dataDir := filepath.Join(t.TempDir(), "state")
	if err := os.MkdirAll(dataDir, 0750); err != nil {
		t.Fatal(err)
	}
	sentinel := filepath.Join(dataDir, "unrelated.txt")
	if err := os.WriteFile(sentinel, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}

	_, err := prepareQuickstart(quickstartOptions{
		Addr:    "127.0.0.1",
		Port:    7714,
		DataDir: dataDir,
		Profile: "mcp",
	})
	if err == nil || !strings.Contains(err.Error(), "without a valid HELM quickstart ownership marker") {
		t.Fatalf("prepare existing directory error = %v", err)
	}
	if _, err := os.Stat(sentinel); err != nil {
		t.Fatalf("existing directory was modified: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(dataDir, quickstartOwnershipMarker)); !os.IsNotExist(err) {
		t.Fatalf("existing directory was claimed: %v", err)
	}
}

func TestPrepareQuickstartWritesPrivateLocalSessionCredential(t *testing.T) {
	dataDir := filepath.Join(t.TempDir(), "state")
	prepared, err := prepareQuickstart(quickstartOptions{
		Addr:    "127.0.0.1",
		Port:    7714,
		DataDir: dataDir,
		Profile: "mcp",
	})
	if err != nil {
		t.Fatalf("prepare quickstart: %v", err)
	}
	info, err := os.Stat(prepared.LocalSessionCredentialPath)
	if err != nil {
		t.Fatalf("stat private credential file: %v", err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("private credential mode = %#o", info.Mode().Perm())
	}
	var credential struct {
		Schema         string `json:"schema"`
		ExchangeURL    string `json:"exchange_url"`
		BootstrapToken string `json:"bootstrap_token"`
	}
	content, err := os.ReadFile(prepared.LocalSessionCredentialPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(content, &credential); err != nil {
		t.Fatal(err)
	}
	if credential.Schema != "helm.local-session-bootstrap/v1" || credential.ExchangeURL != prepared.KernelURL+"/api/v1/local-session/exchange" || credential.BootstrapToken != prepared.Runtime.BootstrapToken {
		t.Fatalf("credential = %+v", credential)
	}

	mux := http.NewServeMux()
	RegisterLocalFirstRunRoutes(mux, &Services{}, serverOptions{BindAddr: "127.0.0.1", Port: 7714, Quickstart: prepared.Runtime})
	if rec := postLocalExchange(t, mux, credential.BootstrapToken, "127.0.0.1:49152"); rec.Code != http.StatusOK {
		t.Fatalf("credential exchange status=%d body=%s", rec.Code, rec.Body.String())
	}
	if _, err := os.Stat(prepared.LocalSessionCredentialPath); !os.IsNotExist(err) {
		t.Fatalf("one-time credential remained after exchange: %v", err)
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

func TestQuickstartInstallsGeneratedRuntimeEnv(t *testing.T) {
	runtime := quickstartRouteRuntime()
	t.Setenv("HELM_ADMIN_API_KEY", "external-admin-key")
	t.Setenv(runtimeTenantIDEnv, "external-tenant")
	t.Setenv(runtimePrincipalIDEnv, "external-principal")

	installQuickstartRuntimeEnv(runtime)

	if got := os.Getenv("HELM_ADMIN_API_KEY"); got != runtime.SessionToken {
		t.Fatalf("admin api key = %q, want generated session token", got)
	}
	if got := os.Getenv(runtimeTenantIDEnv); got != runtime.TenantID {
		t.Fatalf("tenant env = %q, want %q", got, runtime.TenantID)
	}
	if got := os.Getenv(runtimePrincipalIDEnv); got != runtime.PrincipalID {
		t.Fatalf("principal env = %q, want %q", got, runtime.PrincipalID)
	}
	if got := os.Getenv(quickstartExpiresAtEnv); got != runtime.ExpiresAt.Format(time.RFC3339Nano) {
		t.Fatalf("quickstart expiry env = %q, want %q", got, runtime.ExpiresAt.Format(time.RFC3339Nano))
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

func TestQuickstartOnboardingRejectsExpiredSession(t *testing.T) {
	runtime := quickstartRouteRuntime()
	runtime.ExpiresAt = time.Now().UTC().Add(-time.Minute)
	t.Setenv("HELM_ADMIN_API_KEY", runtime.SessionToken)
	t.Setenv(runtimeTenantIDEnv, runtime.TenantID)
	t.Setenv(runtimePrincipalIDEnv, runtime.PrincipalID)
	t.Setenv(quickstartExpiresAtEnv, runtime.ExpiresAt.Format(time.RFC3339Nano))

	mux := http.NewServeMux()
	RegisterLocalFirstRunRoutes(mux, &Services{}, serverOptions{Quickstart: runtime})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/onboarding/state", nil)
	authorizeQuickstartRequest(req, runtime)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expired onboarding session status=%d body=%s", rec.Code, rec.Body.String())
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
