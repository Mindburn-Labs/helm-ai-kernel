package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	helmcrypto "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/store"
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

func TestQuickstartSourceBuildFromRepoRootUsesDedicatedUserState(t *testing.T) {
	t.Setenv("GOWORK", "off")
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	repoRoot := filepath.Clean(filepath.Join(wd, "..", "..", ".."))
	if _, err := os.Stat(filepath.Join(repoRoot, "data", ".keep")); err != nil {
		t.Fatalf("tracked repo data marker: %v", err)
	}
	binary := filepath.Join(t.TempDir(), "helm-ai-kernel")
	build := exec.Command("go", "build", "-o", binary, "./core/cmd/helm-ai-kernel")
	build.Dir = repoRoot
	build.Env = os.Environ()
	for i, entry := range build.Env {
		if strings.HasPrefix(entry, "GOWORK=") {
			build.Env[i] = "GOWORK="
		}
	}
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("source build from repo root: %v\n%s", err, out)
	}

	home := filepath.Join(t.TempDir(), "home")
	if err := os.MkdirAll(home, 0o750); err != nil {
		t.Fatal(err)
	}
	wantDataDir, err := resolveQuickstartDataDir(filepath.Join(home, ".helm-ai-kernel", "quickstart"))
	if err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"quickstart", "--dry-run", "--json"},
		{"setup", "--quickstart", "--dry-run", "--json"},
	} {
		var stdout, stderr bytes.Buffer
		cmd := exec.Command(binary, args...)
		cmd.Dir = repoRoot
		cmd.Env = append(os.Environ(), "HOME="+home)
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr
		if err := cmd.Run(); err != nil {
			t.Fatalf("%v: %v\nstdout=%s\nstderr=%s", args, err, stdout.String(), stderr.String())
		}
		var summary struct {
			DataDir string `json:"data_dir"`
		}
		if err := json.Unmarshal(stdout.Bytes(), &summary); err != nil {
			t.Fatalf("%v returned invalid JSON: %v\n%s", args, err, stdout.String())
		}
		if summary.DataDir != wantDataDir {
			t.Fatalf("%v data_dir = %q, want %q", args, summary.DataDir, wantDataDir)
		}
		if stderr.Len() != 0 {
			t.Fatalf("%v stderr=%s", args, stderr.String())
		}
	}
}

func TestQuickstartExplicitDataDirRemainsExactAcrossFrontDoors(t *testing.T) {
	dataDir := filepath.Join(t.TempDir(), "explicit-state")
	resolvedDataDir, err := resolveQuickstartDataDir(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"quickstart", "--data-dir", dataDir, "--dry-run", "--json"},
		{"setup", "--quickstart", "--data-dir", dataDir, "--dry-run", "--json"},
	} {
		var stdout, stderr bytes.Buffer
		if code := Run(append([]string{"helm-ai-kernel"}, args...), &stdout, &stderr); code != 0 {
			t.Fatalf("%v code=%d stdout=%s stderr=%s", args, code, stdout.String(), stderr.String())
		}
		var summary struct {
			DataDir string `json:"data_dir"`
		}
		if err := json.Unmarshal(stdout.Bytes(), &summary); err != nil {
			t.Fatalf("%v returned invalid JSON: %v\n%s", args, err, stdout.String())
		}
		if summary.DataDir != resolvedDataDir {
			t.Fatalf("%v data_dir = %q, want %q", args, summary.DataDir, resolvedDataDir)
		}
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
		_, _ = fmt.Fprintf(opts.Stderr, "%sstartup narration%s\n", ColorBold, ColorReset)
		logger, format, err := configureServerLogger(opts.Stderr, opts.Mode)
		if err != nil {
			t.Fatal(err)
		}
		writeServerReady(opts, logger, format, opts.BindAddr, opts.Port)
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

func TestPrepareQuickstartClaimsEmptyExistingDataDirectory(t *testing.T) {
	dataDir := filepath.Join(t.TempDir(), "state")
	if err := os.MkdirAll(dataDir, 0750); err != nil {
		t.Fatal(err)
	}

	prepared, err := prepareQuickstart(quickstartOptions{
		Addr:    "127.0.0.1",
		Port:    7714,
		DataDir: dataDir,
		Profile: "mcp",
	})
	if err != nil {
		t.Fatalf("prepare empty directory: %v", err)
	}
	if prepared.Runtime == nil {
		t.Fatalf("missing prepared runtime: %+v", prepared)
	}
	if err := validateQuickstartOwnershipMarker(dataDir); err != nil {
		t.Fatalf("empty directory was not marked: %v", err)
	}
}

func TestQuickstartDryRunAllowsEmptyExistingDataDirectory(t *testing.T) {
	dataDir := filepath.Join(t.TempDir(), "state")
	if err := os.MkdirAll(dataDir, 0750); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	if code := runQuickstartCmd([]string{"--dry-run", "--json", "--data-dir", dataDir}, &stdout, &stderr); code != 0 {
		t.Fatalf("dry-run code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	if _, err := os.Lstat(filepath.Join(dataDir, quickstartOwnershipMarker)); !os.IsNotExist(err) {
		t.Fatalf("dry-run claimed empty directory: %v", err)
	}
}

func TestPrepareQuickstartMigratesCompleteLegacyState(t *testing.T) {
	dataDir := filepath.Join(t.TempDir(), "state")
	writeLegacyQuickstartFixture(t, dataDir)

	prepared, err := prepareQuickstart(quickstartOptions{
		Addr:    "127.0.0.1",
		Port:    7714,
		DataDir: dataDir,
		Profile: "mcp",
	})
	if err != nil {
		t.Fatalf("migrate legacy quickstart: %v", err)
	}
	if prepared.Runtime == nil || prepared.LocalSessionCredentialPath == "" {
		t.Fatalf("legacy migration did not finish normal startup preparation: %+v", prepared)
	}
	if err := validateQuickstartOwnershipMarker(dataDir); err != nil {
		t.Fatalf("legacy migration did not write current ownership marker: %v", err)
	}
}

func TestQuickstartLegacyMigrationRejectsForeignState(t *testing.T) {
	dataDir := filepath.Join(t.TempDir(), "state")
	writeLegacyQuickstartFixture(t, dataDir)
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
	if err == nil || !strings.Contains(err.Error(), "legacy quickstart layout is not a complete ownership proof") {
		t.Fatalf("foreign state was accepted as legacy quickstart: %v", err)
	}
	if _, err := os.Stat(sentinel); err != nil {
		t.Fatalf("foreign state was modified: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(dataDir, quickstartOwnershipMarker)); !os.IsNotExist(err) {
		t.Fatalf("foreign state was claimed: %v", err)
	}
	if _, err := validateQuickstartResetTarget(quickstartOptions{DataDir: dataDir, Reset: true, Yes: true}); err == nil {
		t.Fatal("foreign state was accepted for reset")
	}
}

func TestQuickstartLegacyMigrationDoesNotReplaceMalformedMarker(t *testing.T) {
	dataDir := filepath.Join(t.TempDir(), "state")
	writeLegacyQuickstartFixture(t, dataDir)
	markerPath := filepath.Join(dataDir, quickstartOwnershipMarker)
	if err := os.WriteFile(markerPath, []byte("not a HELM marker\n"), 0600); err != nil {
		t.Fatal(err)
	}

	_, err := prepareQuickstart(quickstartOptions{
		Addr:    "127.0.0.1",
		Port:    7714,
		DataDir: dataDir,
		Profile: "mcp",
	})
	if err == nil || !strings.Contains(err.Error(), "ownership marker is invalid") {
		t.Fatalf("malformed marker fell back to legacy migration: %v", err)
	}
	marker, err := os.ReadFile(markerPath)
	if err != nil || string(marker) != "not a HELM marker\n" {
		t.Fatalf("malformed marker was replaced: %q, %v", marker, err)
	}
}

func TestQuickstartResetPreflightAcceptsCompleteLegacyState(t *testing.T) {
	dataDir := filepath.Join(t.TempDir(), "state")
	writeLegacyQuickstartFixture(t, dataDir)

	target, err := validateQuickstartResetTarget(quickstartOptions{DataDir: dataDir, Reset: true, Yes: true})
	if err != nil {
		t.Fatalf("legacy state was rejected for explicit reset: %v", err)
	}
	resolvedDataDir, err := resolveQuickstartDataDir(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	if target != resolvedDataDir {
		t.Fatalf("reset target = %q, want %q", target, resolvedDataDir)
	}
	if _, err := os.Lstat(filepath.Join(dataDir, quickstartOwnershipMarker)); !os.IsNotExist(err) {
		t.Fatalf("reset preflight mutated legacy state: %v", err)
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

	reader := svc.ReceiptStore.(store.TenantScopedLatestReceiptReader)
	receipts, err := reader.ListLatestByTenant(req.Context(), runtime.TenantID, 50)
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

func TestQuickstartOnboardingExcludesForeignTenantStateAndExport(t *testing.T) {
	svc, cleanup := newContractRouteTestServices(t)
	defer cleanup()
	signer, err := helmcrypto.NewEd25519Signer("quickstart-onboarding-tenant-isolation-test")
	if err != nil {
		t.Fatal(err)
	}
	svc.ReceiptSigner = signer

	foreignRuntime := quickstartRouteRuntime()
	foreignRuntime.SessionToken = "foreign-session-token"
	foreignRuntime.TenantID = "tenant-foreign"
	foreignRuntime.PrincipalID = "principal-foreign"
	t.Setenv("HELM_ADMIN_API_KEY", foreignRuntime.SessionToken)
	t.Setenv(runtimeTenantIDEnv, foreignRuntime.TenantID)
	t.Setenv(runtimePrincipalIDEnv, foreignRuntime.PrincipalID)
	foreignMux := http.NewServeMux()
	RegisterLocalFirstRunRoutes(foreignMux, svc, serverOptions{Quickstart: foreignRuntime})

	foreignReq := httptest.NewRequest(http.MethodPost, "/api/v1/onboarding/run-step", strings.NewReader(`{"step_id":"deny"}`))
	authorizeQuickstartRequest(foreignReq, foreignRuntime)
	foreignRec := httptest.NewRecorder()
	foreignMux.ServeHTTP(foreignRec, foreignReq)
	if foreignRec.Code != http.StatusOK {
		t.Fatalf("foreign run-step status=%d body=%s", foreignRec.Code, foreignRec.Body.String())
	}
	foreignState := decodeOnboardingPayload(t, foreignRec)
	foreignDeny := onboardingStepPayload(t, foreignState, "deny")
	foreignReceiptID, _ := foreignDeny["receipt_ref"].(string)
	if foreignReceiptID == "" || foreignDeny["status"] != "pass" {
		t.Fatalf("foreign deny step = %+v", foreignDeny)
	}

	localRuntime := quickstartRouteRuntime()
	t.Setenv("HELM_ADMIN_API_KEY", localRuntime.SessionToken)
	t.Setenv(runtimeTenantIDEnv, localRuntime.TenantID)
	t.Setenv(runtimePrincipalIDEnv, localRuntime.PrincipalID)
	localMux := http.NewServeMux()
	RegisterLocalFirstRunRoutes(localMux, svc, serverOptions{Quickstart: localRuntime})

	stateReq := httptest.NewRequest(http.MethodGet, "/api/v1/onboarding/state", nil)
	authorizeQuickstartRequest(stateReq, localRuntime)
	stateRec := httptest.NewRecorder()
	localMux.ServeHTTP(stateRec, stateReq)
	if stateRec.Code != http.StatusOK {
		t.Fatalf("local state status=%d body=%s", stateRec.Code, stateRec.Body.String())
	}
	localState := decodeOnboardingPayload(t, stateRec)
	localDenyBefore := onboardingStepPayload(t, localState, "deny")
	if localDenyBefore["status"] != "pending" || localDenyBefore["receipt_ref"] != "" {
		t.Fatalf("foreign receipt changed local onboarding status: %+v", localDenyBefore)
	}
	if strings.Contains(stateRec.Body.String(), foreignReceiptID) {
		t.Fatalf("local state leaked foreign receipt %q: %s", foreignReceiptID, stateRec.Body.String())
	}

	exportReq := httptest.NewRequest(http.MethodGet, "/api/v1/onboarding/export", nil)
	authorizeQuickstartRequest(exportReq, localRuntime)
	exportRec := httptest.NewRecorder()
	localMux.ServeHTTP(exportRec, exportReq)
	if exportRec.Code != http.StatusOK {
		t.Fatalf("local export status=%d body=%s", exportRec.Code, exportRec.Body.String())
	}
	localExportBefore := decodeOnboardingPayload(t, exportRec)
	localExportDenyBefore := onboardingStepPayload(t, localExportBefore, "deny")
	if localExportDenyBefore["status"] != "pending" || localExportDenyBefore["receipt_ref"] != "" {
		t.Fatalf("foreign receipt changed local export status: %+v", localExportDenyBefore)
	}
	if strings.Contains(exportRec.Body.String(), foreignReceiptID) {
		t.Fatalf("local export leaked foreign receipt %q: %s", foreignReceiptID, exportRec.Body.String())
	}

	localRunReq := httptest.NewRequest(http.MethodPost, "/api/v1/onboarding/run-step", strings.NewReader(`{"step_id":"deny"}`))
	authorizeQuickstartRequest(localRunReq, localRuntime)
	localRunRec := httptest.NewRecorder()
	localMux.ServeHTTP(localRunRec, localRunReq)
	if localRunRec.Code != http.StatusOK {
		t.Fatalf("local run-step status=%d body=%s", localRunRec.Code, localRunRec.Body.String())
	}
	localDenyAfter := onboardingStepPayload(t, decodeOnboardingPayload(t, localRunRec), "deny")
	localReceiptID, _ := localDenyAfter["receipt_ref"].(string)
	if localReceiptID == "" || localReceiptID == foreignReceiptID || localDenyAfter["status"] != "pass" {
		t.Fatalf("local deny step = %+v, foreign receipt=%q", localDenyAfter, foreignReceiptID)
	}

	localExportReq := httptest.NewRequest(http.MethodGet, "/api/v1/onboarding/export", nil)
	authorizeQuickstartRequest(localExportReq, localRuntime)
	localExportRec := httptest.NewRecorder()
	localMux.ServeHTTP(localExportRec, localExportReq)
	if localExportRec.Code != http.StatusOK {
		t.Fatalf("local export after run status=%d body=%s", localExportRec.Code, localExportRec.Body.String())
	}
	localExportAfter := decodeOnboardingPayload(t, localExportRec)
	localExportDenyAfter := onboardingStepPayload(t, localExportAfter, "deny")
	if localExportDenyAfter["status"] != "pass" || localExportDenyAfter["receipt_ref"] != localReceiptID {
		t.Fatalf("local export deny step = %+v, want receipt=%q", localExportDenyAfter, localReceiptID)
	}
	if strings.Contains(localExportRec.Body.String(), foreignReceiptID) {
		t.Fatalf("local export after run leaked foreign receipt %q: %s", foreignReceiptID, localExportRec.Body.String())
	}

	reader := svc.ReceiptStore.(store.TenantScopedLatestReceiptReader)
	foreignReceipts, err := reader.ListLatestByTenant(context.Background(), foreignRuntime.TenantID, 10)
	if err != nil {
		t.Fatal(err)
	}
	localReceipts, err := reader.ListLatestByTenant(context.Background(), localRuntime.TenantID, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(foreignReceipts) != 1 || foreignReceipts[0].ReceiptID != foreignReceiptID {
		t.Fatalf("foreign tenant receipts = %+v", foreignReceipts)
	}
	if len(localReceipts) != 1 || localReceipts[0].ReceiptID != localReceiptID {
		t.Fatalf("local tenant receipts = %+v", localReceipts)
	}
}

func TestQuickstartOnboardingProofSurvivesMoreThanFiveHundredNewerTenantReceipts(t *testing.T) {
	runtime := quickstartRouteRuntime()
	svc, cleanup := newContractRouteTestServices(t)
	defer cleanup()
	signer, err := helmcrypto.NewEd25519Signer("quickstart-onboarding-proof-retention-test")
	if err != nil {
		t.Fatal(err)
	}
	svc.ReceiptSigner = signer
	t.Setenv("HELM_ADMIN_API_KEY", runtime.SessionToken)
	t.Setenv(runtimeTenantIDEnv, runtime.TenantID)
	t.Setenv(runtimePrincipalIDEnv, runtime.PrincipalID)

	mux := http.NewServeMux()
	RegisterLocalFirstRunRoutes(mux, svc, serverOptions{Quickstart: runtime})
	runReq := httptest.NewRequest(http.MethodPost, "/api/v1/onboarding/run-step", strings.NewReader(`{"step_id":"deny"}`))
	authorizeQuickstartRequest(runReq, runtime)
	runRec := httptest.NewRecorder()
	mux.ServeHTTP(runRec, runReq)
	if runRec.Code != http.StatusOK {
		t.Fatalf("run-step status=%d body=%s", runRec.Code, runRec.Body.String())
	}
	deniedStep := onboardingStepPayload(t, decodeOnboardingPayload(t, runRec), "deny")
	onboardingReceiptID, _ := deniedStep["receipt_ref"].(string)
	if onboardingReceiptID == "" {
		t.Fatalf("deny step has no receipt: %+v", deniedStep)
	}

	base := time.Now().UTC().Add(time.Second)
	for i := 0; i < 501; i++ {
		decision := &contracts.DecisionRecord{
			ID:                 fmt.Sprintf("post-onboarding-%03d", i),
			SubjectID:          runtime.PrincipalID,
			Action:             "FILE_READ",
			Resource:           fmt.Sprintf("local.file.%03d", i),
			Verdict:            string(contracts.VerdictAllow),
			Reason:             "proof retention regression",
			ReasonCode:         "SAFE_REQUEST_ALLOWED",
			PolicyBackend:      "test",
			PolicyContentHash:  "sha256:policy-content",
			PolicyDecisionHash: "sha256:policy-decision",
			Timestamp:          base.Add(time.Duration(i) * time.Millisecond),
		}
		if err := persistDecisionReceiptForTenant(context.Background(), svc, decision, runtime.PrincipalID, runtime.TenantID, []byte(decision.Resource), map[string]any{"source": "test.bulk"}); err != nil {
			t.Fatalf("persist newer receipt %d: %v", i, err)
		}
	}
	recent, err := svc.ReceiptStore.(store.TenantScopedLatestReceiptReader).ListLatestByTenant(context.Background(), runtime.TenantID, 500)
	if err != nil {
		t.Fatal(err)
	}
	for _, receipt := range recent {
		if receipt.ReceiptID == onboardingReceiptID {
			t.Fatalf("test setup did not age onboarding receipt %q beyond latest-500 window", onboardingReceiptID)
		}
	}

	for _, endpoint := range []string{"/api/v1/onboarding/state", "/api/v1/onboarding/export"} {
		req := httptest.NewRequest(http.MethodGet, endpoint, nil)
		authorizeQuickstartRequest(req, runtime)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s status=%d body=%s", endpoint, rec.Code, rec.Body.String())
		}
		step := onboardingStepPayload(t, decodeOnboardingPayload(t, rec), "deny")
		if step["status"] != "pass" || step["receipt_ref"] != onboardingReceiptID {
			t.Fatalf("%s lost aged onboarding proof: step=%+v want receipt=%q", endpoint, step, onboardingReceiptID)
		}
	}
}

type receiptStoreWithoutOnboardingCapabilities struct {
	store.ReceiptStore
}

type onboardingReceiptReaderStub struct {
	store.ReceiptStore
	err error
}

func (s *onboardingReceiptReaderStub) ListLatestOnboardingByTenant(context.Context, string) ([]*contracts.Receipt, error) {
	return nil, s.err
}

func TestQuickstartOnboardingStateAndExportFailClosedOnProofReadFailure(t *testing.T) {
	runtime := quickstartRouteRuntime()
	t.Setenv("HELM_ADMIN_API_KEY", runtime.SessionToken)
	t.Setenv(runtimeTenantIDEnv, runtime.TenantID)
	t.Setenv(runtimePrincipalIDEnv, runtime.PrincipalID)

	stores := []struct {
		name         string
		receiptStore store.ReceiptStore
	}{
		{name: "missing tenant proof reader", receiptStore: &receiptStoreWithoutOnboardingCapabilities{}},
		{name: "tenant proof read error", receiptStore: &onboardingReceiptReaderStub{err: errors.New("receipt database unavailable")}},
	}
	for _, storeCase := range stores {
		for _, endpoint := range []string{"/api/v1/onboarding/state", "/api/v1/onboarding/export"} {
			t.Run(storeCase.name+" "+endpoint, func(t *testing.T) {
				mux := http.NewServeMux()
				RegisterLocalFirstRunRoutes(mux, &Services{ReceiptStore: storeCase.receiptStore}, serverOptions{Quickstart: runtime})
				req := httptest.NewRequest(http.MethodGet, endpoint, nil)
				authorizeQuickstartRequest(req, runtime)
				rec := httptest.NewRecorder()
				mux.ServeHTTP(rec, req)
				if rec.Code != http.StatusInternalServerError {
					t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
				}
				if strings.Contains(rec.Body.String(), `"status":"pending"`) || strings.Contains(rec.Body.String(), `"receipt_refs":{}`) {
					t.Fatalf("proof read failure produced successful-looking empty state: %s", rec.Body.String())
				}
			})
		}
	}
}

func TestQuickstartOnboardingRunStepFailsClosedWithoutScopedAppender(t *testing.T) {
	runtime := quickstartRouteRuntime()
	signer, err := helmcrypto.NewEd25519Signer("quickstart-onboarding-scoped-appender-test")
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("HELM_ADMIN_API_KEY", runtime.SessionToken)
	t.Setenv(runtimeTenantIDEnv, runtime.TenantID)
	t.Setenv(runtimePrincipalIDEnv, runtime.PrincipalID)

	mux := http.NewServeMux()
	RegisterLocalFirstRunRoutes(mux, &Services{
		ReceiptStore:  &onboardingReceiptReaderStub{},
		ReceiptSigner: signer,
	}, serverOptions{Quickstart: runtime})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/onboarding/run-step", strings.NewReader(`{"step_id":"deny"}`))
	authorizeQuickstartRequest(req, runtime)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
}

func decodeOnboardingPayload(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var payload map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	return payload
}

func onboardingStepPayload(t *testing.T, payload map[string]any, stepID string) map[string]any {
	t.Helper()
	steps, ok := payload["steps"].([]any)
	if !ok {
		t.Fatalf("onboarding payload has no steps: %+v", payload)
	}
	for _, item := range steps {
		step, ok := item.(map[string]any)
		if ok && step["id"] == stepID {
			return step
		}
	}
	t.Fatalf("onboarding step %q not found: %+v", stepID, payload)
	return nil
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

func writeLegacyQuickstartFixture(t *testing.T, dataDir string) {
	t.Helper()
	t.Setenv("HELM_RECEIPT_PROFILE", "")
	if err := os.MkdirAll(filepath.Join(dataDir, "evidence"), 0750); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dataDir, "artifacts"), 0750); err != nil {
		t.Fatal(err)
	}
	db, _, _, err := setupLiteModeWithDataDir(context.Background(), dataDir)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := loadOrGenerateSignerWithDataDir(dataDir); err != nil {
		t.Fatal(err)
	}
	if _, err := ensureQuickstartPolicy(quickstartOptions{Addr: "127.0.0.1", Port: 7714, DataDir: dataDir}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(dataDir, quickstartOwnershipMarker)); !os.IsNotExist(err) {
		t.Fatalf("legacy fixture unexpectedly has ownership marker: %v", err)
	}
}
