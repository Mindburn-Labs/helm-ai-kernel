package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	lpcmd "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/launchpad/cmd"
)

func TestSetupKernelURLPrefersPersistedEndpoint(t *testing.T) {
	orig := setupPersistedKernelURL
	defer func() { setupPersistedKernelURL = orig }()

	opts := setupOptions{Operation: "install"}

	setupPersistedKernelURL = func() string { return "https://api.helm.example" }
	if got := setupKernelURL(opts); got != "https://api.helm.example" {
		t.Errorf("setupKernelURL = %q, want persisted cloud endpoint", got)
	}

	setupPersistedKernelURL = func() string { return "" }
	if got := setupKernelURL(opts); got != "http://127.0.0.1:7714" {
		t.Errorf("setupKernelURL = %q, want localhost fallback", got)
	}
}

func TestWriteRemoteClaudeMCPHeaderNoTokenLeak(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".mcp.json")
	// Pre-existing unrelated server must be preserved.
	if err := os.WriteFile(path, []byte(`{"mcpServers":{"other":{"command":"x","args":["y"]}}}`), 0o600); err != nil {
		t.Fatal(err)
	}

	const secretToken = "access-SECRET-value"
	if err := writeRemoteClaudeMCP(path, "https://api.helm.example/mcp", lpcmd.MachineTokenEnvVar, ""); err != nil {
		t.Fatalf("writeRemoteClaudeMCP: %v", err)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), secretToken) {
		t.Fatalf("config leaked literal token:\n%s", raw)
	}

	var cfg struct {
		MCPServers map[string]struct {
			Command string            `json:"command"`
			Type    string            `json:"type"`
			URL     string            `json:"url"`
			Headers map[string]string `json:"headers"`
		} `json:"mcpServers"`
	}
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatalf("parse config: %v", err)
	}
	if cfg.MCPServers["other"].Command != "x" {
		t.Errorf("pre-existing server not preserved: %+v", cfg.MCPServers)
	}
	helm, ok := cfg.MCPServers[setupMCPServerName]
	if !ok {
		t.Fatalf("helm server not written: %+v", cfg.MCPServers)
	}
	if helm.Type != "http" || helm.URL != "https://api.helm.example/mcp" {
		t.Errorf("remote transport not configured: %+v", helm)
	}
	wantHeader := "Bearer ${" + lpcmd.MachineTokenEnvVar + "}"
	if helm.Headers["Authorization"] != wantHeader {
		t.Errorf("Authorization header = %q, want %q", helm.Headers["Authorization"], wantHeader)
	}
}

func TestWriteRemoteCodexMCPHeaderNoTokenLeak(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	const secretToken = "access-SECRET-value"

	if err := writeRemoteCodexMCP(path, "https://api.helm.example/mcp", lpcmd.MachineTokenEnvVar, ""); err != nil {
		t.Fatalf("writeRemoteCodexMCP: %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	s := string(raw)
	if strings.Contains(s, secretToken) {
		t.Fatalf("config leaked literal token:\n%s", s)
	}
	if !strings.Contains(s, "[mcp_servers."+setupMCPServerName+"]") ||
		!strings.Contains(s, `url = "https://api.helm.example/mcp"`) ||
		!strings.Contains(s, `bearer_token_env_var = "`+lpcmd.MachineTokenEnvVar+`"`) {
		t.Fatalf("codex remote config not written as expected:\n%s", s)
	}
}

func TestWriteRemoteMCPRollbackOnWriteFailure(t *testing.T) {
	orig := connectAtomicWrite
	defer func() { connectAtomicWrite = orig }()
	connectAtomicWrite = func(string, []byte, string) error { return errors.New("simulated write failure") }

	dir := t.TempDir()
	path := filepath.Join(dir, ".mcp.json")
	sentinel := []byte(`{"mcpServers":{"other":{"command":"keep"}}}`)
	if err := os.WriteFile(path, sentinel, 0o600); err != nil {
		t.Fatal(err)
	}

	err := writeRemoteClaudeMCP(path, "https://api.helm.example/mcp", lpcmd.MachineTokenEnvVar, "")
	if err == nil {
		t.Fatal("expected error from injected write failure")
	}

	// Fail-closed: the pre-existing config must be untouched, no partial write.
	got, readErr := os.ReadFile(path)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(got) != string(sentinel) {
		t.Fatalf("config mutated on failed write:\ngot:  %s\nwant: %s", got, sentinel)
	}
	// No stray temp file left behind in the directory.
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".helm-tmp-") {
			t.Errorf("leftover temp file after failed write: %s", e.Name())
		}
	}
}

func TestDeriveCloudMCPURL(t *testing.T) {
	if got := deriveCloudMCPURL("https://api.helm.mindburn.org/"); got != "https://api.helm.mindburn.org/mcp" {
		t.Errorf("deriveCloudMCPURL = %q", got)
	}
}
