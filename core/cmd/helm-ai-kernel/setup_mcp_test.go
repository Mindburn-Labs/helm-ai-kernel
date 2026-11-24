package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestSetupMCPInstalledRequiresExactScopedBinding(t *testing.T) {
	tmp := t.TempDir()
	home := filepath.Join(tmp, "home")
	t.Setenv("HOME", home)
	bin := filepath.Join(tmp, "bin", "helm-ai-kernel")
	dataDir := filepath.Join(tmp, "helm-data")

	for _, test := range []struct {
		target string
		scope  string
	}{
		{target: "claude-code", scope: "user"},
		{target: "claude-code", scope: "project"},
		{target: "codex", scope: "user"},
		{target: "codex", scope: "project"},
	} {
		t.Run(test.target+"_"+test.scope, func(t *testing.T) {
			workspace := filepath.Join(tmp, test.target+"-"+test.scope+"-workspace")
			if err := os.MkdirAll(workspace, 0o750); err != nil {
				t.Fatal(err)
			}
			opts := setupOptions{Target: test.target, Scope: test.scope, Workspace: workspace, DataDir: dataDir}
			path := setupClientConfigPath(opts)

			writeSetupMCPTestConfig(t, test.target, path, bin, dataDir)
			if !setupMCPInstalled(opts, path, bin) {
				t.Fatal("exact MCP binding was not recognized")
			}

			writeSetupMCPTestConfig(t, test.target, path, bin, filepath.Join(tmp, "stale-data"))
			if setupMCPInstalled(opts, path, bin) {
				t.Fatal("MCP binding with stale data directory was reported healthy")
			}

			writeSetupMCPTestConfig(t, test.target, path, filepath.Join(tmp, "stale-bin"), dataDir)
			if setupMCPInstalled(opts, path, bin) {
				t.Fatal("MCP binding with stale Kernel binary was reported healthy")
			}

			otherPath := filepath.Join(tmp, test.target+"-"+test.scope+"-other-config")
			writeSetupMCPTestConfig(t, test.target, otherPath, bin, dataDir)
			if setupMCPInstalled(opts, otherPath, bin) {
				t.Fatal("MCP binding from the wrong scope path was reported healthy")
			}

			outsidePath := filepath.Join(tmp, test.target+"-"+test.scope+"-external-config")
			writeSetupMCPTestConfig(t, test.target, outsidePath, bin, dataDir)
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(outsidePath, path); err != nil {
				t.Skipf("symlinks unavailable: %v", err)
			}
			got := setupMCPInstalled(opts, path, bin)
			if test.scope == "project" && got {
				t.Fatal("project MCP binding through an external symlink was reported healthy")
			}
			if test.scope == "user" && !got {
				t.Fatal("user MCP binding through an external dotfile symlink was not recognized")
			}
		})
	}
}

func TestSetupStatusRejectsStaleMCPDataDir(t *testing.T) {
	for _, test := range []struct {
		target string
		scope  string
	}{
		{target: "claude-code", scope: "user"},
		{target: "claude-code", scope: "project"},
		{target: "codex", scope: "user"},
		{target: "codex", scope: "project"},
	} {
		t.Run(test.target+"_"+test.scope, func(t *testing.T) {
			tmp := t.TempDir()
			stubSetupSideEffects(t)
			t.Setenv("HOME", filepath.Join(tmp, "home"))
			home := filepath.Join(tmp, "home")
			t.Setenv("HOME", home)
			workspace := filepath.Join(tmp, "workspace")
			if err := os.MkdirAll(workspace, 0o750); err != nil {
				t.Fatal(err)
			}
			if test.target == "codex" && test.scope == "project" {
				// Record the workspace as trusted so status reflects an
				// effective (Codex-loadable) install rather than trust-pending.
				markCodexProjectTrusted(t, home, workspace)
			}
			dataDir := filepath.Join(tmp, "helm-data")
			opts := setupOptions{Operation: "status", Target: test.target, Scope: test.scope, Workspace: workspace, DataDir: dataDir}
			summary, err := buildSetupSummary(opts)
			if err != nil {
				t.Fatal(err)
			}
			if err := upsertHookConfig(summary.HookConfigPath, setupHookMatcher(test.target), setupHookCommand(opts, summary.BinaryPath), setupPrivateFileRoot(opts)); err != nil {
				t.Fatalf("write exact hook config: %v", err)
			}
			writeSetupMCPTestConfig(t, test.target, summary.ClientConfigPath, summary.BinaryPath, filepath.Join(tmp, "stale-data"))

			args := []string{"helm-ai-kernel", "setup", "status", test.target, "--scope", test.scope, "--json", "--data-dir", dataDir}
			if test.scope == "project" {
				args = append(args, "--workspace", workspace)
			}
			var stdout, stderr bytes.Buffer
			code := Run(args, &stdout, &stderr)
			if code != 1 {
				t.Fatalf("stale status exit = %d, want 1; stderr=%s stdout=%s", code, stderr.String(), stdout.String())
			}
			stale := decodeSingleSetupSummary(t, &stdout)
			if stale.MCPInstalled || !stale.HookInstalled {
				t.Fatalf("stale status = %#v, want MCP false and hook true", stale)
			}

			writeSetupMCPTestConfig(t, test.target, summary.ClientConfigPath, summary.BinaryPath, dataDir)
			stdout.Reset()
			stderr.Reset()
			code = Run(args, &stdout, &stderr)
			wantCode := 0
			if test.target == "codex" && test.scope == "project" {
				wantCode = 1 // Project-local Codex loading cannot yet be verified natively.
			}
			if code != wantCode {
				t.Fatalf("exact status exit = %d, want %d; stderr=%s stdout=%s", code, wantCode, stderr.String(), stdout.String())
			}
			exact := decodeSingleSetupSummary(t, &stdout)
			if !exact.MCPInstalled || !exact.HookInstalled {
				t.Fatalf("exact status = %#v, want MCP and hook true", exact)
			}
		})
	}
}

func writeSetupMCPTestConfig(t *testing.T, target, path, bin, dataDir string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}
	var raw []byte
	switch target {
	case "claude-code":
		config := claudeMCPConfig{MCPServers: map[string]claudeMCPServer{
			setupMCPServerName: {Command: bin, Args: setupMCPArgs(dataDir)},
		}}
		var err error
		raw, err = json.Marshal(config)
		if err != nil {
			t.Fatal(err)
		}
	case "codex":
		raw = []byte("[mcp_servers." + setupMCPServerName + "]\ncommand = " + strconv.Quote(bin) + "\nargs = [\"mcp\", \"serve\", \"--transport\", \"stdio\", \"--data-dir\", " + strconv.Quote(dataDir) + "]\n")
	case "hermes":
		raw = []byte("mcp_servers:\n  " + setupMCPServerName + ":\n    command: " + strconv.Quote(bin) + "\n    args: [\"mcp\", \"serve\", \"--transport\", \"stdio\", \"--data-dir\", " + strconv.Quote(dataDir) + "]\n")
	default:
		t.Fatalf("unsupported test target %q", target)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestSetupClaudeProjectMCPCommandsUseSelectedWorkspace(t *testing.T) {
	tmp := t.TempDir()
	caller := filepath.Join(tmp, "caller")
	workspace := filepath.Join(tmp, "workspace")
	for _, dir := range []string{caller, workspace} {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			t.Fatal(err)
		}
	}
	t.Chdir(caller)
	canonicalWorkspace, err := filepath.EvalSymlinks(workspace)
	if err != nil {
		t.Fatalf("resolve workspace: %v", err)
	}
	restore := stubSetupSideEffects(t)
	dataDir := filepath.Join(tmp, "helm")

	var stdout, stderr bytes.Buffer
	code := Run([]string{"helm-ai-kernel", "setup", "claude-code", "--scope", "project", "--workspace", workspace, "--yes", "--no-quickstart", "--data-dir", dataDir}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("project setup exit = %d stderr = %s stdout = %s", code, stderr.String(), stdout.String())
	}
	if len(restore.execCalls) != 1 || len(restore.execDirs) != 1 {
		t.Fatalf("project setup exec calls = %#v dirs = %#v", restore.execCalls, restore.execDirs)
	}
	if restore.execDirs[0] != canonicalWorkspace {
		t.Fatalf("project setup exec dir = %q, want %q", restore.execDirs[0], canonicalWorkspace)
	}
	if !strings.Contains(strings.Join(restore.execCalls[0], " "), "claude mcp add --transport stdio --scope project") {
		t.Fatalf("project setup exec call = %#v", restore.execCalls[0])
	}
	bin, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if abs, err := filepath.Abs(bin); err == nil {
		bin = abs
	}
	// The command stub records the client invocation but does not write the
	// config that a real Claude CLI would create. Add the exact owned entry so
	// removal proves it only invokes the client for a verified HELM binding.
	writeSetupMCPTestConfig(t, "claude-code", filepath.Join(canonicalWorkspace, ".mcp.json"), bin, dataDir)

	restore.execCalls = nil
	restore.execDirs = nil
	stdout.Reset()
	stderr.Reset()
	code = Run([]string{"helm-ai-kernel", "setup", "remove", "claude-code", "--scope", "project", "--workspace", workspace, "--yes", "--no-quickstart", "--data-dir", dataDir}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("project remove exit = %d stderr = %s stdout = %s", code, stderr.String(), stdout.String())
	}
	if len(restore.execCalls) != 1 || len(restore.execDirs) != 1 {
		t.Fatalf("project remove exec calls = %#v dirs = %#v", restore.execCalls, restore.execDirs)
	}
	if restore.execDirs[0] != canonicalWorkspace {
		t.Fatalf("project remove exec dir = %q, want %q", restore.execDirs[0], canonicalWorkspace)
	}
	if !strings.Contains(strings.Join(restore.execCalls[0], " "), "claude mcp remove --scope project") {
		t.Fatalf("project remove exec call = %#v", restore.execCalls[0])
	}
}

func TestLocalMCPRuntimeUsesExplicitDataDir(t *testing.T) {
	dataDir := filepath.Join(t.TempDir(), "kernel-store")
	if _, _, err := newLocalMCPRuntimeWithDataDir(dataDir); err != nil {
		t.Fatalf("create local MCP runtime: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dataDir, "root.key")); err != nil {
		t.Fatalf("custom MCP data dir did not receive the signer root key: %v", err)
	}
}
