package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSetupRequiresExplicitDataDirWithoutHome(t *testing.T) {
	t.Setenv("HOME", "")
	var stdout, stderr bytes.Buffer
	code := Run([]string{"helm-ai-kernel", "setup", "claude-code", "--dry-run"}, &stdout, &stderr)
	if code != 2 || !strings.Contains(stderr.String(), "--data-dir is required") {
		t.Fatalf("HOME-less setup = %d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
}

func TestSetupUserScopeRequiresAbsoluteHomeEvenWithDataDir(t *testing.T) {
	commands := [][]string{
		{"helm-ai-kernel", "setup", "codex", "--scope", "user", "--yes"},
		{"helm-ai-kernel", "setup", "status", "codex", "--scope", "user"},
		{"helm-ai-kernel", "setup", "remove", "codex", "--yes"},
	}
	for _, home := range []string{"", "relative-home"} {
		for _, command := range commands {
			name := strings.Join(command[1:3], "-")
			t.Run(home+"/"+name, func(t *testing.T) {
				t.Setenv("HOME", home)
				for _, target := range []string{"claude-code", "codex", "hermes", "deepseek"} {
					opts := setupOptions{Target: target, Scope: "user"}
					if path := setupClientConfigPath(opts); path != "" {
						t.Fatalf("HOME=%q %s client path = %q, want empty", home, target, path)
					}
					if path := setupHookConfigPath(opts); path != "" {
						t.Fatalf("HOME=%q %s hook path = %q, want empty", home, target, path)
					}
				}
				args := append([]string{}, command...)
				args = append(args, "--data-dir", t.TempDir())
				var stdout, stderr bytes.Buffer
				code := Run(args, &stdout, &stderr)
				if code != 2 || !strings.Contains(stderr.String(), "user scope requires an absolute home directory") {
					t.Fatalf("HOME=%q args=%q setup = %d stdout=%s stderr=%s", home, args, code, stdout.String(), stderr.String())
				}
			})
		}
	}
}

func TestSetupProjectScopeDefaultsToCurrentDirectory(t *testing.T) {
	tmp := t.TempDir()
	workspace := filepath.Join(tmp, "workspace")
	if err := os.MkdirAll(workspace, 0o750); err != nil {
		t.Fatal(err)
	}
	t.Chdir(workspace)
	restore := stubSetupSideEffects(t)

	var stdout, stderr bytes.Buffer
	code := Run([]string{"helm-ai-kernel", "setup", "codex", "--scope", "project", "--dry-run", "--json", "--data-dir", filepath.Join(tmp, "helm")}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("project setup without explicit workspace code=%d stderr=%s", code, stderr.String())
	}
	var summary setupSummary
	if err := json.Unmarshal(stdout.Bytes(), &summary); err != nil {
		t.Fatalf("decode project setup summary: %v\n%s", err, stdout.String())
	}
	canonicalWorkspace, err := filepath.EvalSymlinks(workspace)
	if err != nil {
		t.Fatalf("resolve workspace: %v", err)
	}
	if summary.Workspace != canonicalWorkspace {
		t.Fatalf("workspace = %q, want current directory %q", summary.Workspace, canonicalWorkspace)
	}
	if summary.ClientConfigPath != filepath.Join(canonicalWorkspace, ".codex", "config.toml") {
		t.Fatalf("client config path = %q", summary.ClientConfigPath)
	}

	stdout.Reset()
	stderr.Reset()
	code = Run([]string{"helm-ai-kernel", "setup", "codex", "--scope", "project", "--yes", "--no-quickstart", "--json", "--data-dir", filepath.Join(tmp, "helm")}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("project install without explicit workspace code=%d stderr=%s stdout=%s", code, stderr.String(), stdout.String())
	}
	if len(restore.execCalls) != 0 {
		t.Fatalf("Codex project install should write config directly, exec calls = %#v", restore.execCalls)
	}
	if !setupMCPInstalled(setupOptions{Target: "codex", Scope: "project", Workspace: canonicalWorkspace, DataDir: filepath.Join(tmp, "helm")}, summary.ClientConfigPath, summary.BinaryPath) {
		t.Fatal("Codex project install did not write MCP config under the current directory")
	}
	if _, err := os.Stat(filepath.Join(canonicalWorkspace, ".codex", "hooks.json")); err != nil {
		t.Fatalf("Codex project install did not write hook config under the current directory: %v", err)
	}

	stdout.Reset()
	stderr.Reset()
	code = Run([]string{"helm-ai-kernel", "setup", "codex", "--scope", "user", "--workspace", workspace, "--dry-run", "--json", "--data-dir", filepath.Join(tmp, "helm")}, &stdout, &stderr)
	if code != 2 || !strings.Contains(stderr.String(), "only valid with --scope project") {
		t.Fatalf("user setup with workspace code=%d stderr=%s", code, stderr.String())
	}
}

func TestSetupClaudeProjectPreservesSymlinkedHookConfig(t *testing.T) {
	tmp := t.TempDir()
	workspace := filepath.Join(tmp, "workspace")
	targetDir := filepath.Join(workspace, ".managed-dotfiles", "claude")
	for _, dir := range []string{filepath.Join(workspace, ".claude"), targetDir} {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			t.Fatal(err)
		}
	}
	target := filepath.Join(targetDir, "settings.json")
	if err := os.WriteFile(target, []byte("{\"hooks\":{\"PreToolUse\":[]}}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(workspace, ".claude", "settings.json")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	opts := setupOptions{Target: "claude-code", Scope: "project", Workspace: workspace, DataDir: filepath.Join(tmp, "helm")}
	bin := filepath.Join(tmp, "helm-ai-kernel")

	if err := installSetupHook(opts, bin); err != nil {
		t.Fatalf("install symlinked Claude hook: %v", err)
	}
	assertSetupSymlinkTarget(t, link, target, 0o600, "hook pre-tool --client claude-code")
	assertNoSetupTempFiles(t, filepath.Dir(link), targetDir)

	if err := removeSetupHook(opts, bin); err != nil {
		t.Fatalf("remove symlinked Claude hook: %v", err)
	}
	assertSetupSymlinkTarget(t, link, target, 0o600, "")
	if raw, err := os.ReadFile(target); err != nil {
		t.Fatal(err)
	} else if strings.Contains(string(raw), "hook pre-tool --client claude-code") {
		t.Fatalf("Claude hook target still contains HELM command:\n%s", raw)
	}
	assertNoSetupTempFiles(t, filepath.Dir(link), targetDir)
}

func TestSetupCodexProjectPreservesSymlinkedConfigFiles(t *testing.T) {
	tmp := t.TempDir()
	workspace := filepath.Join(tmp, "workspace")
	targetDir := filepath.Join(workspace, ".managed-dotfiles", "codex")
	for _, dir := range []string{filepath.Join(workspace, ".codex"), targetDir} {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			t.Fatal(err)
		}
	}
	configTarget := filepath.Join(targetDir, "config.toml")
	hookTarget := filepath.Join(targetDir, "hooks.json")
	if err := os.WriteFile(configTarget, []byte("model = \"gpt-6-sol\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(hookTarget, []byte("{\"hooks\":{\"PreToolUse\":[]}}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	configLink := filepath.Join(workspace, ".codex", "config.toml")
	hookLink := filepath.Join(workspace, ".codex", "hooks.json")
	if err := os.Symlink(configTarget, configLink); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if err := os.Symlink(hookTarget, hookLink); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	opts := setupOptions{Target: "codex", Scope: "project", Workspace: workspace, DataDir: filepath.Join(tmp, "helm")}
	bin := filepath.Join(tmp, "helm-ai-kernel")

	if err := installSetupMCP(opts, bin); err != nil {
		t.Fatalf("install symlinked Codex MCP config: %v", err)
	}
	if err := installSetupHook(opts, bin); err != nil {
		t.Fatalf("install symlinked Codex hook config: %v", err)
	}
	assertSetupSymlinkTarget(t, configLink, configTarget, 0o600, "[mcp_servers."+setupMCPServerName+"]")
	assertSetupSymlinkTarget(t, hookLink, hookTarget, 0o600, "hook pre-tool --client codex")
	assertNoSetupTempFiles(t, filepath.Dir(configLink), targetDir)

	if err := removeSetupHook(opts, bin); err != nil {
		t.Fatalf("remove symlinked Codex hook config: %v", err)
	}
	if err := removeSetupMCP(opts); err != nil {
		t.Fatalf("remove symlinked Codex MCP config: %v", err)
	}
	assertSetupSymlinkTarget(t, configLink, configTarget, 0o600, "model = \"gpt-6-sol\"")
	assertSetupSymlinkTarget(t, hookLink, hookTarget, 0o600, "")
	for path, forbidden := range map[string]string{
		configTarget: setupMCPServerName,
		hookTarget:   "hook pre-tool --client codex",
	} {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(raw), forbidden) {
			t.Fatalf("%s still contains %q:\n%s", path, forbidden, raw)
		}
	}
	assertNoSetupTempFiles(t, filepath.Dir(configLink), targetDir)
}

func TestSetupProjectRejectsConfigSymlinkEscapes(t *testing.T) {
	t.Run("claude MCP config", func(t *testing.T) {
		tmp := t.TempDir()
		workspace := filepath.Join(tmp, "workspace")
		outside := filepath.Join(tmp, "outside")
		for _, dir := range []string{workspace, outside} {
			if err := os.MkdirAll(dir, 0o750); err != nil {
				t.Fatal(err)
			}
		}
		target := filepath.Join(outside, "mcp.json")
		original := []byte("{\"mcpServers\":{}}\n")
		if err := os.WriteFile(target, original, 0o600); err != nil {
			t.Fatal(err)
		}
		link := filepath.Join(workspace, ".mcp.json")
		if err := os.Symlink(target, link); err != nil {
			t.Skipf("symlinks unavailable: %v", err)
		}
		state := stubSetupSideEffects(t)
		opts := setupOptions{Target: "claude-code", Scope: "project", Workspace: workspace, DataDir: filepath.Join(tmp, "helm")}
		if err := installSetupMCP(opts, filepath.Join(tmp, "helm-ai-kernel")); err == nil || !strings.Contains(err.Error(), "outside project workspace") {
			t.Fatalf("Claude project MCP escape error = %v", err)
		}
		if len(state.execCalls) != 0 {
			t.Fatalf("Claude CLI ran after config escape: %#v", state.execCalls)
		}
		assertSetupFileUnchanged(t, link, target, original)
		assertNoSetupTempFiles(t, workspace, outside)
	})

	t.Run("claude hook config", func(t *testing.T) {
		tmp := t.TempDir()
		workspace := filepath.Join(tmp, "workspace")
		outside := filepath.Join(tmp, "outside")
		for _, dir := range []string{filepath.Join(workspace, ".claude"), outside} {
			if err := os.MkdirAll(dir, 0o750); err != nil {
				t.Fatal(err)
			}
		}
		target := filepath.Join(outside, "settings.json")
		original := []byte("{\"hooks\":{\"PreToolUse\":[]}}\n")
		if err := os.WriteFile(target, original, 0o600); err != nil {
			t.Fatal(err)
		}
		link := filepath.Join(workspace, ".claude", "settings.json")
		if err := os.Symlink(target, link); err != nil {
			t.Skipf("symlinks unavailable: %v", err)
		}
		opts := setupOptions{Target: "claude-code", Scope: "project", Workspace: workspace, DataDir: filepath.Join(tmp, "helm")}
		if err := installSetupHook(opts, filepath.Join(tmp, "helm-ai-kernel")); err == nil || !strings.Contains(err.Error(), "outside project workspace") {
			t.Fatalf("Claude project hook escape error = %v", err)
		}
		assertSetupFileUnchanged(t, link, target, original)
		assertNoSetupTempFiles(t, filepath.Dir(link), outside)
	})

	t.Run("codex config", func(t *testing.T) {
		tmp := t.TempDir()
		workspace := filepath.Join(tmp, "workspace")
		outside := filepath.Join(tmp, "outside")
		for _, dir := range []string{filepath.Join(workspace, ".codex"), outside} {
			if err := os.MkdirAll(dir, 0o750); err != nil {
				t.Fatal(err)
			}
		}
		target := filepath.Join(outside, "config.toml")
		original := []byte("model = \"gpt-6-sol\"\n")
		if err := os.WriteFile(target, original, 0o600); err != nil {
			t.Fatal(err)
		}
		link := filepath.Join(workspace, ".codex", "config.toml")
		if err := os.Symlink(target, link); err != nil {
			t.Skipf("symlinks unavailable: %v", err)
		}
		opts := setupOptions{Target: "codex", Scope: "project", Workspace: workspace, DataDir: filepath.Join(tmp, "helm")}
		if err := installSetupMCP(opts, filepath.Join(tmp, "helm-ai-kernel")); err == nil || !strings.Contains(err.Error(), "outside project workspace") {
			t.Fatalf("Codex project config escape error = %v", err)
		}
		assertSetupFileUnchanged(t, link, target, original)
		assertNoSetupTempFiles(t, filepath.Dir(link), outside)
	})

	t.Run("codex parent directory", func(t *testing.T) {
		tmp := t.TempDir()
		workspace := filepath.Join(tmp, "workspace")
		outside := filepath.Join(tmp, "outside")
		for _, dir := range []string{workspace, outside} {
			if err := os.MkdirAll(dir, 0o750); err != nil {
				t.Fatal(err)
			}
		}
		link := filepath.Join(workspace, ".codex")
		if err := os.Symlink(outside, link); err != nil {
			t.Skipf("symlinks unavailable: %v", err)
		}
		opts := setupOptions{Target: "codex", Scope: "project", Workspace: workspace, DataDir: filepath.Join(tmp, "helm")}
		if err := installSetupMCP(opts, filepath.Join(tmp, "helm-ai-kernel")); err == nil || !strings.Contains(err.Error(), "outside project workspace") {
			t.Fatalf("Codex project parent escape error = %v", err)
		}
		if _, err := os.Stat(filepath.Join(outside, "config.toml")); !os.IsNotExist(err) {
			t.Fatalf("Codex config was created outside workspace, stat error = %v", err)
		}
		if info, err := os.Lstat(link); err != nil {
			t.Fatalf("Codex directory symlink was removed: %v", err)
		} else if info.Mode()&os.ModeSymlink == 0 {
			t.Fatalf("Codex directory mode = %v, want symlink", info.Mode())
		}
		assertNoSetupTempFiles(t, outside)
	})
}

func TestSetupUserScopePreservesExternalHookSymlinks(t *testing.T) {
	for _, target := range []string{"claude-code", "codex"} {
		t.Run(target, func(t *testing.T) {
			tmp := t.TempDir()
			home := filepath.Join(tmp, "home")
			external := filepath.Join(tmp, "managed-dotfiles", target)
			if err := os.MkdirAll(external, 0o750); err != nil {
				t.Fatal(err)
			}
			t.Setenv("HOME", home)
			opts := setupOptions{Target: target, Scope: "user", DataDir: filepath.Join(tmp, "helm")}
			link := setupHookConfigPath(opts)
			if err := os.MkdirAll(filepath.Dir(link), 0o750); err != nil {
				t.Fatal(err)
			}
			managed := filepath.Join(external, "hooks.json")
			if err := os.WriteFile(managed, []byte("{\"hooks\":{\"PreToolUse\":[]}}\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(managed, link); err != nil {
				t.Skipf("symlinks unavailable: %v", err)
			}
			bin := filepath.Join(tmp, "helm-ai-kernel")
			if err := installSetupHook(opts, bin); err != nil {
				t.Fatalf("install user hook through external symlink: %v", err)
			}
			assertSetupSymlinkTarget(t, link, managed, 0o600, "hook pre-tool --client "+target)
			if err := removeSetupHook(opts, bin); err != nil {
				t.Fatalf("remove user hook through external symlink: %v", err)
			}
			assertSetupSymlinkTarget(t, link, managed, 0o600, "")
			assertNoSetupTempFiles(t, filepath.Dir(link), external)
		})
	}
}

func TestWritePrivateFileAtomicRejectsUnsafeSymlinkTargets(t *testing.T) {
	tmp := t.TempDir()
	for _, test := range []struct {
		name   string
		target string
	}{
		{name: "dangling", target: filepath.Join(tmp, "missing.json")},
		{name: "directory", target: filepath.Join(tmp, "directory-target")},
	} {
		t.Run(test.name, func(t *testing.T) {
			if test.name == "directory" {
				if err := os.MkdirAll(test.target, 0o750); err != nil {
					t.Fatal(err)
				}
			}
			linkDir := filepath.Join(tmp, test.name)
			if err := os.MkdirAll(linkDir, 0o750); err != nil {
				t.Fatal(err)
			}
			link := filepath.Join(linkDir, "settings.json")
			if err := os.Symlink(test.target, link); err != nil {
				t.Skipf("symlinks unavailable: %v", err)
			}
			if err := writePrivateFileAtomic(link, []byte("{}\n"), ""); err == nil {
				t.Fatal("unsafe symlink target unexpectedly accepted")
			}
			if info, err := os.Lstat(link); err != nil {
				t.Fatalf("symlink was removed: %v", err)
			} else if info.Mode()&os.ModeSymlink == 0 {
				t.Fatalf("path mode = %v, want symlink", info.Mode())
			}
			assertNoSetupTempFiles(t, linkDir, filepath.Dir(test.target))
		})
	}
}

func TestWritePrivateFileAtomicProjectRejectsParentSwap(t *testing.T) {
	tmp := t.TempDir()
	workspace := filepath.Join(tmp, "workspace")
	configDir := filepath.Join(workspace, ".codex")
	outside := filepath.Join(tmp, "outside")
	for _, dir := range []string{configDir, outside} {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			t.Fatal(err)
		}
	}
	configPath := filepath.Join(configDir, "config.toml")
	original := []byte("model = \"inside\"\n")
	if err := os.WriteFile(configPath, original, 0o600); err != nil {
		t.Fatal(err)
	}
	outsidePath := filepath.Join(outside, "config.toml")
	outsideOriginal := []byte("model = \"outside\"\n")
	if err := os.WriteFile(outsidePath, outsideOriginal, 0o600); err != nil {
		t.Fatal(err)
	}
	movedConfigDir := filepath.Join(workspace, ".codex-before-swap")
	var mutationErr error
	err := writePrivateFileAtomicWithMutationHook(configPath, []byte("model = \"attacker-controlled\"\n"), workspace, func() {
		mutationErr = os.Rename(configDir, movedConfigDir)
		if mutationErr == nil {
			mutationErr = os.Symlink(outside, configDir)
		}
	})
	if mutationErr != nil {
		t.Skipf("parent-swap symlink unavailable: %v", mutationErr)
	}
	if err == nil {
		t.Fatal("project write succeeded after its validated parent was swapped outside the workspace")
	}
	if info, lstatErr := os.Lstat(configDir); lstatErr != nil {
		t.Fatalf("swapped parent missing: %v", lstatErr)
	} else if info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("swapped parent mode = %v, want symlink", info.Mode())
	}
	for path, want := range map[string][]byte{
		filepath.Join(movedConfigDir, "config.toml"): original,
		outsidePath: outsideOriginal,
	} {
		raw, readErr := os.ReadFile(path)
		if readErr != nil {
			t.Fatalf("read %s: %v", path, readErr)
		}
		if !bytes.Equal(raw, want) {
			t.Fatalf("%s changed after parent swap:\n%s", path, raw)
		}
	}
	assertNoSetupTempFiles(t, workspace, movedConfigDir, outside)
}

func TestSetupCodexProjectRejectsMalformedConfigWithoutOverwriting(t *testing.T) {
	tmp := t.TempDir()
	workspace := filepath.Join(tmp, "workspace")
	configPath := filepath.Join(workspace, ".codex", "config.toml")
	if err := os.MkdirAll(filepath.Dir(configPath), 0o750); err != nil {
		t.Fatal(err)
	}
	invalid := "[mcp_servers\ncommand = \"broken\"\n"
	if err := os.WriteFile(configPath, []byte(invalid), 0o600); err != nil {
		t.Fatal(err)
	}
	stubSetupSideEffects(t)

	var stdout, stderr bytes.Buffer
	code := Run([]string{"helm-ai-kernel", "setup", "codex", "--scope", "project", "--workspace", workspace, "--yes", "--no-quickstart", "--data-dir", filepath.Join(tmp, "helm")}, &stdout, &stderr)
	if code != 1 || !strings.Contains(stderr.String(), "parse existing Codex config") {
		t.Fatalf("malformed config setup code=%d stderr=%s", code, stderr.String())
	}
	raw, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != invalid {
		t.Fatalf("malformed config was changed:\n%s", raw)
	}
}

func assertSetupSymlinkTarget(t *testing.T, link, target string, mode os.FileMode, contains string) {
	t.Helper()
	info, err := os.Lstat(link)
	if err != nil {
		t.Fatalf("lstat %s: %v", link, err)
	}
	if info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("%s mode = %v, want preserved symlink", link, info.Mode())
	}
	raw, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("read target %s: %v", target, err)
	}
	if contains != "" && !strings.Contains(string(raw), contains) {
		t.Fatalf("target %s missing %q:\n%s", target, contains, raw)
	}
	targetInfo, err := os.Stat(target)
	if err != nil {
		t.Fatalf("stat target %s: %v", target, err)
	}
	if got := targetInfo.Mode().Perm(); got != mode {
		t.Fatalf("target %s mode = %o, want %o", target, got, mode)
	}
}

func assertSetupFileUnchanged(t *testing.T, link, target string, original []byte) {
	t.Helper()
	info, err := os.Lstat(link)
	if err != nil {
		t.Fatalf("lstat %s: %v", link, err)
	}
	if info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("%s mode = %v, want preserved symlink", link, info.Mode())
	}
	raw, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("read target %s: %v", target, err)
	}
	if !bytes.Equal(raw, original) {
		t.Fatalf("target %s changed:\n%s", target, raw)
	}
}

func assertNoSetupTempFiles(t *testing.T, dirs ...string) {
	t.Helper()
	for _, dir := range dirs {
		matches, err := filepath.Glob(filepath.Join(dir, ".helm-tmp-*"))
		if err != nil {
			t.Fatalf("glob setup temp files in %s: %v", dir, err)
		}
		if len(matches) != 0 {
			t.Fatalf("setup temp files were not cleaned from %s: %#v", dir, matches)
		}
	}
}
