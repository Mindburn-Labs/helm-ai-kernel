package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/shadow"
)

const setupMCPServerName = "helm-ai-kernel-governance"

var (
	setupRunQuickstart = runQuickstartCmd
	setupExecCommand   = func(name string, args ...string) error {
		cmd := exec.Command(name, args...)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		return cmd.Run()
	}
)

type setupOptions struct {
	Target  string
	Scope   string
	Yes     bool
	DryRun  bool
	JSON    bool
	DataDir string
}

type setupSummary struct {
	Target           string `json:"target"`
	BinaryPath       string `json:"binary_path"`
	ClientConfigPath string `json:"client_config_path"`
	HookConfigPath   string `json:"hook_config_path"`
	DataDir          string `json:"data_dir"`
	KernelURL        string `json:"kernel_url"`
	ScanGrade        string `json:"scan_grade"`
	DraftPolicyPath  string `json:"draft_policy_path"`
	UninstallCommand string `json:"uninstall_command"`
	Scope            string `json:"scope,omitempty"`
	MCPInstalled     bool   `json:"mcp_installed,omitempty"`
	HookInstalled    bool   `json:"hook_installed,omitempty"`
}

func init() {
	Register(Subcommand{
		Name:  "setup",
		Usage: "Install local Claude Code or Codex MCP/hook integration and start the headless proof path",
		RunFn: runSetupCmd,
	})
}

func runSetupCmd(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		printSetupUsage(stderr)
		return 2
	}
	switch args[0] {
	case "status":
		return runSetupStatusCmd(args[1:], stdout, stderr)
	case "remove":
		return runSetupRemoveCmd(args[1:], stdout, stderr)
	case "help", "--help", "-h":
		printSetupUsage(stdout)
		return 0
	default:
		return runSetupInstallCmd(args, stdout, stderr)
	}
}

func runSetupInstallCmd(args []string, stdout, stderr io.Writer) int {
	opts, code := parseSetupInstallArgs(args, stderr)
	if code != 0 {
		return code
	}
	if !opts.Yes && !opts.DryRun {
		fmt.Fprintln(stderr, "setup: pass --yes to install local config, or --dry-run to preview changes")
		return 2
	}
	summary, err := buildSetupSummary(opts)
	if err != nil {
		fmt.Fprintf(stderr, "setup: %v\n", err)
		return 2
	}
	if opts.DryRun {
		printSetupSummary(stdout, summary, opts.JSON)
		return 0
	}
	if err := os.MkdirAll(opts.DataDir, 0o750); err != nil {
		fmt.Fprintf(stderr, "setup: create data dir: %v\n", err)
		return 1
	}
	grade, policyPath, err := runSetupAutoconfigure(opts.DataDir)
	if err != nil {
		fmt.Fprintf(stderr, "setup: autoconfigure: %v\n", err)
		return 1
	}
	summary.ScanGrade = grade
	summary.DraftPolicyPath = policyPath
	if err := installSetupMCP(opts, summary.BinaryPath); err != nil {
		fmt.Fprintf(stderr, "setup: install MCP server: %v\n", err)
		return 1
	}
	if err := installSetupHook(opts, summary.BinaryPath); err != nil {
		fmt.Fprintf(stderr, "setup: install pre-tool hook: %v\n", err)
		return 1
	}
	summary.MCPInstalled = true
	summary.HookInstalled = true
	printSetupSummary(stdout, summary, opts.JSON)
	if !opts.JSON {
		fmt.Fprintln(stdout)
		fmt.Fprintln(stdout, "Leave this terminal open. HELM is starting the local Kernel proof path now.")
	}
	quickstartArgs := []string{"--profile", setupQuickstartProfile(opts.Target), "--data-dir", filepath.Join(opts.DataDir, "quickstart")}
	quickstartStdout := stdout
	if opts.JSON {
		quickstartStdout = stderr
	}
	return setupRunQuickstart(quickstartArgs, quickstartStdout, stderr)
}

func runSetupStatusCmd(args []string, stdout, stderr io.Writer) int {
	opts, code := parseSetupInspectArgs("setup status", args, stderr, false)
	if code != 0 {
		return code
	}
	summary, err := buildSetupSummary(opts)
	if err != nil {
		fmt.Fprintf(stderr, "setup status: %v\n", err)
		return 2
	}
	summary.MCPInstalled = setupMCPInstalled(opts, summary.ClientConfigPath)
	summary.HookInstalled = setupHookInstalled(opts, summary.HookConfigPath, summary.BinaryPath)
	if grade := readSetupScanGrade(filepath.Join(opts.DataDir, "autoconfigure", "inventory.json")); grade != "" {
		summary.ScanGrade = grade
	}
	printSetupSummary(stdout, summary, opts.JSON)
	if summary.MCPInstalled && summary.HookInstalled {
		return 0
	}
	return 1
}

func runSetupRemoveCmd(args []string, stdout, stderr io.Writer) int {
	opts, code := parseSetupInspectArgs("setup remove", args, stderr, true)
	if code != 0 {
		return code
	}
	if !opts.Yes && !opts.DryRun {
		fmt.Fprintln(stderr, "setup remove: pass --yes to remove local config, or --dry-run to preview changes")
		return 2
	}
	summary, err := buildSetupSummary(opts)
	if err != nil {
		fmt.Fprintf(stderr, "setup remove: %v\n", err)
		return 2
	}
	if !opts.DryRun {
		if err := removeSetupHook(opts, summary.BinaryPath); err != nil {
			fmt.Fprintf(stderr, "setup remove: remove hook: %v\n", err)
			return 1
		}
		if err := removeSetupMCP(opts); err != nil {
			fmt.Fprintf(stderr, "setup remove: remove MCP server: %v\n", err)
			return 1
		}
	}
	printSetupSummary(stdout, summary, opts.JSON)
	return 0
}

func printSetupUsage(w io.Writer) {
	fmt.Fprintln(w, "Usage:")
	fmt.Fprintln(w, "  helm-ai-kernel setup <claude-code|codex> [--scope user|project] [--yes] [--dry-run] [--json] [--data-dir DIR]")
	fmt.Fprintln(w, "  helm-ai-kernel setup status <claude-code|codex> [--scope user|project] [--json] [--data-dir DIR]")
	fmt.Fprintln(w, "  helm-ai-kernel setup remove <claude-code|codex> [--scope user|project] [--yes] [--dry-run] [--json] [--data-dir DIR]")
}

func parseSetupInstallArgs(args []string, stderr io.Writer) (setupOptions, int) {
	opts := setupOptions{Scope: "user"}
	fs := flag.NewFlagSet("setup", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.StringVar(&opts.Scope, "scope", opts.Scope, "Install scope: user or project")
	fs.BoolVar(&opts.Yes, "yes", false, "Install without prompting")
	fs.BoolVar(&opts.DryRun, "dry-run", false, "Print planned changes without writing config")
	fs.BoolVar(&opts.JSON, "json", false, "Print machine-readable summary")
	fs.StringVar(&opts.DataDir, "data-dir", "", "Directory for HELM local state")
	if err := fs.Parse(args[1:]); err != nil {
		return opts, 2
	}
	opts.Target = args[0]
	return normalizeSetupOptions(opts, stderr)
}

func parseSetupInspectArgs(name string, args []string, stderr io.Writer, includeYes bool) (setupOptions, int) {
	opts := setupOptions{Scope: "user"}
	if len(args) == 0 {
		fmt.Fprintf(stderr, "%s: expected <claude-code|codex>\n", name)
		return opts, 2
	}
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.StringVar(&opts.Scope, "scope", opts.Scope, "Install scope: user or project")
	fs.BoolVar(&opts.DryRun, "dry-run", false, "Print planned changes without writing config")
	fs.BoolVar(&opts.JSON, "json", false, "Print machine-readable summary")
	fs.StringVar(&opts.DataDir, "data-dir", "", "Directory for HELM local state")
	if includeYes {
		fs.BoolVar(&opts.Yes, "yes", false, "Remove without prompting")
	}
	if err := fs.Parse(args[1:]); err != nil {
		return opts, 2
	}
	if fs.NArg() != 0 {
		fmt.Fprintf(stderr, "%s: unexpected argument %q\n", name, fs.Arg(0))
		return opts, 2
	}
	opts.Target = args[0]
	return normalizeSetupOptions(opts, stderr)
}

func normalizeSetupOptions(opts setupOptions, stderr io.Writer) (setupOptions, int) {
	target, err := normalizeSetupTarget(opts.Target)
	if err != nil {
		fmt.Fprintf(stderr, "setup: %v\n", err)
		return opts, 2
	}
	opts.Target = target
	opts.Scope = strings.ToLower(strings.TrimSpace(opts.Scope))
	if opts.Scope != "user" && opts.Scope != "project" {
		fmt.Fprintf(stderr, "setup: --scope must be user or project, got %q\n", opts.Scope)
		return opts, 2
	}
	if opts.DataDir == "" {
		opts.DataDir = defaultSetupDataDir()
	}
	if abs, err := filepath.Abs(opts.DataDir); err == nil {
		opts.DataDir = abs
	}
	return opts, 0
}

func normalizeSetupTarget(target string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(target)) {
	case "claude", "claude-code", "claude_code":
		return "claude-code", nil
	case "codex":
		return "codex", nil
	default:
		return "", fmt.Errorf("target must be claude-code or codex, got %q", target)
	}
}

func buildSetupSummary(opts setupOptions) (setupSummary, error) {
	bin, err := os.Executable()
	if err != nil {
		return setupSummary{}, fmt.Errorf("locate executable: %w", err)
	}
	if abs, err := filepath.Abs(bin); err == nil {
		bin = abs
	}
	return setupSummary{
		Target:           opts.Target,
		BinaryPath:       bin,
		ClientConfigPath: setupClientConfigPath(opts),
		HookConfigPath:   setupHookConfigPath(opts),
		DataDir:          opts.DataDir,
		KernelURL:        "http://127.0.0.1:7714",
		ScanGrade:        "not_run",
		DraftPolicyPath:  filepath.Join(opts.DataDir, "autoconfigure", "policy.draft.json"),
		UninstallCommand: fmt.Sprintf("helm-ai-kernel setup remove %s --scope %s --yes --data-dir %s", opts.Target, opts.Scope, shellQuote(opts.DataDir)),
		Scope:            opts.Scope,
	}, nil
}

func printSetupSummary(stdout io.Writer, summary setupSummary, jsonOut bool) {
	if jsonOut {
		_ = json.NewEncoder(stdout).Encode(summary)
		return
	}
	fmt.Fprintf(stdout, "HELM setup for %s\n", summary.Target)
	fmt.Fprintf(stdout, "  MCP config:    %s\n", summary.ClientConfigPath)
	fmt.Fprintf(stdout, "  Hook config:   %s\n", summary.HookConfigPath)
	fmt.Fprintf(stdout, "  Data dir:      %s\n", summary.DataDir)
	fmt.Fprintf(stdout, "  Kernel:        %s\n", summary.KernelURL)
	fmt.Fprintf(stdout, "  Scan grade:    %s\n", summary.ScanGrade)
	fmt.Fprintf(stdout, "  Draft policy:  %s\n", summary.DraftPolicyPath)
	fmt.Fprintf(stdout, "  Uninstall:     %s\n", summary.UninstallCommand)
	if summary.MCPInstalled || summary.HookInstalled {
		fmt.Fprintf(stdout, "  Installed:     mcp=%v hook=%v\n", summary.MCPInstalled, summary.HookInstalled)
	}
}

func runSetupAutoconfigure(dataDir string) (string, string, error) {
	outDir := filepath.Join(dataDir, "autoconfigure")
	report, err := shadow.NewScanner().Scan(".")
	if err != nil {
		return "", "", err
	}
	inv := buildInventory(report)
	if err := writeJSONArtifact(filepath.Join(outDir, "inventory.json"), inv); err != nil {
		return "", "", err
	}
	draft, plan := buildPolicyDraft(inv)
	policyPath := filepath.Join(outDir, "policy.draft.json")
	if err := writeJSONArtifact(policyPath, draft); err != nil {
		return "", "", err
	}
	if err := writeJSONArtifact(filepath.Join(outDir, "mcp_quarantine_plan.json"), plan); err != nil {
		return "", "", err
	}
	return inv.Grade.Letter, policyPath, nil
}

func installSetupMCP(opts setupOptions, bin string) error {
	switch opts.Target {
	case "claude-code":
		return setupExecCommand("claude", "mcp", "add", "--transport", "stdio", "--scope", opts.Scope, setupMCPServerName, "--", bin, "mcp", "serve", "--transport", "stdio")
	case "codex":
		if opts.Scope == "project" {
			return upsertCodexProjectMCP(setupClientConfigPath(opts), bin)
		}
		return setupExecCommand("codex", "mcp", "add", setupMCPServerName, "--", bin, "mcp", "serve", "--transport", "stdio")
	default:
		return fmt.Errorf("unsupported target %q", opts.Target)
	}
}

func removeSetupMCP(opts setupOptions) error {
	switch opts.Target {
	case "claude-code":
		return setupExecCommand("claude", "mcp", "remove", "--scope", opts.Scope, setupMCPServerName)
	case "codex":
		if opts.Scope == "project" {
			return removeCodexProjectMCP(setupClientConfigPath(opts))
		}
		return setupExecCommand("codex", "mcp", "remove", setupMCPServerName)
	default:
		return fmt.Errorf("unsupported target %q", opts.Target)
	}
}

func installSetupHook(opts setupOptions, bin string) error {
	return upsertHookConfig(setupHookConfigPath(opts), setupHookMatcher(opts.Target), setupHookCommand(opts, bin))
}

func removeSetupHook(opts setupOptions, bin string) error {
	return removeHookConfig(setupHookConfigPath(opts), setupHookCommand(opts, bin))
}

func setupMCPInstalled(opts setupOptions, path string) bool {
	if opts.Target == "claude-code" && opts.Scope == "user" {
		return fileContains(path, setupMCPServerName)
	}
	return fileContains(path, setupMCPServerName)
}

func setupHookInstalled(opts setupOptions, path, bin string) bool {
	return fileContains(path, setupHookCommand(opts, bin))
}

func setupQuickstartProfile(target string) string {
	if target == "codex" {
		return "codex"
	}
	return "claude"
}

func setupClientConfigPath(opts setupOptions) string {
	switch opts.Target {
	case "claude-code":
		if opts.Scope == "project" {
			return filepath.Join(".", ".mcp.json")
		}
		return filepath.Join(homeDirOrDot(), ".claude.json")
	case "codex":
		if opts.Scope == "project" {
			return filepath.Join(".", ".codex", "config.toml")
		}
		return filepath.Join(homeDirOrDot(), ".codex", "config.toml")
	default:
		return ""
	}
}

func setupHookConfigPath(opts setupOptions) string {
	switch opts.Target {
	case "claude-code":
		if opts.Scope == "project" {
			return filepath.Join(".", ".claude", "settings.json")
		}
		return filepath.Join(homeDirOrDot(), ".claude", "settings.json")
	case "codex":
		if opts.Scope == "project" {
			return filepath.Join(".", ".codex", "hooks.json")
		}
		return filepath.Join(homeDirOrDot(), ".codex", "hooks.json")
	default:
		return ""
	}
}

func setupHookMatcher(target string) string {
	if target == "codex" {
		return "^(Bash|apply_patch|mcp__.*)$"
	}
	return "^(Bash|Edit|Write|MultiEdit|mcp__.*)$"
}

func setupHookCommand(opts setupOptions, bin string) string {
	return shellQuote(bin) + " hook pre-tool --client " + opts.Target + " --data-dir " + shellQuote(opts.DataDir)
}

func upsertHookConfig(path, matcher, command string) error {
	root, err := readJSONObject(path)
	if err != nil {
		return err
	}
	hooks := objectValue(root, "hooks")
	pre := arrayValue(hooks, "PreToolUse")
	if hookCommandPresent(pre, command) {
		return writeJSONObject(path, root)
	}
	entry := map[string]any{
		"matcher": matcher,
		"hooks": []any{
			map[string]any{
				"type":          "command",
				"command":       command,
				"timeout":       float64(30),
				"statusMessage": "Checking HELM policy",
			},
		},
	}
	hooks["PreToolUse"] = append(pre, entry)
	root["hooks"] = hooks
	return writeJSONObject(path, root)
}

func removeHookConfig(path, command string) error {
	root, err := readJSONObject(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	hooks := objectValue(root, "hooks")
	pre := arrayValue(hooks, "PreToolUse")
	filtered := make([]any, 0, len(pre))
	for _, item := range pre {
		obj, ok := item.(map[string]any)
		if !ok {
			filtered = append(filtered, item)
			continue
		}
		hookItems, ok := obj["hooks"].([]any)
		if !ok {
			filtered = append(filtered, item)
			continue
		}
		keptHooks := make([]any, 0, len(hookItems))
		for _, h := range hookItems {
			if hookCommandFromAny(h) != command {
				keptHooks = append(keptHooks, h)
			}
		}
		if len(keptHooks) > 0 {
			obj["hooks"] = keptHooks
			filtered = append(filtered, obj)
		}
	}
	hooks["PreToolUse"] = filtered
	root["hooks"] = hooks
	return writeJSONObject(path, root)
}

func readJSONObject(path string) (map[string]any, error) {
	raw, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return map[string]any{}, nil
	}
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(string(raw)) == "" {
		return map[string]any{}, nil
	}
	var root map[string]any
	if err := json.Unmarshal(raw, &root); err != nil {
		return nil, err
	}
	if root == nil {
		root = map[string]any{}
	}
	return root, nil
}

func writeJSONObject(path string, root map[string]any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	data, err := json.MarshalIndent(root, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o600)
}

func objectValue(root map[string]any, key string) map[string]any {
	if obj, ok := root[key].(map[string]any); ok {
		return obj
	}
	obj := map[string]any{}
	root[key] = obj
	return obj
}

func arrayValue(root map[string]any, key string) []any {
	if arr, ok := root[key].([]any); ok {
		return arr
	}
	return []any{}
}

func hookCommandPresent(pre []any, command string) bool {
	for _, item := range pre {
		obj, ok := item.(map[string]any)
		if !ok {
			continue
		}
		hooks, ok := obj["hooks"].([]any)
		if !ok {
			continue
		}
		for _, h := range hooks {
			if hookCommandFromAny(h) == command {
				return true
			}
		}
	}
	return false
}

func hookCommandFromAny(v any) string {
	obj, ok := v.(map[string]any)
	if !ok {
		return ""
	}
	command, _ := obj["command"].(string)
	return command
}

func upsertCodexProjectMCP(path, bin string) error {
	current := ""
	if raw, err := os.ReadFile(path); err == nil {
		current = string(raw)
	} else if !os.IsNotExist(err) {
		return err
	}
	current = removeTOMLTable(current, "[mcp_servers."+setupMCPServerName+"]")
	block := fmt.Sprintf("[mcp_servers.%s]\ncommand = %q\nargs = [\"mcp\", \"serve\", \"--transport\", \"stdio\"]\n", setupMCPServerName, bin)
	next := strings.TrimRight(current, "\n")
	if next != "" {
		next += "\n\n"
	}
	next += block
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(next), 0o600)
}

func removeCodexProjectMCP(path string) error {
	raw, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	next := removeTOMLTable(string(raw), "[mcp_servers."+setupMCPServerName+"]")
	return os.WriteFile(path, []byte(strings.TrimRight(next, "\n")+"\n"), 0o600)
}

func removeTOMLTable(input, table string) string {
	lines := strings.Split(input, "\n")
	out := make([]string, 0, len(lines))
	skipping := false
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == table {
			skipping = true
			continue
		}
		if skipping && strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") {
			skipping = false
		}
		if !skipping {
			out = append(out, line)
		}
	}
	return strings.TrimRight(strings.Join(out, "\n"), "\n")
}

func readSetupScanGrade(path string) string {
	raw, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	var inv AutoconfigureInventory
	if err := json.Unmarshal(raw, &inv); err != nil {
		return ""
	}
	return inv.Grade.Letter
}

func fileContains(path, needle string) bool {
	raw, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	return strings.Contains(string(raw), needle)
}

func defaultSetupDataDir() string {
	return filepath.Join(homeDirOrDot(), ".helm-ai-kernel")
}

func homeDirOrDot() string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return "."
	}
	return home
}
