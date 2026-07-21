// quantum_posture: setup wires only classical Ed25519 receipt signer sources;
// it does not provide post-quantum or hybrid cryptographic protection.
package main

import (
	"crypto/rand"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/BurntSushi/toml"
	lpcmd "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/launchpad/cmd"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/shadow"
)

const setupMCPServerName = "helm-ai-kernel-governance"

var (
	setupRunQuickstart = runQuickstartCmdWithReady
	setupExecCommand   = func(dir, name string, args ...string) error {
		cmd := exec.Command(name, args...)
		if dir != "" {
			cmd.Dir = dir
		}
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		return cmd.Run()
	}
)

type setupOptions struct {
	Target          string
	Operation       string
	Scope           string
	Workspace       string
	WorkspaceSet    bool
	Yes             bool
	DryRun          bool
	JSON            bool
	NoQuickstart    bool
	DataDir         string
	SigningSeedFile string
}

type setupSummary struct {
	Operation        string `json:"operation"`
	Target           string `json:"target"`
	Workspace        string `json:"workspace"`
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
	// CodexTrustPending is true when a project-scoped Codex config is written
	// but the workspace is not recorded as trusted in ~/.codex/config.toml.
	// Codex ignores project-scoped config until trust is granted, so the
	// integration is written-but-not-yet-loaded; reporting it as installed
	// without this flag would be a false positive.
	CodexTrustPending bool     `json:"codex_trust_pending,omitempty"`
	QuickstartStarted bool     `json:"quickstart_started"`
	PlannedActions    []string `json:"planned_actions"`
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
		printSetupUsage(stdout)
		return 0
	}
	if strings.HasPrefix(args[0], "-") {
		return runSetupFrontDoorFlags(args, stdout, stderr)
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

func runSetupFrontDoorFlags(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("setup", flag.ContinueOnError)
	fs.SetOutput(stderr)
	client := fs.String("client", "", "Client to print config for")
	printConfig := fs.Bool("print-config", false, "Print config for --client")
	jsonOut := fs.Bool("json", false, "Print machine-readable support matrix")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		fmt.Fprintf(stderr, "setup: unexpected argument %q\n", fs.Arg(0))
		return 2
	}
	if *jsonOut {
		return writeSupportMatrixJSON(stdout)
	}
	if *printConfig {
		if *client == "" {
			fmt.Fprintln(stderr, "setup: --print-config requires --client")
			return 2
		}
		return runMCPPrintConfig([]string{"--client", *client}, stdout, stderr)
	}
	printSetupUsage(stdout)
	return 0
}

func runSetupInstallCmd(args []string, stdout, stderr io.Writer) int {
	opts, code := parseSetupInstallArgs(args, stderr)
	if code != 0 {
		return code
	}
	if opts.DryRun {
		opts.Operation = "preview"
	} else {
		opts.Operation = "install"
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
	if _, err := resolveWorkstationSigningSeed(opts.DataDir, "", opts.SigningSeedFile); err != nil {
		fmt.Fprintf(stderr, "setup: provision local receipt signing key: %v\n", err)
		return 1
	}
	grade, policyPath, err := runSetupAutoconfigure(opts.DataDir, opts.Workspace)
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
	if opts.Target == "codex" && opts.Scope == "project" {
		summary.CodexTrustPending = codexProjectTrustPending(opts.Workspace)
	}
	if opts.NoQuickstart {
		printSetupSummary(stdout, summary, opts.JSON)
		return 0
	}
	if !opts.JSON {
		fmt.Fprintln(stdout)
		fmt.Fprintln(stdout, "Leave this terminal open. HELM is starting the local Kernel proof path now.")
	}
	quickstartArgs := []string{"--profile", setupQuickstartProfile(opts.Target), "--data-dir", filepath.Join(opts.DataDir, "quickstart")}
	quickstartStdout := stdout
	if opts.JSON {
		quickstartStdout = stderr
	}
	summaryPrinted := false
	code = setupRunQuickstart(quickstartArgs, quickstartStdout, stderr, func() {
		if summaryPrinted {
			return
		}
		summary.QuickstartStarted = true
		printSetupSummary(stdout, summary, opts.JSON)
		summaryPrinted = true
	})
	if !summaryPrinted {
		summary.KernelURL = ""
		printSetupSummary(stdout, summary, opts.JSON)
	}
	return code
}

func runSetupStatusCmd(args []string, stdout, stderr io.Writer) int {
	opts, code := parseSetupInspectArgs("setup status", args, stderr, false)
	if code != 0 {
		return code
	}
	opts.Operation = "status"
	summary, err := buildSetupSummary(opts)
	if err != nil {
		fmt.Fprintf(stderr, "setup status: %v\n", err)
		return 2
	}
	summary.MCPInstalled = setupMCPInstalled(opts, summary.ClientConfigPath, summary.BinaryPath)
	summary.HookInstalled = setupHookInstalled(opts, summary.HookConfigPath, summary.BinaryPath)
	if opts.Target == "codex" && opts.Scope == "project" && (summary.MCPInstalled || summary.HookInstalled) {
		summary.CodexTrustPending = codexProjectTrustPending(opts.Workspace)
	}
	if grade := readSetupScanGrade(filepath.Join(opts.DataDir, "autoconfigure", "inventory.json")); grade != "" {
		summary.ScanGrade = grade
	}
	printSetupSummary(stdout, summary, opts.JSON)
	// A project-scoped Codex config that Codex will not load until the
	// project is trusted is not an effective install; do not report success.
	if summary.MCPInstalled && summary.HookInstalled && !summary.CodexTrustPending {
		return 0
	}
	return 1
}

func runSetupRemoveCmd(args []string, stdout, stderr io.Writer) int {
	opts, code := parseSetupInspectArgs("setup remove", args, stderr, true)
	if code != 0 {
		return code
	}
	if opts.DryRun {
		opts.Operation = "preview_remove"
	} else {
		opts.Operation = "remove"
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
	fmt.Fprintln(w, "Protect an agent:")
	fmt.Fprintln(w, "  helm-ai-kernel setup claude-code --yes")
	fmt.Fprintln(w, "  helm-ai-kernel setup codex --yes")
	fmt.Fprintln(w, "  helm-ai-kernel setup --client cursor --print-config")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "Inspect first:")
	fmt.Fprintln(w, "  helm-ai-kernel setup claude-code --dry-run --json")
	fmt.Fprintln(w, "  helm-ai-kernel setup --json")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "Manage:")
	fmt.Fprintln(w, "  helm-ai-kernel setup codex --scope project --workspace DIR --dry-run --json")
	fmt.Fprintln(w, "  helm-ai-kernel setup status <claude-code|codex> [--scope user|project] [--workspace DIR] [--json] [--data-dir DIR]")
	fmt.Fprintln(w, "  helm-ai-kernel setup remove <claude-code|codex> [--scope user|project] [--workspace DIR] [--yes] [--dry-run] [--json] [--data-dir DIR]")
	fmt.Fprintln(w, "")
	printSupportMatrix(w)
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "No config is written without --yes.")
}

func parseSetupInstallArgs(args []string, stderr io.Writer) (setupOptions, int) {
	opts := setupOptions{Scope: "user"}
	fs := flag.NewFlagSet("setup", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.StringVar(&opts.Scope, "scope", opts.Scope, "Install scope: user or project")
	fs.StringVar(&opts.Workspace, "workspace", "", "Workspace to scan and configure (defaults to the current directory for project scope)")
	fs.BoolVar(&opts.Yes, "yes", false, "Install without prompting")
	fs.BoolVar(&opts.DryRun, "dry-run", false, "Print planned changes without writing config")
	fs.BoolVar(&opts.JSON, "json", false, "Print machine-readable summary")
	fs.BoolVar(&opts.NoQuickstart, "no-quickstart", false, "Install without starting the blocking Quickstart server")
	fs.StringVar(&opts.DataDir, "data-dir", "", "Directory for HELM local state")
	fs.StringVar(&opts.SigningSeedFile, "signing-seed-file", "", "Path to 0600 file containing a 32-byte Ed25519 seed as hex")
	if err := fs.Parse(args[1:]); err != nil {
		return opts, 2
	}
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "workspace" {
			opts.WorkspaceSet = true
		}
	})
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
	fs.StringVar(&opts.Workspace, "workspace", "", "Workspace to inspect or remove from (defaults to the current directory for project scope)")
	fs.BoolVar(&opts.DryRun, "dry-run", false, "Print planned changes without writing config")
	fs.BoolVar(&opts.JSON, "json", false, "Print machine-readable summary")
	fs.BoolVar(&opts.NoQuickstart, "no-quickstart", false, "Report a headless setup without a Quickstart server")
	fs.StringVar(&opts.DataDir, "data-dir", "", "Directory for HELM local state")
	fs.StringVar(&opts.SigningSeedFile, "signing-seed-file", "", "Path to 0600 file containing a 32-byte Ed25519 seed as hex")
	if includeYes {
		fs.BoolVar(&opts.Yes, "yes", false, "Remove without prompting")
	}
	if err := fs.Parse(args[1:]); err != nil {
		return opts, 2
	}
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "workspace" {
			opts.WorkspaceSet = true
		}
	})
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
	if opts.Scope == "user" && opts.WorkspaceSet {
		fmt.Fprintln(stderr, "setup: --workspace is only valid with --scope project")
		return opts, 2
	}
	if opts.DataDir == "" {
		opts.DataDir = defaultSetupDataDir()
	}
	if opts.DataDir == "" {
		fmt.Fprintln(stderr, "setup: --data-dir is required when the home directory is unavailable")
		return opts, 2
	}
	if opts.Scope == "user" && homeDirOrEmpty() == "" {
		fmt.Fprintln(stderr, "setup: user scope requires an absolute home directory")
		return opts, 2
	}
	if abs, err := filepath.Abs(opts.DataDir); err == nil {
		opts.DataDir = abs
	}
	if opts.Workspace == "" {
		workspace, err := os.Getwd()
		if err != nil {
			fmt.Fprintf(stderr, "setup: determine workspace: %v\n", err)
			return opts, 2
		}
		opts.Workspace = workspace
	}
	if abs, err := filepath.Abs(opts.Workspace); err == nil {
		opts.Workspace = abs
	}
	if resolved, err := filepath.EvalSymlinks(opts.Workspace); err == nil {
		opts.Workspace = resolved
	}
	info, err := os.Stat(opts.Workspace)
	if err != nil {
		fmt.Fprintf(stderr, "setup: workspace: %v\n", err)
		return opts, 2
	}
	if !info.IsDir() {
		fmt.Fprintf(stderr, "setup: workspace must be a directory, got %q\n", opts.Workspace)
		return opts, 2
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
		Operation:         opts.Operation,
		Target:            opts.Target,
		Workspace:         opts.Workspace,
		BinaryPath:        bin,
		ClientConfigPath:  setupClientConfigPath(opts),
		HookConfigPath:    setupHookConfigPath(opts),
		DataDir:           opts.DataDir,
		KernelURL:         setupKernelURL(opts),
		ScanGrade:         "not_run",
		DraftPolicyPath:   filepath.Join(opts.DataDir, "autoconfigure", "policy.draft.json"),
		UninstallCommand:  setupUninstallCommand(opts),
		Scope:             opts.Scope,
		QuickstartStarted: false,
		PlannedActions:    setupPlannedActions(opts),
	}, nil
}

func setupPlannedActions(opts setupOptions) []string {
	switch opts.Operation {
	case "preview":
		actions := []string{
			"scan selected workspace and write draft-only inventory artifacts",
			"configure the HELM MCP server with the selected local data directory",
			"configure the HELM PreToolUse hook for the selected client",
		}
		if !opts.NoQuickstart {
			actions = append(actions, "start the local Quickstart proof path")
		}
		return actions
	case "preview_remove":
		return []string{
			"remove the HELM PreToolUse hook from the selected scope",
			"remove the HELM MCP server from the selected scope",
		}
	default:
		return []string{}
	}
}

// setupPersistedKernelURL returns a persisted cloud endpoint from a `connect`
// machine credential or a `control-plane pair` pairing, or "" if none. It is a
// package var so tests can control it deterministically.
var setupPersistedKernelURL = loadPersistedKernelURL

func loadPersistedKernelURL() string {
	if mc, err := lpcmd.LoadMachineCredential(); err == nil && strings.TrimSpace(mc.APIURL) != "" {
		return strings.TrimRight(mc.APIURL, "/")
	}
	if p, err := lpcmd.LoadPairing(); err == nil && strings.TrimSpace(p.APIURL) != "" {
		return strings.TrimRight(p.APIURL, "/")
	}
	return ""
}

func setupKernelURL(opts setupOptions) string {
	if opts.NoQuickstart || (opts.Operation != "preview" && opts.Operation != "install") {
		return ""
	}
	if url := setupPersistedKernelURL(); url != "" {
		return url
	}
	return "http://127.0.0.1:7714"
}

func setupUninstallCommand(opts setupOptions) string {
	workspace := ""
	if opts.Scope == "project" {
		workspace = " --workspace " + shellQuote(opts.Workspace)
	}
	signingSeedFile := ""
	if strings.TrimSpace(opts.SigningSeedFile) != "" {
		signingSeedFile = " --signing-seed-file " + shellQuote(opts.SigningSeedFile)
	}
	return fmt.Sprintf(
		"helm-ai-kernel setup remove %s --scope %s%s --yes --data-dir %s%s",
		opts.Target,
		opts.Scope,
		workspace,
		shellQuote(opts.DataDir),
		signingSeedFile,
	)
}

func printSetupSummary(stdout io.Writer, summary setupSummary, jsonOut bool) {
	if jsonOut {
		_ = json.NewEncoder(stdout).Encode(summary)
		return
	}
	fmt.Fprintf(stdout, "HELM setup for %s\n", summary.Target)
	fmt.Fprintf(stdout, "  Workspace:     %s\n", summary.Workspace)
	fmt.Fprintf(stdout, "  MCP config:    %s\n", summary.ClientConfigPath)
	fmt.Fprintf(stdout, "  Hook config:   %s\n", summary.HookConfigPath)
	fmt.Fprintf(stdout, "  Data dir:      %s\n", summary.DataDir)
	fmt.Fprintf(stdout, "  Kernel:        %s\n", summary.KernelURL)
	fmt.Fprintf(stdout, "  Scan grade:    %s\n", summary.ScanGrade)
	fmt.Fprintf(stdout, "  Draft policy:  %s\n", summary.DraftPolicyPath)
	fmt.Fprintf(stdout, "  Uninstall:     %s\n", summary.UninstallCommand)
	if len(summary.PlannedActions) > 0 {
		fmt.Fprintln(stdout, "  Planned:")
		for _, action := range summary.PlannedActions {
			fmt.Fprintf(stdout, "    - %s\n", action)
		}
	}
	if summary.MCPInstalled || summary.HookInstalled {
		fmt.Fprintf(stdout, "  Installed:     mcp=%v hook=%v\n", summary.MCPInstalled, summary.HookInstalled)
	}
	if summary.CodexTrustPending {
		fmt.Fprintf(stdout, "  Codex trust:   PENDING — Codex will ignore this project config until you trust the workspace (run `codex` in %s and approve it, or set trust_level=\"trusted\" in ~/.codex/config.toml). Governance is not active until then.\n", summary.Workspace)
	}
}

func runSetupAutoconfigure(dataDir, workspace string) (string, string, error) {
	outDir := filepath.Join(dataDir, "autoconfigure")
	report, err := shadow.NewScanner().Scan(workspace)
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
		if opts.Scope == "project" {
			if _, err := privateFileWritePath(setupClientConfigPath(opts), setupPrivateFileRoot(opts)); err != nil {
				return err
			}
		}
		return setupExecCommand(setupCommandDir(opts), "claude", "mcp", "add", "--transport", "stdio", "--scope", opts.Scope, setupMCPServerName, "--", bin, "mcp", "serve", "--transport", "stdio", "--data-dir", opts.DataDir)
	case "codex":
		if opts.Scope == "project" {
			return upsertCodexProjectMCP(setupClientConfigPath(opts), bin, opts.DataDir, setupPrivateFileRoot(opts))
		}
		return setupExecCommand(setupCommandDir(opts), "codex", "mcp", "add", setupMCPServerName, "--", bin, "mcp", "serve", "--transport", "stdio", "--data-dir", opts.DataDir)
	default:
		return fmt.Errorf("unsupported target %q", opts.Target)
	}
}

func removeSetupMCP(opts setupOptions) error {
	switch opts.Target {
	case "claude-code":
		if opts.Scope == "project" {
			if _, err := privateFileWritePath(setupClientConfigPath(opts), setupPrivateFileRoot(opts)); err != nil {
				return err
			}
		}
		return setupExecCommand(setupCommandDir(opts), "claude", "mcp", "remove", "--scope", opts.Scope, setupMCPServerName)
	case "codex":
		if opts.Scope == "project" {
			return removeCodexProjectMCP(setupClientConfigPath(opts), setupPrivateFileRoot(opts))
		}
		return setupExecCommand(setupCommandDir(opts), "codex", "mcp", "remove", setupMCPServerName)
	default:
		return fmt.Errorf("unsupported target %q", opts.Target)
	}
}

func setupCommandDir(opts setupOptions) string {
	if opts.Scope == "project" {
		return opts.Workspace
	}
	return ""
}

func setupPrivateFileRoot(opts setupOptions) string {
	if opts.Scope == "project" {
		return opts.Workspace
	}
	return ""
}

func installSetupHook(opts setupOptions, bin string) error {
	return upsertHookConfig(setupHookConfigPath(opts), setupHookMatcher(opts.Target), setupHookCommand(opts, bin), setupPrivateFileRoot(opts))
}

func removeSetupHook(opts setupOptions, bin string) error {
	return removeHookConfig(setupHookConfigPath(opts), setupHookCommand(opts, bin), setupPrivateFileRoot(opts))
}

func setupMCPInstalled(opts setupOptions, path, bin string) bool {
	if filepath.Clean(path) != filepath.Clean(setupClientConfigPath(opts)) {
		return false
	}
	readPath := path
	if root := setupPrivateFileRoot(opts); root != "" {
		resolved, err := privateFileWritePath(path, root)
		if err != nil {
			return false
		}
		readPath = resolved
	}
	switch opts.Target {
	case "claude-code":
		return claudeMCPInstalled(readPath, bin, opts.DataDir)
	case "codex":
		return codexMCPInstalled(readPath, bin, opts.DataDir)
	default:
		return false
	}
}

func setupHookInstalled(opts setupOptions, path, bin string) bool {
	root, err := readJSONObject(path)
	if err != nil {
		return false
	}
	hooks, ok := root["hooks"].(map[string]any)
	if !ok {
		return false
	}
	return hookCommandPresent(arrayValue(hooks, "PreToolUse"), setupHookCommand(opts, bin))
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
			return filepath.Join(opts.Workspace, ".mcp.json")
		}
		return setupUserPath(".claude.json")
	case "codex":
		if opts.Scope == "project" {
			return filepath.Join(opts.Workspace, ".codex", "config.toml")
		}
		return setupUserPath(".codex", "config.toml")
	default:
		return ""
	}
}

func setupHookConfigPath(opts setupOptions) string {
	switch opts.Target {
	case "claude-code":
		if opts.Scope == "project" {
			return filepath.Join(opts.Workspace, ".claude", "settings.json")
		}
		return setupUserPath(".claude", "settings.json")
	case "codex":
		if opts.Scope == "project" {
			return filepath.Join(opts.Workspace, ".codex", "hooks.json")
		}
		return setupUserPath(".codex", "hooks.json")
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
	command := shellQuote(bin) + " hook pre-tool --client " + opts.Target + " --data-dir " + shellQuote(opts.DataDir)
	if strings.TrimSpace(opts.SigningSeedFile) != "" {
		command += " --signing-seed-file " + shellQuote(opts.SigningSeedFile)
	}
	return command
}

func upsertHookConfig(path, matcher, command, allowedRoot string) error {
	if _, err := privateFileWritePath(path, allowedRoot); err != nil {
		return err
	}
	root, err := readJSONObject(path)
	if err != nil {
		return err
	}
	hooks := objectValue(root, "hooks")
	pre := arrayValue(hooks, "PreToolUse")
	if hookCommandPresent(pre, command) {
		return writeJSONObject(path, root, allowedRoot)
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
	return writeJSONObject(path, root, allowedRoot)
}

func removeHookConfig(path, command, allowedRoot string) error {
	if _, err := privateFileWritePath(path, allowedRoot); err != nil {
		return err
	}
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
	return writeJSONObject(path, root, allowedRoot)
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

func writeJSONObject(path string, root map[string]any, allowedRoot string) error {
	data, err := json.MarshalIndent(root, "", "  ")
	if err != nil {
		return err
	}
	return writePrivateFileAtomic(path, append(data, '\n'), allowedRoot)
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

func upsertCodexProjectMCP(path, bin, dataDir, allowedRoot string) error {
	if _, err := privateFileWritePath(path, allowedRoot); err != nil {
		return err
	}
	current := ""
	if raw, err := os.ReadFile(path); err == nil {
		current = string(raw)
		if err := validateCodexProjectTOML(current); err != nil {
			return fmt.Errorf("parse existing Codex config: %w", err)
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	current = removeTOMLTable(current, "[mcp_servers."+setupMCPServerName+"]")
	block := fmt.Sprintf("[mcp_servers.%s]\ncommand = %q\nargs = [\"mcp\", \"serve\", \"--transport\", \"stdio\", \"--data-dir\", %q]\n", setupMCPServerName, bin, dataDir)
	next := strings.TrimRight(current, "\n")
	if next != "" {
		next += "\n\n"
	}
	next += block
	if err := validateCodexProjectTOML(next); err != nil {
		return fmt.Errorf("validate updated Codex config: %w", err)
	}
	return writePrivateFileAtomic(path, []byte(next), allowedRoot)
}

func removeCodexProjectMCP(path, allowedRoot string) error {
	if _, err := privateFileWritePath(path, allowedRoot); err != nil {
		return err
	}
	raw, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if err := validateCodexProjectTOML(string(raw)); err != nil {
		return fmt.Errorf("parse existing Codex config: %w", err)
	}
	next := strings.TrimRight(removeTOMLTable(string(raw), "[mcp_servers."+setupMCPServerName+"]"), "\n") + "\n"
	if err := validateCodexProjectTOML(next); err != nil {
		return fmt.Errorf("validate updated Codex config: %w", err)
	}
	return writePrivateFileAtomic(path, []byte(next), allowedRoot)
}

type codexProjectConfig struct {
	MCPServers map[string]codexMCPServer `toml:"mcp_servers"`
}

type codexMCPServer struct {
	Command string   `toml:"command,omitempty"`
	Args    []string `toml:"args,omitempty"`
	// Remote HTTP transport fields (used by `connect`). BearerTokenEnvVar names
	// the environment variable holding the bearer; the literal token is never
	// written into a client config.
	URL               string `toml:"url,omitempty"`
	BearerTokenEnvVar string `toml:"bearer_token_env_var,omitempty"`
}

type claudeMCPConfig struct {
	MCPServers map[string]claudeMCPServer `json:"mcpServers"`
}

type claudeMCPServer struct {
	Command string   `json:"command,omitempty"`
	Args    []string `json:"args,omitempty"`
	// Remote HTTP transport fields (used by `connect`). Headers reference a
	// bearer via env-var expansion (e.g. Bearer ${HELM_MACHINE_TOKEN}); the
	// literal token is never written into a client config.
	Type    string            `json:"type,omitempty"`
	URL     string            `json:"url,omitempty"`
	Headers map[string]string `json:"headers,omitempty"`
}

func validateCodexProjectTOML(raw string) error {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	var config map[string]any
	_, err := toml.Decode(raw, &config)
	return err
}

// codexProjectTrustPending reports whether a project-scoped Codex workspace
// has NOT been recorded as trusted in ~/.codex/config.toml. Codex only loads a
// project-scoped .codex/config.toml (and its MCP server + hook) once the
// project's trust_level is "trusted"; until then a written config is inert, so
// setup/status must not report it as an effective install.
func codexProjectTrustPending(workspace string) bool {
	abs, err := filepath.Abs(workspace)
	if err != nil {
		abs = workspace
	}
	if resolved, err := filepath.EvalSymlinks(abs); err == nil {
		abs = resolved
	}
	home := homeDirOrEmpty()
	if home == "" {
		// Without an absolute home we cannot read recorded trust; fail closed.
		return true
	}
	userConfig := filepath.Join(home, ".codex", "config.toml")
	raw, err := os.ReadFile(userConfig)
	if err != nil {
		// No user-level Codex config means no recorded trust for this project.
		return true
	}
	var config struct {
		Projects map[string]struct {
			TrustLevel string `toml:"trust_level"`
		} `toml:"projects"`
	}
	if _, err := toml.Decode(string(raw), &config); err != nil {
		return true
	}
	if entry, ok := config.Projects[abs]; ok && strings.EqualFold(entry.TrustLevel, "trusted") {
		return false
	}
	return true
}

func claudeMCPInstalled(path, bin, dataDir string) bool {
	raw, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	var config claudeMCPConfig
	if err := json.Unmarshal(raw, &config); err != nil {
		return false
	}
	server, ok := config.MCPServers[setupMCPServerName]
	return ok && server.Command == bin && equalSetupStrings(server.Args, setupMCPArgs(dataDir))
}

func codexMCPInstalled(path, bin, dataDir string) bool {
	raw, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	var config codexProjectConfig
	if _, err := toml.Decode(string(raw), &config); err != nil {
		return false
	}
	server, ok := config.MCPServers[setupMCPServerName]
	if !ok || server.Command != bin {
		return false
	}
	return equalSetupStrings(server.Args, setupMCPArgs(dataDir))
}

func setupMCPArgs(dataDir string) []string {
	return []string{"mcp", "serve", "--transport", "stdio", "--data-dir", dataDir}
}

// connectAtomicWrite is the atomic file writer used by the remote MCP config
// writers. It is a package var so tests can exercise fail-closed rollback by
// injecting a write error.
var connectAtomicWrite = writePrivateFileAtomic

// remoteClaudeServer builds a Claude remote HTTP MCP server entry whose bearer
// is supplied at runtime via env-var expansion; the literal token is never
// embedded in the config.
func remoteClaudeServer(mcpURL, tokenEnvVar string) claudeMCPServer {
	return claudeMCPServer{
		Type: "http",
		URL:  mcpURL,
		Headers: map[string]string{
			"Authorization": "Bearer ${" + tokenEnvVar + "}",
		},
	}
}

// writeRemoteClaudeMCP merges a remote HTTP HELM MCP server into a Claude client
// config, preserving any other servers, and writes it atomically. The bearer is
// referenced by env var only.
func writeRemoteClaudeMCP(path, mcpURL, tokenEnvVar, allowedRoot string) error {
	if _, err := privateFileWritePath(path, allowedRoot); err != nil {
		return err
	}
	root, err := readJSONObject(path)
	if err != nil {
		return err
	}
	entry, err := structToObject(remoteClaudeServer(mcpURL, tokenEnvVar))
	if err != nil {
		return err
	}
	servers := objectValue(root, "mcpServers")
	servers[setupMCPServerName] = entry
	root["mcpServers"] = servers
	data, err := json.MarshalIndent(root, "", "  ")
	if err != nil {
		return err
	}
	return connectAtomicWrite(path, append(data, '\n'), allowedRoot)
}

// writeRemoteCodexMCP upserts a remote HTTP HELM MCP server into a Codex config,
// preserving any other tables, and writes it atomically. The bearer is
// referenced by env var only.
func writeRemoteCodexMCP(path, mcpURL, tokenEnvVar, allowedRoot string) error {
	if _, err := privateFileWritePath(path, allowedRoot); err != nil {
		return err
	}
	current := ""
	if raw, err := os.ReadFile(path); err == nil {
		current = string(raw)
		if err := validateCodexProjectTOML(current); err != nil {
			return fmt.Errorf("parse existing Codex config: %w", err)
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	current = removeTOMLTable(current, "[mcp_servers."+setupMCPServerName+"]")
	block := fmt.Sprintf("[mcp_servers.%s]\nurl = %q\nbearer_token_env_var = %q\n", setupMCPServerName, mcpURL, tokenEnvVar)
	next := strings.TrimRight(current, "\n")
	if next != "" {
		next += "\n\n"
	}
	next += block
	if err := validateCodexProjectTOML(next); err != nil {
		return fmt.Errorf("validate updated Codex config: %w", err)
	}
	return connectAtomicWrite(path, []byte(next), allowedRoot)
}

func structToObject(v any) (map[string]any, error) {
	data, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, err
	}
	return m, nil
}

func equalSetupStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}

func writePrivateFileAtomic(path string, data []byte, allowedRoot string) error {
	return writePrivateFileAtomicWithMutationHook(path, data, allowedRoot, nil)
}

func writePrivateFileAtomicWithMutationHook(path string, data []byte, allowedRoot string, beforeMutation func()) error {
	if allowedRoot != "" {
		root, err := os.OpenRoot(allowedRoot)
		if err != nil {
			return fmt.Errorf("open project workspace root %q: %w", allowedRoot, err)
		}
		defer func() { _ = root.Close() }()

		canonicalRoot, err := canonicalPrivateFileRoot(allowedRoot)
		if err != nil {
			return err
		}
		writePath, err := privateFileWritePath(path, canonicalRoot)
		if err != nil {
			return err
		}
		if !privateFilePathWithinRoot(canonicalRoot, writePath) || !privateFilePathWithinRoot(canonicalRoot, filepath.Dir(writePath)) {
			return fmt.Errorf("private config path %q resolves outside opened project workspace %q", path, canonicalRoot)
		}
		relPath, err := filepath.Rel(canonicalRoot, writePath)
		if err != nil {
			return fmt.Errorf("make private config path relative to project workspace: %w", err)
		}
		if beforeMutation != nil {
			beforeMutation()
		}
		return writePrivateFileAtomicInRoot(root, relPath, data)
	}

	writePath, err := privateFileWritePath(path, allowedRoot)
	if err != nil {
		return err
	}
	if beforeMutation != nil {
		beforeMutation()
	}
	return writePrivateFileAtomicAtPath(writePath, data)
}

func writePrivateFileAtomicAtPath(writePath string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(writePath), 0o750); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(writePath), ".helm-tmp-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer func() { _ = os.Remove(tmpPath) }()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpPath, writePath)
}

func writePrivateFileAtomicInRoot(root *os.Root, writePath string, data []byte) error {
	parent := filepath.Dir(writePath)
	if err := root.MkdirAll(parent, 0o750); err != nil {
		return err
	}
	tmp, tmpPath, err := createPrivateRootTemp(root, parent)
	if err != nil {
		return err
	}
	defer func() { _ = root.Remove(tmpPath) }()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return root.Rename(tmpPath, writePath)
}

func createPrivateRootTemp(root *os.Root, parent string) (*os.File, string, error) {
	for range 100 {
		var random [12]byte
		if _, err := rand.Read(random[:]); err != nil {
			return nil, "", fmt.Errorf("generate private config temp name: %w", err)
		}
		path := filepath.Join(parent, fmt.Sprintf(".helm-tmp-%x", random[:]))
		file, err := root.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
		if err == nil {
			return file, path, nil
		}
		if !os.IsExist(err) {
			return nil, "", err
		}
	}
	return nil, "", fmt.Errorf("create private config temp file: exhausted unique names")
}

func privateFileWritePath(path, allowedRoot string) (string, error) {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("resolve private config path %q: %w", path, err)
	}

	var writePath string
	_, err = os.Lstat(absPath)
	switch {
	case err == nil:
		resolved, resolveErr := filepath.EvalSymlinks(absPath)
		if resolveErr != nil {
			return "", fmt.Errorf("resolve private config path %q: %w", path, resolveErr)
		}
		targetInfo, statErr := os.Stat(resolved)
		if statErr != nil {
			return "", fmt.Errorf("stat private config target %q: %w", path, statErr)
		}
		if !targetInfo.Mode().IsRegular() {
			return "", fmt.Errorf("private config path %q targets a non-regular file", path)
		}
		writePath = resolved
	case os.IsNotExist(err):
		resolvedParent, resolveErr := resolvePrivateFileParent(filepath.Dir(absPath))
		if resolveErr != nil {
			return "", fmt.Errorf("resolve private config parent for %q: %w", path, resolveErr)
		}
		writePath = filepath.Join(resolvedParent, filepath.Base(absPath))
	default:
		return "", err
	}

	if allowedRoot == "" {
		return writePath, nil
	}
	root, err := canonicalPrivateFileRoot(allowedRoot)
	if err != nil {
		return "", err
	}
	if !privateFilePathWithinRoot(root, writePath) || !privateFilePathWithinRoot(root, filepath.Dir(writePath)) {
		return "", fmt.Errorf("private config path %q resolves outside project workspace %q", path, root)
	}
	return writePath, nil
}

func resolvePrivateFileParent(parent string) (string, error) {
	missing := make([]string, 0, 2)
	for current := parent; ; current = filepath.Dir(current) {
		resolved, err := filepath.EvalSymlinks(current)
		if err == nil {
			info, statErr := os.Stat(resolved)
			if statErr != nil {
				return "", statErr
			}
			if !info.IsDir() {
				return "", fmt.Errorf("private config parent %q is not a directory", current)
			}
			for i := len(missing) - 1; i >= 0; i-- {
				resolved = filepath.Join(resolved, missing[i])
			}
			return resolved, nil
		}

		if info, lstatErr := os.Lstat(current); lstatErr == nil {
			return "", fmt.Errorf("resolve private config parent %q: %w (mode %v)", current, err, info.Mode())
		} else if !os.IsNotExist(lstatErr) {
			return "", lstatErr
		}
		next := filepath.Dir(current)
		if next == current {
			return "", err
		}
		missing = append(missing, filepath.Base(current))
	}
}

func canonicalPrivateFileRoot(root string) (string, error) {
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return "", fmt.Errorf("resolve project workspace %q: %w", root, err)
	}
	resolved, err := filepath.EvalSymlinks(absRoot)
	if err != nil {
		return "", fmt.Errorf("resolve project workspace %q: %w", root, err)
	}
	info, err := os.Stat(resolved)
	if err != nil {
		return "", fmt.Errorf("stat project workspace %q: %w", root, err)
	}
	if !info.IsDir() {
		return "", fmt.Errorf("project workspace %q is not a directory", root)
	}
	return resolved, nil
}

func privateFilePathWithinRoot(root, path string) bool {
	rel, err := filepath.Rel(root, path)
	if err != nil || filepath.IsAbs(rel) || rel == ".." {
		return false
	}
	return !strings.HasPrefix(rel, ".."+string(filepath.Separator))
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

func defaultSetupDataDir() string {
	home, err := os.UserHomeDir()
	if err != nil || strings.TrimSpace(home) == "" || !filepath.IsAbs(home) {
		return ""
	}
	return filepath.Join(home, ".helm-ai-kernel")
}

func homeDirOrEmpty() string {
	home, err := os.UserHomeDir()
	if err != nil || strings.TrimSpace(home) == "" || !filepath.IsAbs(home) {
		return ""
	}
	return home
}

func setupUserPath(parts ...string) string {
	home := homeDirOrEmpty()
	if home == "" {
		return ""
	}
	return filepath.Join(append([]string{home}, parts...)...)
}
