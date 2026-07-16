package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/BurntSushi/toml"
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
	Target       string
	Operation    string
	Scope        string
	Workspace    string
	WorkspaceSet bool
	Yes          bool
	DryRun       bool
	JSON         bool
	NoQuickstart bool
	DataDir      string
}

type setupSummary struct {
	Operation         string   `json:"operation"`
	Target            string   `json:"target"`
	Workspace         string   `json:"workspace"`
	BinaryPath        string   `json:"binary_path"`
	ClientConfigPath  string   `json:"client_config_path"`
	HookConfigPath    string   `json:"hook_config_path"`
	DataDir           string   `json:"data_dir"`
	KernelURL         string   `json:"kernel_url"`
	ScanGrade         string   `json:"scan_grade"`
	DraftPolicyPath   string   `json:"draft_policy_path"`
	UninstallCommand  string   `json:"uninstall_command"`
	Scope             string   `json:"scope,omitempty"`
	MCPInstalled      bool     `json:"mcp_installed"`
	HookInstalled     bool     `json:"hook_installed"`
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
	if opts.Target == "codex" && opts.Scope == "project" {
		if _, err := loadOrGenerateSignerWithDataDir(opts.DataDir); err != nil {
			fmt.Fprintf(stderr, "setup: initialize shared receipt signer: %v\n", err)
			return 1
		}
	}
	grade, policyPath, err := runSetupAutoconfigure(opts.DataDir, opts.Workspace)
	if err != nil {
		fmt.Fprintf(stderr, "setup: autoconfigure: %v\n", err)
		return 1
	}
	summary.ScanGrade = grade
	summary.DraftPolicyPath = policyPath
	if opts.Target == "codex" && opts.Scope == "project" {
		projectDir, err := openCodexProjectDir(opts.Workspace, true)
		if err != nil {
			fmt.Fprintf(stderr, "setup: open project Codex config: %v\n", err)
			return 1
		}
		defer func() { _ = projectDir.Close() }()
		if err := installCodexProjectSetup(projectDir, opts, summary.BinaryPath); err != nil {
			fmt.Fprintf(stderr, "setup: install project Codex integration: %v\n", err)
			return 1
		}
	} else {
		if err := installSetupMCP(opts, summary.BinaryPath); err != nil {
			fmt.Fprintf(stderr, "setup: install MCP server: %v\n", err)
			return 1
		}
		if err := installSetupHook(opts, summary.BinaryPath); err != nil {
			fmt.Fprintf(stderr, "setup: install pre-tool hook: %v\n", err)
			return 1
		}
	}
	summary.MCPInstalled = true
	summary.HookInstalled = true
	printSetupSummary(stdout, summary, opts.JSON)
	if opts.NoQuickstart {
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
	return setupRunQuickstart(quickstartArgs, quickstartStdout, stderr)
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
	if opts.Target == "codex" && opts.Scope == "project" {
		projectDir, err := openCodexProjectDir(opts.Workspace, false)
		switch {
		case err == nil:
			defer func() { _ = projectDir.Close() }()
			summary.MCPInstalled, err = codexProjectMCPInstalled(projectDir, summary.BinaryPath, opts.DataDir)
			if err == nil {
				summary.HookInstalled, err = codexProjectHookInstalled(projectDir, setupHookCommand(opts, summary.BinaryPath))
			}
			if err != nil {
				fmt.Fprintf(stderr, "setup status: inspect project Codex config: %v\n", err)
				return 2
			}
		case err == errCodexProjectDirNotFound:
			// An unconfigured project is a truthful incomplete status, not an error.
		default:
			fmt.Fprintf(stderr, "setup status: open project Codex config: %v\n", err)
			return 2
		}
	} else {
		summary.MCPInstalled = setupMCPInstalled(opts, summary.ClientConfigPath, summary.BinaryPath)
		summary.HookInstalled = setupHookInstalled(opts, summary.HookConfigPath, summary.BinaryPath)
	}
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
	if opts.Target == "codex" && opts.Scope == "project" {
		projectDir, err := openCodexProjectDir(opts.Workspace, false)
		switch {
		case err == nil:
			defer func() { _ = projectDir.Close() }()
			summary.MCPInstalled, err = codexProjectMCPInstalled(projectDir, summary.BinaryPath, opts.DataDir)
			if err == nil {
				summary.HookInstalled, err = codexProjectHookInstalled(projectDir, setupHookCommand(opts, summary.BinaryPath))
			}
			if err != nil {
				fmt.Fprintf(stderr, "setup remove: inspect project Codex config: %v\n", err)
				return 1
			}
			if !opts.DryRun {
				if err := removeCodexProjectSetup(projectDir); err != nil {
					fmt.Fprintf(stderr, "setup remove: remove project Codex integration: %v\n", err)
					return 1
				}
			}
		case err == errCodexProjectDirNotFound:
			// Nothing is installed in this project yet.
		default:
			fmt.Fprintf(stderr, "setup remove: open project Codex config: %v\n", err)
			return 1
		}
	} else {
		summary.MCPInstalled = setupMCPInstalled(opts, summary.ClientConfigPath, summary.BinaryPath)
		summary.HookInstalled = setupHookInstalled(opts, summary.HookConfigPath, summary.BinaryPath)
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
	fs.StringVar(&opts.Workspace, "workspace", "", "Workspace to scan and configure (required for project scope)")
	fs.BoolVar(&opts.Yes, "yes", false, "Install without prompting")
	fs.BoolVar(&opts.DryRun, "dry-run", false, "Print planned changes without writing config")
	fs.BoolVar(&opts.JSON, "json", false, "Print machine-readable summary")
	fs.BoolVar(&opts.NoQuickstart, "no-quickstart", false, "Install without starting the blocking Quickstart server")
	fs.StringVar(&opts.DataDir, "data-dir", "", "Directory for HELM local state")
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
	fs.StringVar(&opts.Workspace, "workspace", "", "Workspace to inspect or remove from (required for project scope)")
	fs.BoolVar(&opts.DryRun, "dry-run", false, "Print planned changes without writing config")
	fs.BoolVar(&opts.JSON, "json", false, "Print machine-readable summary")
	fs.BoolVar(&opts.NoQuickstart, "no-quickstart", false, "Report a headless setup without a Quickstart server")
	fs.StringVar(&opts.DataDir, "data-dir", "", "Directory for HELM local state")
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
	if opts.Target != "codex" && opts.WorkspaceSet {
		fmt.Fprintln(stderr, "setup: --workspace is currently supported only for Codex project scope")
		return opts, 2
	}
	if opts.Target == "codex" && opts.Scope == "project" && (!opts.WorkspaceSet || strings.TrimSpace(opts.Workspace) == "") {
		fmt.Fprintln(stderr, "setup: Codex --scope project requires an explicit --workspace DIR with a non-empty value")
		return opts, 2
	}
	if opts.Target == "codex" && opts.Scope == "user" && opts.WorkspaceSet {
		fmt.Fprintln(stderr, "setup: --workspace is only valid with Codex --scope project")
		return opts, 2
	}
	if opts.DataDir == "" {
		opts.DataDir = defaultSetupDataDir()
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
	opts.Workspace = filepath.Clean(opts.Workspace)
	if opts.Target == "codex" && opts.Scope == "project" && filepath.Dir(opts.Workspace) == opts.Workspace {
		fmt.Fprintln(stderr, "setup: workspace must not be the filesystem root")
		return opts, 2
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
		QuickstartStarted: opts.Operation == "install" && !opts.NoQuickstart,
		PlannedActions:    setupPlannedActions(opts),
	}, nil
}

func setupPlannedActions(opts setupOptions) []string {
	switch opts.Operation {
	case "preview", "install":
		hookAction := "configure the HELM PreToolUse hook for the selected client"
		if opts.Target == "codex" {
			hookAction = "configure the HELM PreToolUse hook for supported Codex tools"
		}
		actions := []string{
			"scan selected workspace and write draft-only inventory artifacts",
			"configure the HELM MCP server with the selected local data directory",
			hookAction,
		}
		if !opts.NoQuickstart {
			actions = append(actions, "start the local Quickstart proof path")
		}
		return actions
	case "status":
		return []string{"inspect the existing local integration without writing files"}
	case "preview_remove", "remove":
		return []string{"remove the HELM MCP server and PreToolUse hook from the selected scope"}
	default:
		return nil
	}
}

func setupKernelURL(opts setupOptions) string {
	if opts.NoQuickstart {
		return ""
	}
	return "http://127.0.0.1:7714"
}

func setupUninstallCommand(opts setupOptions) string {
	workspace := ""
	if opts.Target == "codex" && opts.Scope == "project" {
		workspace = " --workspace " + shellQuote(opts.Workspace)
	}
	return fmt.Sprintf(
		"helm-ai-kernel setup remove %s --scope %s%s --yes --data-dir %s",
		opts.Target,
		opts.Scope,
		workspace,
		shellQuote(opts.DataDir),
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
		return setupExecCommand("claude", "mcp", "add", "--transport", "stdio", "--scope", opts.Scope, setupMCPServerName, "--", bin, "mcp", "serve", "--transport", "stdio")
	case "codex":
		if opts.Scope == "project" {
			projectDir, err := openCodexProjectDir(opts.Workspace, true)
			if err != nil {
				return err
			}
			defer func() { _ = projectDir.Close() }()
			return upsertCodexProjectMCP(projectDir, bin, opts.DataDir)
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
			projectDir, err := openCodexProjectDir(opts.Workspace, false)
			if err == errCodexProjectDirNotFound {
				return nil
			}
			if err != nil {
				return err
			}
			defer func() { _ = projectDir.Close() }()
			return removeCodexProjectMCP(projectDir)
		}
		return setupExecCommand("codex", "mcp", "remove", setupMCPServerName)
	default:
		return fmt.Errorf("unsupported target %q", opts.Target)
	}
}

func installSetupHook(opts setupOptions, bin string) error {
	if opts.Target == "codex" && opts.Scope == "project" {
		projectDir, err := openCodexProjectDir(opts.Workspace, true)
		if err != nil {
			return err
		}
		defer func() { _ = projectDir.Close() }()
		return upsertCodexProjectHook(projectDir, setupHookMatcher(opts.Target), setupHookCommand(opts, bin))
	}
	return upsertHookConfig(setupHookConfigPath(opts), setupHookMatcher(opts.Target), setupHookCommand(opts, bin))
}

func removeSetupHook(opts setupOptions, bin string) error {
	if opts.Target == "codex" && opts.Scope == "project" {
		projectDir, err := openCodexProjectDir(opts.Workspace, false)
		if err == errCodexProjectDirNotFound {
			return nil
		}
		if err != nil {
			return err
		}
		defer func() { _ = projectDir.Close() }()
		return removeCodexProjectHook(projectDir)
	}
	return removeHookConfig(setupHookConfigPath(opts), setupHookCommand(opts, bin))
}

func installCodexProjectSetup(projectDir *codexProjectDir, opts setupOptions, bin string) error {
	config, err := prepareCodexProjectMCPUpsert(projectDir, bin, opts.DataDir)
	if err != nil {
		return err
	}
	hooks, err := prepareCodexProjectHookUpsert(projectDir, setupHookMatcher(opts.Target), setupHookCommand(opts, bin))
	if err != nil {
		return err
	}
	if config != nil {
		if err := projectDir.writePrivateFileAtomic("config.toml", config); err != nil {
			return err
		}
	}
	if hooks != nil {
		if err := projectDir.writePrivateFileAtomic("hooks.json", hooks); err != nil {
			return err
		}
	}
	return nil
}

func removeCodexProjectSetup(projectDir *codexProjectDir) error {
	config, err := prepareCodexProjectMCPRemoval(projectDir)
	if err != nil {
		return err
	}
	hooks, err := prepareCodexProjectHookRemoval(projectDir)
	if err != nil {
		return err
	}
	if hooks != nil {
		if err := projectDir.writePrivateFileAtomic("hooks.json", hooks); err != nil {
			return err
		}
	}
	if config != nil {
		if err := projectDir.writePrivateFileAtomic("config.toml", config); err != nil {
			return err
		}
	}
	return nil
}

func setupMCPInstalled(opts setupOptions, path, bin string) bool {
	return fileContains(path, setupMCPServerName)
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
			return ".mcp.json"
		}
		return filepath.Join(homeDirOrDot(), ".claude.json")
	case "codex":
		if opts.Scope == "project" {
			return filepath.Join(opts.Workspace, ".codex", "config.toml")
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
			return filepath.Join(".claude", "settings.json")
		}
		return filepath.Join(homeDirOrDot(), ".claude", "settings.json")
	case "codex":
		if opts.Scope == "project" {
			return filepath.Join(opts.Workspace, ".codex", "hooks.json")
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

func upsertCodexProjectHook(projectDir *codexProjectDir, matcher, command string) error {
	next, err := prepareCodexProjectHookUpsert(projectDir, matcher, command)
	if err != nil || next == nil {
		return err
	}
	return projectDir.writePrivateFileAtomic("hooks.json", next)
}

func prepareCodexProjectHookUpsert(projectDir *codexProjectDir, matcher, command string) ([]byte, error) {
	root, hooks, pre, err := readCodexProjectHooks(projectDir)
	if os.IsNotExist(err) {
		root = map[string]any{}
		hooks = map[string]any{}
		pre = []any{}
		err = nil
	}
	if err != nil {
		return nil, err
	}
	updated, found, changed := reconcileOwnedCodexHooks(pre, matcher, command)
	if found {
		if !changed {
			return nil, nil
		}
		hooks["PreToolUse"] = updated
		root["hooks"] = hooks
		return marshalCodexProjectHooks(root)
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
	return marshalCodexProjectHooks(root)
}

func removeCodexProjectHook(projectDir *codexProjectDir) error {
	next, err := prepareCodexProjectHookRemoval(projectDir)
	if err != nil || next == nil {
		return err
	}
	return projectDir.writePrivateFileAtomic("hooks.json", next)
}

func prepareCodexProjectHookRemoval(projectDir *codexProjectDir) ([]byte, error) {
	root, hooks, pre, err := readCodexProjectHooks(projectDir)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	changed := false
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
		for _, hook := range hookItems {
			if isOwnedCodexHook(hook) {
				changed = true
				continue
			}
			keptHooks = append(keptHooks, hook)
		}
		if len(keptHooks) > 0 {
			obj["hooks"] = keptHooks
			filtered = append(filtered, obj)
		} else if len(hookItems) > 0 {
			changed = true
		} else {
			filtered = append(filtered, obj)
		}
	}
	if !changed {
		return nil, nil
	}
	hooks["PreToolUse"] = filtered
	root["hooks"] = hooks
	return marshalCodexProjectHooks(root)
}

func codexProjectHookInstalled(projectDir *codexProjectDir, command string) (bool, error) {
	_, _, pre, err := readCodexProjectHooks(projectDir)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return currentOwnedCodexHookPresent(pre, command), nil
}

func readCodexProjectHooks(projectDir *codexProjectDir) (map[string]any, map[string]any, []any, error) {
	raw, err := projectDir.readRegularFile("hooks.json")
	if err != nil {
		return nil, nil, nil, err
	}
	var root map[string]any
	if err := json.Unmarshal(raw, &root); err != nil {
		return nil, nil, nil, fmt.Errorf("parse existing Codex hooks: %w", err)
	}
	if root == nil {
		return nil, nil, nil, fmt.Errorf("parse existing Codex hooks: root must be an object")
	}
	hooksValue, hasHooks := root["hooks"]
	if !hasHooks {
		return root, map[string]any{}, []any{}, nil
	}
	hooks, ok := hooksValue.(map[string]any)
	if !ok {
		return nil, nil, nil, fmt.Errorf("parse existing Codex hooks: hooks must be an object")
	}
	preValue, hasPre := hooks["PreToolUse"]
	if !hasPre {
		return root, hooks, []any{}, nil
	}
	pre, ok := preValue.([]any)
	if !ok {
		return nil, nil, nil, fmt.Errorf("parse existing Codex hooks: hooks.PreToolUse must be an array")
	}
	return root, hooks, pre, nil
}

func marshalCodexProjectHooks(root map[string]any) ([]byte, error) {
	data, err := json.MarshalIndent(root, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

func currentOwnedCodexHookPresent(pre []any, command string) bool {
	for _, item := range pre {
		obj, ok := item.(map[string]any)
		if !ok {
			continue
		}
		hooks, ok := obj["hooks"].([]any)
		if !ok {
			continue
		}
		for _, hook := range hooks {
			if isOwnedCodexHook(hook) && hookCommandFromAny(hook) == command {
				return true
			}
		}
	}
	return false
}

func isOwnedCodexHook(v any) bool {
	obj, ok := v.(map[string]any)
	if !ok || obj["type"] != "command" || obj["statusMessage"] != "Checking HELM policy" {
		return false
	}
	return isCodexHookCommand(hookCommandFromAny(v))
}

func isCodexHookCommand(command string) bool {
	words, ok := splitSetupShellWords(command)
	if !ok || len(words) != 7 || words[0] == "" || words[6] == "" {
		return false
	}
	return words[1] == "hook" && words[2] == "pre-tool" && words[3] == "--client" && words[4] == "codex" && words[5] == "--data-dir"
}

func reconcileOwnedCodexHooks(pre []any, matcher, command string) ([]any, bool, bool) {
	updated := make([]any, 0, len(pre))
	found := false
	changed := false
	var dedicatedOwned map[string]any
	for _, item := range pre {
		obj, ok := item.(map[string]any)
		if !ok {
			updated = append(updated, item)
			continue
		}
		hookItems, ok := obj["hooks"].([]any)
		if !ok {
			updated = append(updated, item)
			continue
		}
		ownedCount := 0
		for _, hook := range hookItems {
			if isOwnedCodexHook(hook) {
				ownedCount++
			}
		}
		kept := make([]any, 0, len(hookItems))
		for _, hook := range hookItems {
			if !isOwnedCodexHook(hook) {
				kept = append(kept, hook)
				continue
			}
			if found {
				changed = true
				continue
			}
			found = true
			owned := cloneSetupJSONObject(hook.(map[string]any))
			if owned["command"] != command || owned["timeout"] != float64(30) {
				changed = true
			}
			owned["command"] = command
			owned["timeout"] = float64(30)
			if entryMatcher, _ := obj["matcher"].(string); entryMatcher != matcher && len(hookItems) != ownedCount {
				// Do not widen a shared user entry. Move the marked HELM hook
				// into a dedicated entry with the current matcher instead.
				dedicatedOwned = owned
				changed = true
				continue
			}
			if obj["matcher"] != matcher {
				obj["matcher"] = matcher
				changed = true
			}
			kept = append(kept, owned)
		}
		if len(kept) > 0 {
			if len(kept) != len(hookItems) || changed {
				obj["hooks"] = kept
			}
			updated = append(updated, obj)
		} else if len(hookItems) > 0 {
			changed = true
		} else {
			updated = append(updated, obj)
		}
	}
	if dedicatedOwned != nil {
		updated = append(updated, map[string]any{
			"matcher": matcher,
			"hooks":   []any{dedicatedOwned},
		})
	}
	return updated, found, changed
}

func cloneSetupJSONObject(input map[string]any) map[string]any {
	clone := make(map[string]any, len(input))
	for key, value := range input {
		clone[key] = value
	}
	return clone
}

// splitSetupShellWords accepts the small, deterministic shell-quoting subset
// emitted by shellQuote. It deliberately does not execute or interpret shell
// expansions; it is used only to recognize a HELM-owned hook during removal.
func splitSetupShellWords(input string) ([]string, bool) {
	var words []string
	var word strings.Builder
	inWord := false
	inSingle := false
	inDouble := false
	for i := 0; i < len(input); i++ {
		ch := input[i]
		switch {
		case inSingle:
			if ch == 0x27 {
				inSingle = false
			} else {
				word.WriteByte(ch)
			}
		case inDouble:
			switch ch {
			case '"':
				inDouble = false
			case '\\':
				i++
				if i >= len(input) {
					return nil, false
				}
				word.WriteByte(input[i])
			default:
				word.WriteByte(ch)
			}
		case ch == 0x27:
			inSingle = true
			inWord = true
		case ch == '"':
			inDouble = true
			inWord = true
		case ch == '\\':
			i++
			if i >= len(input) {
				return nil, false
			}
			word.WriteByte(input[i])
			inWord = true
		case ch == ' ' || ch == '\t' || ch == '\n':
			if inWord {
				words = append(words, word.String())
				word.Reset()
				inWord = false
			}
		default:
			word.WriteByte(ch)
			inWord = true
		}
	}
	if inSingle || inDouble {
		return nil, false
	}
	if inWord {
		words = append(words, word.String())
	}
	return words, true
}

func upsertCodexProjectMCP(projectDir *codexProjectDir, bin, dataDir string) error {
	next, err := prepareCodexProjectMCPUpsert(projectDir, bin, dataDir)
	if err != nil || next == nil {
		return err
	}
	return projectDir.writePrivateFileAtomic("config.toml", next)
}

func prepareCodexProjectMCPUpsert(projectDir *codexProjectDir, bin, dataDir string) ([]byte, error) {
	current := ""
	if raw, err := projectDir.readRegularFile("config.toml"); err == nil {
		current = string(raw)
		if err := validateCodexProjectTOML(current); err != nil {
			return nil, fmt.Errorf("parse existing Codex config: %w", err)
		}
		var config codexProjectConfig
		if _, err := toml.Decode(current, &config); err != nil {
			return nil, fmt.Errorf("parse existing Codex config: %w", err)
		}
		if server, exists := config.MCPServers[setupMCPServerName]; exists && !isOwnedCodexMCPServer(server) {
			return nil, fmt.Errorf("refuse to replace non-HELM Codex MCP server %q", setupMCPServerName)
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	current = removeTOMLTable(current, "[mcp_servers."+setupMCPServerName+"]")
	block := fmt.Sprintf("[mcp_servers.%s]\ncommand = %q\nargs = [\"mcp\", \"serve\", \"--transport\", \"stdio\", \"--data-dir\", %q]\n", setupMCPServerName, bin, dataDir)
	next := strings.TrimRight(current, "\n")
	if next != "" {
		next += "\n\n"
	}
	next += block
	if err := validateCodexProjectTOML(next); err != nil {
		return nil, fmt.Errorf("validate updated Codex config: %w", err)
	}
	return []byte(next), nil
}

func removeCodexProjectMCP(projectDir *codexProjectDir) error {
	next, err := prepareCodexProjectMCPRemoval(projectDir)
	if err != nil || next == nil {
		return err
	}
	return projectDir.writePrivateFileAtomic("config.toml", next)
}

func prepareCodexProjectMCPRemoval(projectDir *codexProjectDir) ([]byte, error) {
	raw, err := projectDir.readRegularFile("config.toml")
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if err := validateCodexProjectTOML(string(raw)); err != nil {
		return nil, fmt.Errorf("parse existing Codex config: %w", err)
	}
	var config codexProjectConfig
	if _, err := toml.Decode(string(raw), &config); err != nil {
		return nil, fmt.Errorf("parse existing Codex config: %w", err)
	}
	server, exists := config.MCPServers[setupMCPServerName]
	if !exists || !isOwnedCodexMCPServer(server) {
		return nil, nil
	}
	next := strings.TrimRight(removeTOMLTable(string(raw), "[mcp_servers."+setupMCPServerName+"]"), "\n") + "\n"
	if err := validateCodexProjectTOML(next); err != nil {
		return nil, fmt.Errorf("validate updated Codex config: %w", err)
	}
	return []byte(next), nil
}

type codexProjectConfig struct {
	MCPServers map[string]codexMCPServer `toml:"mcp_servers"`
}

type codexMCPServer struct {
	Command string   `toml:"command"`
	Args    []string `toml:"args"`
}

func isOwnedCodexMCPServer(server codexMCPServer) bool {
	switch strings.ToLower(filepath.Base(strings.TrimSpace(server.Command))) {
	case "helm-ai-kernel", "helm-ai-kernel.exe", "helm-ai-kernel.test":
		// Exact known HELM kernel executable names only. A named server is not
		// ownership proof on its own, and lookalike executable names stay intact.
	default:
		return false
	}
	if len(server.Args) != 6 || server.Args[0] != "mcp" || server.Args[1] != "serve" || server.Args[2] != "--transport" || server.Args[3] != "stdio" || server.Args[4] != "--data-dir" {
		return false
	}
	return strings.TrimSpace(server.Args[5]) != ""
}

func validateCodexProjectTOML(raw string) error {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	var config map[string]any
	_, err := toml.Decode(raw, &config)
	return err
}

func codexProjectMCPInstalled(projectDir *codexProjectDir, bin, dataDir string) (bool, error) {
	raw, err := projectDir.readRegularFile("config.toml")
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	var config codexProjectConfig
	if _, err := toml.Decode(string(raw), &config); err != nil {
		return false, fmt.Errorf("parse existing Codex config: %w", err)
	}
	server, ok := config.MCPServers[setupMCPServerName]
	if !ok || server.Command != bin {
		return false, nil
	}
	return equalSetupStrings(server.Args, setupMCPArgs(dataDir)), nil
}

func setupMCPArgs(dataDir string) []string {
	return []string{"mcp", "serve", "--transport", "stdio", "--data-dir", dataDir}
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

func removeTOMLTable(input, table string) string {
	target, ok := tomlTableHeader(strings.TrimSpace(table))
	if !ok {
		return strings.TrimRight(input, "\n")
	}
	lines := strings.Split(input, "\n")
	out := make([]string, 0, len(lines))
	skipping := false
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if header, ok := tomlTableHeader(trimmed); ok {
			skipping = tomlTableIsOwnedBy(header, target)
		}
		if !skipping {
			out = append(out, line)
		}
	}
	return strings.TrimRight(strings.Join(out, "\n"), "\n")
}

func tomlTableIsOwnedBy(header, target []string) bool {
	if len(header) < len(target) {
		return false
	}
	for i := range target {
		if header[i] != target[i] {
			return false
		}
	}
	return true
}

func tomlTableHeader(line string) ([]string, bool) {
	line = strings.TrimSpace(line)
	if !strings.HasPrefix(line, "[") {
		return nil, false
	}
	array := strings.HasPrefix(line, "[[")
	start := 1
	if array {
		start = 2
	}
	inBasic := false
	inLiteral := false
	escaped := false
	for i := start; i < len(line); i++ {
		ch := line[i]
		switch {
		case inBasic:
			if escaped {
				escaped = false
				continue
			}
			if ch == '\\' {
				escaped = true
			} else if ch == '"' {
				inBasic = false
			}
		case inLiteral:
			if ch == '\'' {
				inLiteral = false
			}
		case ch == '"':
			inBasic = true
		case ch == '\'':
			inLiteral = true
		case ch == ']':
			end := i + 1
			if array {
				if end >= len(line) || line[end] != ']' {
					return nil, false
				}
				end++
			}
			rest := strings.TrimSpace(line[end:])
			if rest != "" && !strings.HasPrefix(rest, "#") {
				return nil, false
			}
			return parseTOMLDottedKey(line[start:i])
		}
	}
	return nil, false
}

func parseTOMLDottedKey(input string) ([]string, bool) {
	var segments []string
	for i := 0; ; {
		for i < len(input) && (input[i] == ' ' || input[i] == '\t') {
			i++
		}
		if i >= len(input) {
			return nil, false
		}
		var segment string
		switch input[i] {
		case '"':
			start := i
			i++
			escaped := false
			for i < len(input) {
				if escaped {
					escaped = false
					i++
					continue
				}
				if input[i] == '\\' {
					escaped = true
				} else if input[i] == '"' {
					i++
					value, err := strconv.Unquote(input[start:i])
					if err != nil {
						return nil, false
					}
					segment = value
					break
				}
				i++
			}
			if segment == "" && (i == len(input) || input[i-1] != '"') {
				return nil, false
			}
		case '\'':
			i++
			start := i
			for i < len(input) && input[i] != '\'' {
				i++
			}
			if i >= len(input) {
				return nil, false
			}
			segment = input[start:i]
			i++
		default:
			start := i
			for i < len(input) && input[i] != '.' && input[i] != ' ' && input[i] != '\t' {
				i++
			}
			segment = input[start:i]
		}
		if segment == "" {
			return nil, false
		}
		segments = append(segments, segment)
		for i < len(input) && (input[i] == ' ' || input[i] == '\t') {
			i++
		}
		if i == len(input) {
			return segments, true
		}
		if input[i] != '.' {
			return nil, false
		}
		i++
	}
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
