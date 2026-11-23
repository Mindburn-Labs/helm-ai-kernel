package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/internal/cli/ui"
)

type setupRecoveryMarker struct {
	Version         int    `json:"version"`
	Target          string `json:"target"`
	Scope           string `json:"scope"`
	Workspace       string `json:"workspace"`
	SigningSeedFile string `json:"signing_seed_file,omitempty"`
	PolicyProfile   string `json:"policy_profile,omitempty"`
}

func runSetupStatusCmd(args []string, stdout, stderr io.Writer) int {
	if isHelpRequest(args) {
		printSetupInspectUsage(stdout, "status", false)
		return 0
	}
	if isSetupFleetStatusArgs(args) {
		return runSetupStatusFleetCmd(args, stdout, stderr)
	}
	if len(args) > 0 && isPrintConfigTarget(args[0]) {
		return runSetupStatusPrintConfigCmd(args, stdout, stderr)
	}
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
	marker, recoveryPending, err := readSetupRecoveryMarker(opts)
	if err != nil {
		fmt.Fprintf(stderr, "setup status: recovery marker: %v\n", err)
		return 2
	}
	if recoveryPending && marker.matches(opts) {
		recoveryOpts := marker.options(opts)
		if err := populateSetupPolicyProfileDigest(&recoveryOpts); err != nil {
			fmt.Fprintf(stderr, "setup status: policy profile: %v\n", err)
			return 2
		}
		summary.RecoveryCommand = setupRecoveryCommand(recoveryOpts)
		summary.RecoveryRequired = true
		summary.MCPInstalled = setupMCPInstalled(recoveryOpts, summary.ClientConfigPath, summary.BinaryPath)
		summary.HookInstalled = setupHookInstalled(recoveryOpts, summary.HookConfigPath, summary.BinaryPath)
		summary.ClientState = "recovery_required"
		assignSetupLifecycle(&summary)
		printSetupSummary(stdout, summary, opts.JSON)
		return 1
	}
	if !opts.PolicyProfileSet {
		if err := discoverSetupStatusPolicyProfile(&opts, summary.HookConfigPath, summary.BinaryPath); err != nil {
			fmt.Fprintf(stderr, "setup status: policy profile: %v\n", err)
			return 2
		}
	}
	if err := populateSetupPolicyProfileDigest(&opts); err != nil {
		fmt.Fprintf(stderr, "setup status: policy profile: %v\n", err)
		return 2
	}
	summary.MCPInstalled = setupMCPInstalled(opts, summary.ClientConfigPath, summary.BinaryPath)
	summary.HookInstalled = setupHookInstalled(opts, summary.HookConfigPath, summary.BinaryPath)
	observeSetupClientState(opts, &summary)
	observeSetupHookMatcher(opts, &summary)
	if grade := readSetupScanGrade(filepath.Join(opts.DataDir, "autoconfigure", "inventory.json")); grade != "" {
		summary.ScanGrade = grade
	}
	assignSetupLifecycle(&summary)
	printSetupSummary(stdout, summary, opts.JSON)
	// On-disk config alone is not healthy: the client must be present and
	// confirm that it loaded HELM, with no explicit trust step still pending.
	if setupStatusHealthy(summary) {
		return 0
	}
	return 1
}

type setupFleetStatus struct {
	Operation string         `json:"operation"`
	DataDir   string         `json:"data_dir"`
	Clients   []setupSummary `json:"clients"`
}

func isSetupFleetStatusArgs(args []string) bool {
	if len(args) == 0 {
		return true
	}
	if args[0] == "all" {
		return true
	}
	return strings.HasPrefix(args[0], "-")
}

func isPrintConfigTarget(target string) bool {
	switch strings.ToLower(strings.TrimSpace(target)) {
	case "cursor", "vscode", "vs-code", "windsurf":
		return true
	default:
		return false
	}
}

func normalizePrintConfigTarget(target string) string {
	switch strings.ToLower(strings.TrimSpace(target)) {
	case "vs-code":
		return "vscode"
	default:
		return strings.ToLower(strings.TrimSpace(target))
	}
}

func runSetupStatusFleetCmd(args []string, stdout, stderr io.Writer) int {
	opts, code := parseSetupFleetArgs("setup status", args, stderr)
	if code != 0 {
		return code
	}
	targets := append(append([]string{}, supportMatrix().DirectSetup...), supportMatrix().ConfigPrint...)
	clients := make([]setupSummary, 0, len(targets))
	exit := 0
	for _, target := range targets {
		for _, scope := range setupInspectionScopes(target) {
			inspect := opts
			inspect.Scope = scope
			summary, err := inspectSetupTarget(inspect, target)
			if err != nil {
				fmt.Fprintf(stderr, "setup status %s (%s): %v\n", target, scope, err)
				exit = 1
				continue
			}
			clients = append(clients, summary)
			if !setupStatusHealthy(summary) && summary.ClientState != "print_config_only" && summary.ClientState != "absent" {
				exit = 1
			}
		}
	}
	fleet := setupFleetStatus{Operation: "status", DataDir: opts.DataDir, Clients: clients}
	if opts.JSON {
		if err := json.NewEncoder(stdout).Encode(fleet); err != nil {
			return 1
		}
		return exit
	}
	fmt.Fprintf(stdout, "HELM setup status (%s)\n", fleet.DataDir)
	for _, client := range clients {
		fmt.Fprintf(stdout, "  %-12s  scope=%-7s  lifecycle=%-10s  state=%s  loaded=%v  config=%s\n",
			client.Target, client.Scope, client.Lifecycle, client.ClientState, client.NativeLoaded, client.ClientConfigPath)
	}
	return exit
}

func runSetupStatusPrintConfigCmd(args []string, stdout, stderr io.Writer) int {
	opts, code := parseSetupFleetArgs("setup status", args[1:], stderr)
	if code != 0 {
		return code
	}
	opts.Target = normalizePrintConfigTarget(args[0])
	summary, err := inspectPrintConfigClient(opts)
	if err != nil {
		fmt.Fprintf(stderr, "setup status: %v\n", err)
		return 2
	}
	printSetupSummary(stdout, summary, opts.JSON)
	return 1
}

func parseSetupFleetArgs(name string, args []string, stderr io.Writer) (setupOptions, int) {
	opts := setupOptions{Scope: "user", Operation: "status", NoQuickstart: true}
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.BoolVar(&opts.JSON, "json", false, "Print machine-readable summary")
	formatFlag := ui.RegisterFormat(fs, ui.FormatText)
	fs.StringVar(&opts.DataDir, "data-dir", "", "Directory for HELM local state")
	fs.StringVar(&opts.Workspace, "workspace", "", "Workspace used to resolve project config paths")
	all := fs.Bool("all", false, "Inspect every supported client")
	_ = all
	if err := fs.Parse(args); err != nil {
		return opts, 2
	}
	opts.JSON = opts.JSON || formatFlag.IsJSON()
	if opts.DataDir == "" {
		opts.DataDir = defaultSetupDataDir()
	}
	if opts.DataDir == "" {
		fmt.Fprintln(stderr, "setup: --data-dir is required when the home directory is unavailable")
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
	return opts, 0
}

// setupInspectionScopes covers every supported installation location. The
// overview and doctor must include the project scope used by default setup.
func setupInspectionScopes(target string) []string {
	switch target {
	case "claude-code", "codex":
		return []string{"project", "user"}
	default:
		return []string{"user"}
	}
}

func inspectSetupTarget(opts setupOptions, target string) (setupSummary, error) {
	if isPrintConfigTarget(target) {
		printOpts := opts
		printOpts.Target = normalizePrintConfigTarget(target)
		return inspectPrintConfigClient(printOpts)
	}
	inspect := opts
	inspect.Target = target
	inspect.Operation = "status"
	normalized, code := normalizeSetupOptions(inspect, io.Discard)
	if code != 0 {
		return setupSummary{}, fmt.Errorf("normalize %s", target)
	}
	summary, err := buildSetupSummary(normalized)
	if err != nil {
		return setupSummary{}, err
	}
	summary.MCPInstalled = setupMCPInstalled(normalized, summary.ClientConfigPath, summary.BinaryPath)
	summary.HookInstalled = setupHookInstalled(normalized, summary.HookConfigPath, summary.BinaryPath)
	observeSetupClientState(normalized, &summary)
	observeSetupHookMatcher(normalized, &summary)
	assignSetupLifecycle(&summary)
	return summary, nil
}

func inspectPrintConfigClient(opts setupOptions) (setupSummary, error) {
	target := normalizePrintConfigTarget(opts.Target)
	summary := setupSummary{
		Operation:        "status",
		Target:           target,
		Workspace:        opts.Workspace,
		DataDir:          opts.DataDir,
		ClientConfigPath: printConfigInspectPath(target, opts.Workspace),
		NativeLoaded:     false,
	}
	path := summary.ClientConfigPath
	if path == "" {
		summary.ClientState = "print_config_only"
		summary.Lifecycle = "absent"
		summary.PlannedActions = []string{"HELM prints config only; it does not own a canonical " + target + " path and does not claim the client loaded it"}
		return summary, nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		summary.ClientState = "absent"
		summary.Lifecycle = "absent"
		return summary, nil
	}
	if !strings.Contains(string(raw), setupMCPServerName) {
		summary.ClientState = "config_present_no_helm"
		summary.Lifecycle = "absent"
		return summary, nil
	}
	summary.MCPInstalled = true
	summary.ClientState = "configured_unverified"
	summary.Lifecycle = "configured"
	return summary, nil
}

func printConfigInspectPath(target, workspace string) string {
	switch target {
	case "cursor":
		return filepath.Join(workspace, ".cursor", "mcp.json")
	case "vscode":
		return filepath.Join(workspace, ".vscode", "settings.json")
	default:
		return ""
	}
}

func assignSetupLifecycle(summary *setupSummary) {
	if summary.Lifecycle != "" {
		return
	}
	summary.Lifecycle = setupLifecycleOf(summary.ClientState)
}

func setupLifecycleOf(state string) string {
	switch state {
	case "absent", "removed", "config_present_no_helm", "print_config_only":
		return "absent"
	case "planned", "planned_removal":
		return "planned"
	case "trust_pending":
		return "pending"
	case "native_loaded":
		return "active"
	case "degraded":
		return "degraded"
	case "recovery_required":
		return "repairable"
	case "configured", "configured_client_missing", "configured_unverified", "config_present":
		return "configured"
	default:
		if state == "" {
			return "absent"
		}
		return state
	}
}

func runSetupRepairCmd(args []string, stdout, stderr io.Writer) int {
	if isHelpRequest(args) {
		printSetupInspectUsage(stdout, "repair", true)
		return 0
	}
	opts, code := parseSetupInspectArgs("setup repair", args, stderr, true)
	if code != 0 {
		return code
	}
	if opts.DryRun {
		opts.Operation = "preview_repair"
	} else {
		opts.Operation = "repair"
	}
	if !opts.Yes && !opts.DryRun {
		fmt.Fprintln(stderr, "setup repair: pass --yes to repair HELM-owned config, or --dry-run to preview changes")
		return 2
	}
	marker, recoveryPending, err := readSetupRecoveryMarker(opts)
	if err != nil {
		fmt.Fprintf(stderr, "setup repair: recovery marker: %v\n", err)
		return 2
	}
	if recoveryPending {
		if !marker.matches(opts) {
			fmt.Fprintf(stderr, "setup repair: recovery marker belongs to a different setup; run `%s`\n", setupRecoveryCommand(marker.options(opts)))
			return 2
		}
		opts, err = applySetupRecoveryMarker(opts, marker)
		if err != nil {
			fmt.Fprintf(stderr, "setup repair: recovery marker: %v\n", err)
			return 2
		}
	}
	summary, err := buildSetupSummary(opts)
	if err != nil {
		fmt.Fprintf(stderr, "setup repair: %v\n", err)
		return 2
	}
	if !opts.PolicyProfileSet {
		if err := discoverSetupStatusPolicyProfile(&opts, summary.HookConfigPath, summary.BinaryPath); err != nil {
			fmt.Fprintf(stderr, "setup repair: policy profile: %v\n", err)
			return 2
		}
	}
	if err := populateSetupPolicyProfileDigest(&opts); err != nil {
		fmt.Fprintf(stderr, "setup repair: policy profile: %v\n", err)
		return 2
	}
	if err := preflightSetup(opts, &summary); err != nil {
		fmt.Fprintf(stderr, "setup repair: %v\n", err)
		return 1
	}
	summary.MCPInstalled = setupMCPInstalled(opts, summary.ClientConfigPath, summary.BinaryPath)
	summary.HookInstalled = setupHookInstalled(opts, summary.HookConfigPath, summary.BinaryPath)
	summary.RecoveryRequired = recoveryPending
	summary.PlannedActions = setupRepairActions(summary)
	if opts.DryRun {
		printSetupSummary(stdout, summary, opts.JSON)
		return 0
	}
	printSetupPlan(stderr, summary)
	if recoveryPending {
		if err := provisionSetupLocalState(opts, &summary); err != nil {
			return reportSetupRecovery(stderr, opts, err)
		}
	}
	if !summary.MCPInstalled && setupIncludesMCP(opts.Target) {
		if err := setupInstallMCP(opts, summary.BinaryPath); err != nil {
			if recoveryPending {
				return reportSetupRecovery(stderr, opts, fmt.Errorf("install MCP server: %w", err))
			}
			fmt.Fprintf(stderr, "setup repair: install MCP server: %v\n", err)
			return 1
		}
		summary.MCPInstalled = true
	}
	if !summary.HookInstalled {
		if err := setupInstallHook(opts, summary.BinaryPath); err != nil {
			if recoveryPending {
				return reportSetupRecovery(stderr, opts, fmt.Errorf("install pre-tool hook: %w", err))
			}
			fmt.Fprintf(stderr, "setup repair: install pre-tool hook: %v\n", err)
			return 1
		}
		summary.HookInstalled = true
	}
	if recoveryPending {
		if err := clearSetupRecovery(opts); err != nil {
			return reportSetupRecovery(stderr, opts, fmt.Errorf("clear recovery marker: %w", err))
		}
		summary.RecoveryRequired = false
	}
	observeSetupClientState(opts, &summary)
	printSetupSummary(stdout, summary, opts.JSON)
	return 0
}

func runSetupRemoveCmd(args []string, stdout, stderr io.Writer) int {
	if isHelpRequest(args) {
		printSetupInspectUsage(stdout, "remove", true)
		return 0
	}
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
	if !opts.PolicyProfileSet {
		if err := discoverSetupStatusPolicyProfile(&opts, summary.HookConfigPath, summary.BinaryPath); err != nil {
			fmt.Fprintf(stderr, "setup remove: policy profile: %v\n", err)
			return 2
		}
	}
	if err := populateSetupPolicyProfileDigest(&opts); err != nil {
		fmt.Fprintf(stderr, "setup remove: policy profile: %v\n", err)
		return 2
	}
	summary, err = buildSetupSummary(opts)
	if err != nil {
		fmt.Fprintf(stderr, "setup remove: %v\n", err)
		return 2
	}
	summary.MCPInstalled = setupMCPInstalled(opts, summary.ClientConfigPath, summary.BinaryPath)
	summary.HookInstalled = setupHookInstalled(opts, summary.HookConfigPath, summary.BinaryPath)
	summary.PlannedActions = setupRemoveActions(summary)
	summary.RetainedData = true
	if !opts.DryRun {
		printSetupPlan(stderr, summary)
		// Remove the MCP entry before the hook. If the client command cannot
		// remove an owned MCP entry, the hook remains in place and the setup is
		// still repairable rather than silently half-removed.
		if summary.MCPInstalled {
			if err := removeSetupMCP(opts); err != nil {
				fmt.Fprintf(stderr, "setup remove: remove MCP server: %v\n", err)
				return 1
			}
			summary.MCPInstalled = false
		}
		if summary.HookInstalled {
			if err := removeSetupHook(opts, summary.BinaryPath); err != nil {
				fmt.Fprintf(stderr, "setup remove: remove hook: %v\n", err)
				return 1
			}
			summary.HookInstalled = false
		}
	}
	if opts.DryRun {
		summary.ClientState = "planned_removal"
	} else {
		summary.ClientState = "removed"
	}
	printSetupSummary(stdout, summary, opts.JSON)
	return 0
}

func setupStatusHealthy(summary setupSummary) bool {
	if !summary.HookInstalled || !summary.ClientDetected || !summary.NativeLoaded || summary.CodexTrustPending || summary.HookMatcherOutdated {
		return false
	}
	if setupIncludesMCP(summary.Target) && !summary.MCPInstalled {
		return false
	}
	return true
}

func setupRepairActions(summary setupSummary) []string {
	actions := make([]string, 0, 3)
	if summary.RecoveryRequired {
		actions = append(actions, "resume the incomplete HELM setup")
	}
	if !summary.MCPInstalled && setupIncludesMCP(summary.Target) {
		actions = append(actions, "configure the HELM MCP server in "+summary.ClientConfigPath)
	}
	if !summary.HookInstalled {
		actions = append(actions, setupHookInstallAction(summary.Target, summary.HookConfigPath))
		if action := setupProfileInstallAction(summary.Target, summary.ClientConfigPath); action != "" {
			actions = append(actions, action)
		}
	}
	return actions
}

func setupRecoveryMarkerPath(opts setupOptions) string {
	return filepath.Join(opts.DataDir, setupRecoveryMarkerName)
}

func (marker setupRecoveryMarker) matches(opts setupOptions) bool {
	if marker.Target != opts.Target || marker.Scope != opts.Scope {
		return false
	}
	return opts.Scope != "project" || marker.Workspace == opts.Workspace
}

func (marker setupRecoveryMarker) options(opts setupOptions) setupOptions {
	opts.Target = marker.Target
	opts.Scope = marker.Scope
	opts.Workspace = marker.Workspace
	opts.SigningSeedFile = marker.SigningSeedFile
	opts.PolicyProfile = marker.PolicyProfile
	// The marker is the source of truth for a resumed setup, including an
	// intentionally empty policy profile. Do not inspect a half-written hook
	// and accidentally replace the original choice while recovering.
	opts.PolicyProfileSet = true
	return opts
}

func applySetupRecoveryMarker(opts setupOptions, marker setupRecoveryMarker) (setupOptions, error) {
	if !marker.matches(opts) {
		return opts, errors.New("marker does not match this target, scope, and workspace")
	}
	if opts.SigningSeedFile != "" && opts.SigningSeedFile != marker.SigningSeedFile {
		return opts, errors.New("--signing-seed-file differs from the interrupted setup")
	}
	if opts.PolicyProfile != "" && opts.PolicyProfile != marker.PolicyProfile {
		return opts, errors.New("--policy-profile differs from the interrupted setup")
	}
	return marker.options(opts), nil
}

func readSetupRecoveryMarker(opts setupOptions) (setupRecoveryMarker, bool, error) {
	path := setupRecoveryMarkerPath(opts)
	raw, err := readRegularFile(path, "setup recovery marker")
	if os.IsNotExist(err) {
		return setupRecoveryMarker{}, false, nil
	}
	if err != nil {
		return setupRecoveryMarker{}, false, err
	}
	var marker setupRecoveryMarker
	if err := json.Unmarshal(raw, &marker); err != nil {
		return setupRecoveryMarker{}, false, fmt.Errorf("parse %q: %w", path, err)
	}
	target, targetErr := normalizeSetupTarget(marker.Target)
	if marker.Version != 1 || targetErr != nil || target != marker.Target || (marker.Scope != "user" && marker.Scope != "project") || !filepath.IsAbs(marker.Workspace) {
		return setupRecoveryMarker{}, false, fmt.Errorf("invalid %q", path)
	}
	return marker, true, nil
}

func beginSetupRecovery(opts setupOptions) error {
	marker, pending, err := readSetupRecoveryMarker(opts)
	if err != nil {
		return err
	}
	if pending {
		return fmt.Errorf("an earlier setup still needs recovery; run `%s`", setupRecoveryCommand(marker.options(opts)))
	}
	data, err := json.Marshal(setupRecoveryMarker{
		Version:         1,
		Target:          opts.Target,
		Scope:           opts.Scope,
		Workspace:       opts.Workspace,
		SigningSeedFile: opts.SigningSeedFile,
		PolicyProfile:   opts.PolicyProfile,
	})
	if err != nil {
		return err
	}
	return writePrivateFileAtomic(setupRecoveryMarkerPath(opts), append(data, '\n'), opts.DataDir)
}

func clearSetupRecovery(opts setupOptions) error {
	path, err := privateFileWritePath(setupRecoveryMarkerPath(opts), opts.DataDir)
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func reportSetupRecovery(stderr io.Writer, opts setupOptions, err error) int {
	fmt.Fprintf(stderr, "setup: %v\n", err)
	fmt.Fprintf(stderr, "setup: recovery required; run `%s`\n", setupRecoveryCommand(opts))
	return 1
}

func setupRemoveActions(summary setupSummary) []string {
	actions := make([]string, 0, 2)
	if summary.MCPInstalled {
		actions = append(actions, "remove the HELM MCP server from "+summary.ClientConfigPath)
	}
	if summary.HookInstalled {
		switch summary.Target {
		case "hermes":
			actions = append(actions, "remove the fail-closed Hermes pre_tool_call hook from "+summary.HookConfigPath)
		case "deepseek":
			actions = append(actions, "remove the fail-closed DeepSeek PreToolUse hook from "+summary.HookConfigPath)
		default:
			actions = append(actions, "remove the HELM PreToolUse hook from "+summary.HookConfigPath)
		}
		if action := setupProfileRemoveAction(summary.Target, summary.ClientConfigPath); action != "" {
			actions = append(actions, action)
		}
	}
	return actions
}

func observeSetupClientState(opts setupOptions, summary *setupSummary) {
	summary.ClientDetected = false
	summary.NativeLoaded = false
	if !summary.HookInstalled && !summary.MCPInstalled {
		summary.ClientState = "absent"
		return
	}
	if !summary.HookInstalled || (setupIncludesMCP(opts.Target) && !summary.MCPInstalled) {
		summary.ClientState = "degraded"
		return
	}
	if opts.Target == "codex" && opts.Scope == "project" && codexProjectTrustPending(opts.Workspace) {
		summary.CodexTrustPending = true
		summary.ClientState = "trust_pending"
		return
	}
	if _, err := setupFindClient(opts.Target); err != nil {
		summary.ClientState = "configured_client_missing"
		return
	}
	summary.ClientDetected = true
	// Codex's native `mcp get` command reads the user-level registry, so it
	// cannot prove that a project-local config is loaded. Keep this state
	// deliberately conservative instead of borrowing a global success signal.
	if opts.Target == "codex" && opts.Scope == "project" {
		summary.ClientState = "configured_unverified"
		return
	}
	// Hermes has no `mcp get` probe that proves the YAML gate is loaded.
	if opts.Target == "hermes" {
		summary.ClientState = "configured_unverified"
		return
	}
	// DeepSeek Harness has no probe that proves the profile configPath is loaded.
	if opts.Target == "deepseek" {
		summary.ClientState = "configured_unverified"
		return
	}
	if err := setupProbeClient(opts.Target, setupCommandDir(opts)); err != nil {
		summary.ClientState = "configured_unverified"
		return
	}
	summary.NativeLoaded = true
	summary.ClientState = "native_loaded"
	assignSetupLifecycle(summary)
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
