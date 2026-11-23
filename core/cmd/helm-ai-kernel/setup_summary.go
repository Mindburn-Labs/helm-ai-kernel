package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/internal/cli/ui"
	lpcmd "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/launchpad/cmd"
)

type setupSummary struct {
	Operation        string `json:"operation"`
	Target           string `json:"target"`
	Workspace        string `json:"workspace"`
	BinaryPath       string `json:"binary_path"`
	ClientBinaryPath string `json:"client_binary_path,omitempty"`
	ClientConfigPath string `json:"client_config_path"`
	HookConfigPath   string `json:"hook_config_path"`
	DataDir          string `json:"data_dir"`
	KernelURL        string `json:"kernel_url"`
	ScanGrade        string `json:"scan_grade"`
	DraftPolicyPath  string `json:"draft_policy_path"`
	UninstallCommand string `json:"uninstall_command"`
	RecoveryCommand  string `json:"recovery_command"`
	Scope            string `json:"scope,omitempty"`
	// MCPInstalled and HookInstalled mean HELM's exact configuration is
	// present on disk. They do not claim the client has loaded it.
	MCPInstalled   bool   `json:"mcp_installed,omitempty"`
	HookInstalled  bool   `json:"hook_installed,omitempty"`
	ClientDetected bool   `json:"client_detected"`
	NativeLoaded   bool   `json:"native_loaded"`
	ClientState    string `json:"client_state,omitempty"`
	// Lifecycle is the coarse operator model: absent|planned|configured|pending|active|degraded|repairable.
	// It is a projection of ClientState. native_loaded is the only active claim.
	Lifecycle string `json:"lifecycle,omitempty"`
	// CodexTrustPending is true when a project-scoped Codex config is written
	// but the workspace is not recorded as trusted in ~/.codex/config.toml.
	// Codex ignores project-scoped config until trust is granted, so the
	// integration is written-but-not-yet-loaded; reporting it as installed
	// without this flag would be a false positive.
	CodexTrustPending bool     `json:"codex_trust_pending,omitempty"`
	QuickstartStarted bool     `json:"quickstart_started"`
	PlannedActions    []string `json:"planned_actions"`
	RetainedData      bool     `json:"retained_data,omitempty"`
	RecoveryRequired  bool     `json:"recovery_required,omitempty"`
	// HookMatcher is the matcher of the installed hook entry, and
	// HookMatcherExpected the one this release installs. The matcher is
	// outdated when it does not route a tool this release routes to the
	// hook; HookMatcherMissingTools names them.
	// HookMatchers lists the matcher of every entry that holds the HELM
	// hook, HookMatcher being the first; a tool reaches the hook when any of
	// them routes it. HookMatcherUpgradeCommand is the setup command that
	// upgrades this install.
	HookMatcher               string   `json:"hook_matcher,omitempty"`
	HookMatchers              []string `json:"hook_matchers,omitempty"`
	HookMatcherExpected       string   `json:"hook_matcher_expected,omitempty"`
	HookMatcherOutdated       bool     `json:"hook_matcher_outdated,omitempty"`
	HookMatcherMissingTools   []string `json:"hook_matcher_missing_tools,omitempty"`
	HookMatcherUpgradeCommand string   `json:"hook_matcher_upgrade_command,omitempty"`
	// Warnings are what setup could not do for the user, such as a shared
	// hook entry whose matcher it left alone.
	Warnings []string `json:"warnings,omitempty"`
}

// renderSetupOutcome writes the resolved timeline and a completion card to the
// chrome stream. It replaces the old `mcp=true hook=true` line with a step
// transcript that shows the resolved state of every action — the property the
// setup path borrowed the vocabulary of (a [WAIT] preview) without ever
// delivering.
func renderSetupOutcome(chrome io.Writer, caps ui.Capabilities, summary setupSummary, steps []ui.Step, applyErr error) {
	r := ui.NewRenderer(chrome, caps)
	r.WriteTimeline("HELM setup", steps)
	if applyErr != nil {
		r.WriteCompletion(ui.CompletionCard{
			Title:      "Setup did not complete",
			Fields:     []ui.KeyValue{{Key: "Failed at", Value: firstFailedStepTitle(steps)}, {Key: "Left in place", Value: describeSetupResidue(steps)}},
			NextAction: summary.RecoveryCommand,
		})
		return
	}
	r.WriteCompletion(ui.CompletionCard{
		Title:      "Setup complete",
		Fields:     setupOutcomeFields(summary),
		NextAction: setupNextAction(summary),
	})
}

func firstFailedStepTitle(steps []ui.Step) string {
	for _, s := range steps {
		if s.Status == ui.StatusFail {
			return s.Title
		}
	}
	return "unknown"
}

// describeSetupResidue names which surfaces were written before the failure, so
// the user is never left guessing what half-configured state remains — the
// exact gap the audit flagged (an MCP boundary present with the hook absent is
// the dangerous half of a fail-closed firewall).
func describeSetupResidue(steps []ui.Step) string {
	var written []string
	for _, s := range steps {
		if s.Status != ui.StatusPass {
			continue
		}
		switch {
		case strings.Contains(s.Title, "MCP server"):
			written = append(written, "MCP server config")
		case strings.Contains(s.Title, "hook"):
			written = append(written, "hook")
		case strings.Contains(s.Title, "signing key"):
			written = append(written, "local signing key and draft artifacts")
		}
	}
	if len(written) == 0 {
		return "nothing written"
	}
	return strings.Join(written, ", ") + " (governance is NOT fully active until repair completes)"
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
		RecoveryCommand:   setupRecoveryCommand(opts),
		Scope:             opts.Scope,
		QuickstartStarted: false,
		PlannedActions:    setupPlannedActions(opts),
	}, nil
}

func setupPlannedActions(opts setupOptions) []string {
	switch opts.Operation {
	case "preview":
		return setupInstallActions(opts)
	default:
		return []string{}
	}
}

func setupHookInstallAction(target, path string) string {
	switch target {
	case "hermes":
		return "configure the fail-closed Hermes pre_tool_call hook in " + path
	case "deepseek":
		return "configure the fail-closed DeepSeek PreToolUse hook in " + path
	default:
		return "configure the HELM PreToolUse hook in " + path
	}
}

func setupProfileInstallAction(target, path string) string {
	if target == "deepseek" {
		return "point the DSH profile configPath at the hook file in " + path
	}
	return ""
}

func setupProfileRemoveAction(target, path string) string {
	if target == "deepseek" {
		return "remove the DSH profile configPath from " + path
	}
	return ""
}

func setupConfirmationDetails(summary setupSummary) []ui.KeyValue {
	details := []ui.KeyValue{
		{Key: "Scope", Value: summary.Scope},
		{Key: "Workspace", Value: summary.Workspace},
	}
	if setupIncludesMCP(summary.Target) {
		details = append(details, ui.KeyValue{Key: "MCP config", Value: summary.ClientConfigPath})
	} else if summary.Target == "deepseek" {
		details = append(details, ui.KeyValue{Key: "DSH profile", Value: summary.ClientConfigPath})
	}
	details = append(details,
		ui.KeyValue{Key: "Hook config", Value: summary.HookConfigPath},
		ui.KeyValue{Key: "Data dir", Value: summary.DataDir},
		ui.KeyValue{Key: "Recovery", Value: summary.RecoveryCommand},
	)
	return details
}

func setupOutcomeFields(summary setupSummary) []ui.KeyValue {
	fields := []ui.KeyValue{
		{Key: "Client", Value: summary.Target},
		{Key: "Scope", Value: summary.Scope},
	}
	if setupIncludesMCP(summary.Target) {
		fields = append(fields, ui.KeyValue{Key: "MCP server", Value: summary.ClientConfigPath})
	}
	hookKey := "PreToolUse hook"
	switch summary.Target {
	case "hermes":
		hookKey = "pre_tool_call hook"
	case "deepseek":
		hookKey = "PreToolUse hook"
	}
	return append(fields,
		ui.KeyValue{Key: hookKey, Value: summary.HookConfigPath},
		ui.KeyValue{Key: "Data dir", Value: summary.DataDir},
	)
}

func setupNextAction(summary setupSummary) string {
	if summary.CodexTrustPending {
		return "trust this workspace in Codex, then restart it — governance is not active until then"
	}
	if summary.Target == "hermes" {
		return "accept the Hermes first-use hook allowlist (--accept-hooks, HERMES_ACCEPT_HOOKS, or hooks_auto_accept), then restart Hermes. Non-TTY sessions never register the hook without that consent. This does not mean DENY is visible in the Hermes UI."
	}
	if summary.Target == "deepseek" {
		return "keep the stock dsh-hooks-claude-code configPath pointed at the Kernel hook file, then restart DeepSeek Harness. A missing configPath leaves the hook file dead. This is an adapter hop, not a HELM-native agent runtime. This does not mean `npx @deepseek-ai/dsh web` sees DENY."
	}
	return "restart " + summary.Target + " to activate governance"
}

func printSetupPlan(w io.Writer, summary setupSummary) {
	actions := summary.PlannedActions
	if len(actions) == 0 {
		switch summary.Operation {
		case "install":
			actions = []string{
				"create or reuse local HELM state under " + summary.DataDir,
			}
			if setupIncludesMCP(summary.Target) {
				actions = append(actions, "configure the HELM MCP server in "+summary.ClientConfigPath)
			}
			actions = append(actions, setupHookInstallAction(summary.Target, summary.HookConfigPath))
			if action := setupProfileInstallAction(summary.Target, summary.ClientConfigPath); action != "" {
				actions = append(actions, action)
			}
		case "repair", "remove":
			actions = []string{"no HELM-owned configuration changes are needed"}
		}
	}
	fmt.Fprintln(w, "Planned changes:")
	fmt.Fprintf(w, "  Client binary: %s\n", summary.ClientBinaryPath)
	for _, action := range actions {
		fmt.Fprintf(w, "  - %s\n", action)
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
	policyProfile := ""
	if strings.TrimSpace(opts.PolicyProfile) != "" {
		policyProfile = " --policy-profile " + shellQuote(opts.PolicyProfile)
	}
	return fmt.Sprintf(
		"helm-ai-kernel setup remove %s --scope %s%s --yes --data-dir %s%s%s",
		opts.Target,
		opts.Scope,
		workspace,
		shellQuote(opts.DataDir),
		signingSeedFile,
		policyProfile,
	)
}

// setupUpgradeCommand is the setup command that installs this release's hook
// over the install opts describes, with the same scope, workspace, data
// directory and policy profile.
func setupUpgradeCommand(opts setupOptions) string {
	workspace := ""
	if opts.Scope == "project" {
		workspace = " --workspace " + shellQuote(opts.Workspace)
	}
	signingSeedFile := ""
	if strings.TrimSpace(opts.SigningSeedFile) != "" {
		signingSeedFile = " --signing-seed-file " + shellQuote(opts.SigningSeedFile)
	}
	policyProfile := ""
	if strings.TrimSpace(opts.PolicyProfile) != "" {
		policyProfile = " --policy-profile " + shellQuote(opts.PolicyProfile)
	}
	return fmt.Sprintf(
		"helm-ai-kernel setup %s --scope %s%s --yes --data-dir %s%s%s",
		opts.Target,
		opts.Scope,
		workspace,
		shellQuote(opts.DataDir),
		signingSeedFile,
		policyProfile,
	)
}

func setupRecoveryCommand(opts setupOptions) string {
	return setupRepairCommand(opts, "--yes")
}

func setupRepairCommand(opts setupOptions, confirmation string) string {
	workspace := ""
	if opts.Scope == "project" {
		workspace = " --workspace " + shellQuote(opts.Workspace)
	}
	signingSeedFile := ""
	if strings.TrimSpace(opts.SigningSeedFile) != "" {
		signingSeedFile = " --signing-seed-file " + shellQuote(opts.SigningSeedFile)
	}
	policyProfile := ""
	if strings.TrimSpace(opts.PolicyProfile) != "" {
		policyProfile = " --policy-profile " + shellQuote(opts.PolicyProfile)
	}
	return fmt.Sprintf(
		"helm-ai-kernel setup repair %s --scope %s%s %s --data-dir %s%s%s",
		opts.Target,
		opts.Scope,
		workspace,
		confirmation,
		shellQuote(opts.DataDir),
		signingSeedFile,
		policyProfile,
	)
}

func printSetupSummary(stdout io.Writer, summary setupSummary, jsonOut bool) {
	assignSetupLifecycle(&summary)
	if jsonOut {
		_ = json.NewEncoder(stdout).Encode(summary)
		return
	}
	fmt.Fprintf(stdout, "HELM setup for %s\n", summary.Target)
	fmt.Fprintf(stdout, "  Workspace:     %s\n", summary.Workspace)
	if setupIncludesMCP(summary.Target) {
		fmt.Fprintf(stdout, "  MCP config:    %s\n", summary.ClientConfigPath)
	} else if summary.Target == "deepseek" {
		fmt.Fprintf(stdout, "  DSH profile:   %s\n", summary.ClientConfigPath)
	} else {
		fmt.Fprintf(stdout, "  Hermes config: %s\n", summary.HookConfigPath)
	}
	fmt.Fprintf(stdout, "  Hook config:   %s\n", summary.HookConfigPath)
	fmt.Fprintf(stdout, "  Data dir:      %s\n", summary.DataDir)
	if summary.KernelURL != "" {
		fmt.Fprintf(stdout, "  Kernel:        %s\n", summary.KernelURL)
	}
	fmt.Fprintf(stdout, "  Scan grade:    %s\n", summary.ScanGrade)
	fmt.Fprintf(stdout, "  Draft policy:  %s\n", summary.DraftPolicyPath)
	fmt.Fprintf(stdout, "  Recovery:      %s\n", summary.RecoveryCommand)
	fmt.Fprintf(stdout, "  Uninstall:     %s\n", summary.UninstallCommand)
	if len(summary.PlannedActions) > 0 {
		fmt.Fprintln(stdout, "  Planned:")
		for _, action := range summary.PlannedActions {
			fmt.Fprintf(stdout, "    - %s\n", action)
		}
	}
	if summary.MCPInstalled || summary.HookInstalled {
		fmt.Fprintf(stdout, "  Configured:    mcp=%v hook=%v\n", summary.MCPInstalled, summary.HookInstalled)
	}
	if summary.ClientState != "" {
		fmt.Fprintf(stdout, "  Client state:  %s (lifecycle=%s detected=%v native_loaded=%v)\n", summary.ClientState, summary.Lifecycle, summary.ClientDetected, summary.NativeLoaded)
	}
	if summary.HookMatcherOutdated {
		fix := "Run " + summary.HookMatcherUpgradeCommand + " to upgrade it."
		if summary.HookMatcherUpgradeCommand == "" {
			fix = "setup does not rewrite an entry it shares with other hooks; edit it as the warning says."
		}
		fmt.Fprintf(stdout, "  Hook matcher:  outdated: %s does not route %s; this release installs %s. %s\n",
			strings.Join(summary.HookMatchers, " and "), strings.Join(summary.HookMatcherMissingTools, ", "), summary.HookMatcherExpected, fix)
	}
	for _, warning := range summary.Warnings {
		fmt.Fprintf(stdout, "  Warning:       %s\n", warning)
	}
	if summary.CodexTrustPending {
		fmt.Fprintf(stdout, "  Codex trust:   PENDING — Codex will ignore this project config until you trust the workspace (run `codex` in %s and approve it, or set trust_level=\"trusted\" in ~/.codex/config.toml). Governance is not active until then.\n", summary.Workspace)
	}
	if summary.RecoveryRequired {
		fmt.Fprintf(stdout, "  Next:          recovery required; run %s\n", summary.RecoveryCommand)
	} else if summary.MCPInstalled || summary.HookInstalled {
		// A healthy install's next step is to restart the client, not to run
		// repair. Printing the repair command after every success — including a
		// clean install and a removal preview — trained users to treat repair
		// as routine and gave the lifecycle no terminal "you're done" state.
		fmt.Fprintf(stdout, "  Next:          %s\n", setupNextAction(summary))
	}
	if summary.RetainedData {
		fmt.Fprintln(stdout, "  Local state:   retained (keys, evidence, and receipts were not removed)")
	}
}
