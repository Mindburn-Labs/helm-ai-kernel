// quantum_posture: setup provisions the classical Ed25519 workstation
// signing seed through the resolver in workstation_signing.go.

package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/internal/cli/ui"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/shadow"
)

func confirmSetupInstall(input io.Reader, chrome io.Writer, caps ui.Capabilities, summary setupSummary, actions []string, apply func() error) error {
	renderer := ui.NewRenderer(chrome, caps)
	// State intent before asking for anything. The old preface named only the
	// scope; a user was asked to approve an install without being told what it
	// would do. Enumerate the actions first, the way a person would want them
	// explained before consenting.
	fmt.Fprintf(chrome, "HELM setup will configure %s at %s scope for %s. It will:\n", summary.Target, summary.Scope, summary.Workspace)
	steps := make([]ui.Step, 0, len(actions))
	for _, action := range actions {
		steps = append(steps, ui.Step{Status: ui.StatusWait, Title: action})
	}
	renderer.WriteTimeline("HELM setup preview", steps)
	return renderer.ConfirmDecision(input, ui.DecisionContext{
		Action:  ui.DecisionApprove,
		Subject: "setup " + summary.Target,
		Summary: "Write only the scoped local HELM configuration below.",
		Details: setupConfirmationDetails(summary),
	}, apply)
}

// applySetupSteps runs the install operations in order and records the state of
// each as a timeline step. It stops at the first failure and marks the
// remaining steps as not attempted — a fail-closed governance install must not
// keep going after a prerequisite fails (a hook installed on top of a failed
// key provision would be worse than a clean abort), but the user is still shown
// which steps ran, which failed, and which were skipped. The returned error is
// nil only when every step passed.
func applySetupSteps(opts setupOptions, summary *setupSummary) ([]ui.Step, error) {
	type setupStep struct {
		title string
		run   func() error
		wrap  string
	}
	plan := []setupStep{
		{"provision the local signing key and draft policy artifacts", func() error { return provisionSetupLocalState(opts, summary) }, ""},
	}
	if setupIncludesMCP(opts.Target) {
		plan = append(plan, setupStep{
			"configure the HELM MCP server in " + summary.ClientConfigPath,
			func() error { return setupInstallMCP(opts, summary.BinaryPath) },
			"install MCP server",
		})
	}
	plan = append(plan,
		setupStep{
			setupHookInstallAction(opts.Target, summary.HookConfigPath),
			func() error { return setupInstallHook(opts, summary.BinaryPath) },
			"install pre-tool hook",
		},
		setupStep{"clear the recovery marker", func() error { return clearSetupRecovery(opts) }, "clear recovery marker"},
	)
	steps := make([]ui.Step, len(plan))
	var applyErr error
	failed := -1
	for i, s := range plan {
		if failed >= 0 {
			steps[i] = ui.Step{Status: ui.StatusWait, Title: s.title, Detail: "not attempted"}
			continue
		}
		if err := s.run(); err != nil {
			steps[i] = ui.Step{Status: ui.StatusFail, Title: s.title, Detail: err.Error()}
			failed = i
			// Wrap with the same context the previous per-call errors carried,
			// so recovery reporting reads identically to before this refactor.
			if s.wrap != "" {
				applyErr = fmt.Errorf("%s: %w", s.wrap, err)
			} else {
				applyErr = err
			}
			continue
		}
		steps[i] = ui.Step{Status: ui.StatusPass, Title: s.title}
	}
	return steps, applyErr
}

func runSetupInstallCmd(args []string, stdout, stderr io.Writer) int {
	input, caps := setupTerminalSession(stderr)
	return runSetupInstallCmdWithInput(args, stdout, stderr, bufio.NewReader(input), caps)
}

func runSetupInstallCmdWithInput(args []string, stdout, stderr io.Writer, input io.Reader, caps ui.Capabilities) int {
	if isHelpRequest(args) {
		printSetupInstallUsage(stdout)
		return 0
	}
	opts, code := parseSetupInstallArgs(args, stderr)
	if code != 0 {
		return code
	}
	if err := populateSetupPolicyProfileDigest(&opts); err != nil {
		fmt.Fprintf(stderr, "setup: policy profile: %v\n", err)
		return 2
	}
	if opts.DryRun {
		opts.Operation = "preview"
	} else {
		opts.Operation = "install"
	}
	if !opts.Yes && !opts.DryRun && (!caps.Interactive || opts.JSON) {
		fmt.Fprintln(stderr, "setup: pass --yes to install local config, or --dry-run to preview changes")
		return 2
	}
	summary, err := buildSetupSummary(opts)
	if err != nil {
		fmt.Fprintf(stderr, "setup: %v\n", err)
		return 2
	}
	if err := preflightSetup(opts, &summary); err != nil {
		fmt.Fprintf(stderr, "setup: %v\n", err)
		return 1
	}
	if opts.DryRun {
		printSetupSummary(stdout, summary, opts.JSON)
		return 0
	}
	if !opts.Yes {
		confirmed := false
		if err := confirmSetupInstall(input, stderr, caps, summary, setupInstallActions(opts), func() error {
			confirmed = true
			return nil
		}); err != nil {
			switch {
			case errors.Is(err, ui.ErrConfirmationRequired):
				fmt.Fprintln(stderr, "setup: no changes made; rerun and type APPROVE to confirm")
			case errors.Is(err, ui.ErrNonInteractive):
				fmt.Fprintln(stderr, "setup: this terminal cannot accept confirmation; use --dry-run or --yes")
			default:
				fmt.Fprintf(stderr, "setup: confirmation: %v\n", err)
			}
			return 2
		}
		if !confirmed {
			fmt.Fprintln(stderr, "setup: no changes made; confirmation is required")
			return 2
		}
	}
	printSetupPlan(stderr, summary)
	if err := os.MkdirAll(opts.DataDir, 0o750); err != nil {
		fmt.Fprintf(stderr, "setup: create data dir: %v\n", err)
		return 1
	}
	if err := beginSetupRecovery(opts); err != nil {
		fmt.Fprintf(stderr, "setup: recovery marker: %v\n", err)
		return 1
	}
	steps, applyErr := applySetupSteps(opts, &summary)
	if !opts.JSON {
		renderSetupOutcome(stderr, caps, summary, steps, applyErr)
	}
	if applyErr != nil {
		compensateFailedSetupApply(opts, steps)
		return reportSetupRecovery(stderr, opts, applyErr)
	}
	summary.MCPInstalled = setupIncludesMCP(opts.Target)
	summary.HookInstalled = true
	summary.ClientDetected = true
	summary.ClientState = "configured"
	summary.Warnings = setupSharedHookEntryWarnings(opts, summary.HookConfigPath, summary.BinaryPath)
	for _, warning := range summary.Warnings {
		fmt.Fprintf(stderr, "setup: warning: %s\n", warning)
	}
	if opts.Target == "codex" && opts.Scope == "project" {
		summary.CodexTrustPending = codexProjectTrustPending(opts.Workspace)
		if summary.CodexTrustPending {
			summary.ClientState = "trust_pending"
		}
	}
	if opts.NoQuickstart {
		printSetupSummary(stdout, summary, opts.JSON)
		return 0
	}
	if !opts.JSON {
		fmt.Fprintln(stdout)
		fmt.Fprintln(stdout, "Leave this terminal open. HELM is starting the local Kernel proof path now.")
	}
	quickstartArgs := setupQuickstartArgs(setupQuickstartProfile(opts.Target), filepath.Join(opts.DataDir, "quickstart"), opts.Console, opts.ConsolePort, opts.NoOpen, false, false, false)
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

func compensateFailedSetupApply(opts setupOptions, steps []ui.Step) {
	mcpPassed, hookFailed := false, false
	for _, step := range steps {
		if strings.Contains(step.Title, "MCP") && step.Status == ui.StatusPass {
			mcpPassed = true
		}
		if strings.Contains(strings.ToLower(step.Title), "hook") && step.Status == ui.StatusFail {
			hookFailed = true
		}
	}
	if mcpPassed && hookFailed {
		_ = setupCompensateMCP(opts)
	}
}

func setupInstallActions(opts setupOptions) []string {
	actions := []string{
		"create or reuse the local receipt signing key under " + filepath.Join(opts.DataDir, workstationSigningKeyDirectory),
		"write draft-only inventory and policy artifacts under " + filepath.Join(opts.DataDir, "autoconfigure"),
	}
	if setupIncludesMCP(opts.Target) {
		actions = append(actions, "configure the HELM MCP server in "+setupClientConfigPath(opts))
	}
	actions = append(actions, setupHookInstallAction(opts.Target, setupHookConfigPath(opts)))
	if action := setupProfileInstallAction(opts.Target, setupClientConfigPath(opts)); action != "" {
		actions = append(actions, action)
	}
	if !opts.NoQuickstart {
		action := "start the local Quickstart proof path"
		if opts.Console {
			action += " with the packaged local Console"
		}
		actions = append(actions, action)
	}
	return actions
}

func provisionSetupLocalState(opts setupOptions, summary *setupSummary) error {
	if err := os.MkdirAll(opts.DataDir, 0o750); err != nil {
		return fmt.Errorf("create data dir: %w", err)
	}
	if _, err := setupResolveSigningSeed(opts.DataDir, "", opts.SigningSeedFile); err != nil {
		return fmt.Errorf("provision local receipt signing key: %w", err)
	}
	grade, policyPath, err := setupRunAutoconfigure(opts.DataDir, opts.Workspace)
	if err != nil {
		return fmt.Errorf("autoconfigure: %w", err)
	}
	summary.ScanGrade = grade
	summary.DraftPolicyPath = policyPath
	return nil
}

func preflightSetup(opts setupOptions, summary *setupSummary) error {
	if err := preflightSetupDataDir(opts.DataDir); err != nil {
		return err
	}
	client, err := setupFindClient(opts.Target)
	if err != nil && !opts.DryRun {
		return fmt.Errorf("%s client is not available on PATH; install %q and retry", opts.Target, setupClientCommand(opts.Target))
	}
	// A preview needs no client executable. Keep validating the configuration
	// and signing material below, and report that the client was not detected.
	summary.ClientBinaryPath = client
	summary.ClientDetected = err == nil
	if summary.ClientState == "" {
		summary.ClientState = "planned"
	}
	if err := preflightWorkstationSigningSeed(opts.DataDir, "", opts.SigningSeedFile); err != nil {
		return fmt.Errorf("validate local receipt signing key: %w", err)
	}
	if err := preflightSetupClientConfig(opts); err != nil {
		return err
	}
	if err := preflightSetupHookConfig(opts); err != nil {
		return err
	}
	return nil
}

func preflightSetupDataDir(dataDir string) error {
	info, err := os.Lstat(dataDir)
	if err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return fmt.Errorf("data directory %q must be a directory, not a symlink or special file", dataDir)
		}
		return nil
	}
	if !os.IsNotExist(err) {
		return fmt.Errorf("inspect data directory %q: %w", dataDir, err)
	}
	if _, err := resolvePrivateFileParent(filepath.Dir(dataDir)); err != nil {
		return fmt.Errorf("inspect data directory parent: %w", err)
	}
	return nil
}

func preflightSetupClientConfig(opts setupOptions) error {
	path := setupClientConfigPath(opts)
	if _, err := privateFileWritePath(path, setupPrivateFileRoot(opts)); err != nil {
		return err
	}
	switch opts.Target {
	case "claude-code":
		if _, err := readJSONObject(path); err != nil {
			return fmt.Errorf("parse existing Claude config: %w", err)
		}
	case "codex":
		raw, err := os.ReadFile(path)
		if err != nil && !os.IsNotExist(err) {
			return err
		}
		if err == nil {
			if err := validateCodexProjectTOML(string(raw)); err != nil {
				return fmt.Errorf("parse existing Codex config: %w", err)
			}
		}
	case "hermes":
		if _, err := readYAMLObject(path); err != nil {
			return fmt.Errorf("parse existing Hermes config: %w", err)
		}
	case "deepseek":
		if _, err := readYAMLList(path); err != nil {
			return fmt.Errorf("parse existing DeepSeek profile: %w", err)
		}
	}
	return nil
}

func preflightSetupHookConfig(opts setupOptions) error {
	path := setupHookConfigPath(opts)
	if _, err := privateFileWritePath(path, setupPrivateFileRoot(opts)); err != nil {
		return err
	}
	if opts.Target == "hermes" {
		if _, err := readYAMLObject(path); err != nil {
			return fmt.Errorf("parse existing Hermes hook config: %w", err)
		}
		return nil
	}
	if opts.Target == "deepseek" {
		if _, err := readJSONObject(path); err != nil {
			return fmt.Errorf("parse existing DeepSeek hook config: %w", err)
		}
		return nil
	}
	if _, err := readJSONObject(path); err != nil {
		return fmt.Errorf("parse existing hook config: %w", err)
	}
	return nil
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

func setupQuickstartProfile(target string) string {
	switch target {
	case "codex":
		return "codex"
	case "hermes", "deepseek":
		return "mcp"
	default:
		return "claude"
	}
}
