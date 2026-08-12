// quantum_posture: setup provisions and propagates the path to the classical
// Ed25519 workstation signing seed (resolution and key handling live in
// workstation_signing.go); crypto/rand is used only for install identifiers.
// No post-quantum or hybrid primitives are used in this file.

package main

import (
	"bufio"
	"crypto/rand"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/BurntSushi/toml"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/internal/cli/ui"
	lpcmd "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/launchpad/cmd"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/shadow"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/workstation"
	"mvdan.cc/sh/v3/syntax"
)

const (
	setupMCPServerName      = "helm-ai-kernel-governance"
	setupRecoveryMarkerName = "setup-recovery.json"
)

var (
	setupRunQuickstart      = runQuickstartCmdWithReady
	setupRunFirstRun        = runQuickstartCmd
	setupResolveSigningSeed = resolveWorkstationSigningSeed
	setupRunAutoconfigure   = runSetupAutoconfigure
	setupInstallMCP         = installSetupMCP
	setupInstallHook        = installSetupHook
	setupExecCommand        = func(dir, name string, args ...string) error {
		cmd := exec.Command(name, args...)
		if dir != "" {
			cmd.Dir = dir
		}
		// The wrapped client's stdout (e.g. `claude mcp add` printing "Added
		// stdio MCP server …") is its confirmation prose, not our machine
		// document. Sending it to our stdout put unparseable text ahead of the
		// JSON object under --json; it belongs with the rest of our human
		// scaffolding on stderr, where it still shows in human mode.
		cmd.Stdout = os.Stderr
		cmd.Stderr = os.Stderr
		return cmd.Run()
	}
	setupFindClient = func(target string) (string, error) {
		return exec.LookPath(setupClientCommand(target))
	}
	setupProbeClient = func(target, dir string) error {
		client, err := setupFindClient(target)
		if err != nil {
			return err
		}
		cmd := exec.Command(client, "mcp", "get", setupMCPServerName)
		cmd.Dir = dir
		cmd.Stdout = io.Discard
		cmd.Stderr = io.Discard
		return cmd.Run()
	}
	setupTerminalSession = func(chrome io.Writer) (io.Reader, ui.Capabilities) {
		return os.Stdin, setupConfirmationCapabilities(chrome)
	}
)

type setupOptions struct {
	Target              string
	Operation           string
	Scope               string
	Workspace           string
	WorkspaceSet        bool
	Yes                 bool
	DryRun              bool
	JSON                bool
	NoQuickstart        bool
	Quickstart          bool
	Console             bool
	ConsolePort         int
	NoOpen              bool
	DataDir             string
	SigningSeedFile     string
	PolicyProfile       string
	PolicyProfileSet    bool
	PolicyProfileSHA256 string
}

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
}

type setupRecoveryMarker struct {
	Version         int    `json:"version"`
	Target          string `json:"target"`
	Scope           string `json:"scope"`
	Workspace       string `json:"workspace"`
	SigningSeedFile string `json:"signing_seed_file,omitempty"`
	PolicyProfile   string `json:"policy_profile,omitempty"`
}

func init() {
	Register(Subcommand{
		Name:  "setup",
		Usage: "Install local Claude Code or Codex MCP/hook integration",
		RunFn: runSetupCmd,
	})
}

func runSetupCmd(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		input, caps := setupTerminalSession(stderr)
		if !caps.Interactive {
			printSetupUsage(stdout)
			return 0
		}
		return runSetupGuidedChooser(bufio.NewReader(input), stdout, stderr, caps)
	}
	if len(args) == 1 && isHelpRequest(args) {
		printSetupUsage(stdout)
		return 0
	}
	if strings.HasPrefix(args[0], "-") {
		return runSetupFrontDoorFlags(args, stdout, stderr)
	}
	switch args[0] {
	case "status":
		return runSetupStatusCmd(args[1:], stdout, stderr)
	case "repair":
		return runSetupRepairCmd(args[1:], stdout, stderr)
	case "remove":
		return runSetupRemoveCmd(args[1:], stdout, stderr)
	case "help", "--help", "-h":
		printSetupUsage(stdout)
		return 0
	default:
		return runSetupInstallCmd(args, stdout, stderr)
	}
}

func runSetupGuidedChooser(input *bufio.Reader, stdout, stderr io.Writer, caps ui.Capabilities) int {
	fmt.Fprintln(stderr, "HELM setup configures one client for this project (project scope is the default).")
	fmt.Fprintln(stderr, "  1) Claude Code (recommended, default)")
	fmt.Fprintln(stderr, "  2) Codex")
	fmt.Fprintln(stderr, "  q) Quit without changes")
	fmt.Fprint(stderr, "Choose [1]: ")

	choice, err := input.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		fmt.Fprintf(stderr, "setup: read selection: %v\n", err)
		fmt.Fprintln(stderr, "setup: no changes made; run `helm-ai-kernel setup claude-code --scope project --dry-run` when ready")
		return 2
	}

	switch strings.ToLower(strings.TrimSpace(choice)) {
	case "", "1", "claude", "claude-code":
		return runSetupInstallCmdWithInput([]string{"claude-code", "--scope", "project"}, stdout, stderr, input, caps)
	case "2", "codex":
		return runSetupInstallCmdWithInput([]string{"codex", "--scope", "project"}, stdout, stderr, input, caps)
	case "q", "quit", "cancel":
		fmt.Fprintln(stderr, "setup: no changes made; run `helm-ai-kernel setup claude-code --scope project --dry-run` when ready")
		return 0
	default:
		fmt.Fprintf(stderr, "setup: unknown choice %q; choose 1, 2, or q\n", strings.TrimSpace(choice))
		fmt.Fprintln(stderr, "setup: no changes made; run `helm-ai-kernel setup claude-code --scope project --dry-run` when ready")
		return 2
	}
}

func runSetupFrontDoorFlags(args []string, stdout, stderr io.Writer) int {
	if isHelpRequest(args) {
		printSetupFrontDoorUsage(stdout)
		return 0
	}
	fs := flag.NewFlagSet("setup", flag.ContinueOnError)
	fs.SetOutput(stderr)
	client := fs.String("client", "", "Client to print config for")
	printConfig := fs.Bool("print-config", false, "Print config for --client")
	jsonOut := fs.Bool("json", false, "Print machine-readable support matrix")
	quickstart := fs.Bool("quickstart", false, "Start the local first-run proof path")
	profile := fs.String("profile", "mcp", "First-run profile: claude, codex, mcp, openai-compatible")
	yes := fs.Bool("yes", false, "Confirm first-run changes without prompting")
	dryRun := fs.Bool("dry-run", false, "Preview first-run changes without writing local state")
	dataDir := fs.String("data-dir", defaultQuickstartDataDir(), "Directory for local first-run state")
	console := fs.Bool("console", false, "Start the packaged local Console with Quickstart")
	consolePort := fs.Int("console-port", 3400, "Local Console port (0 chooses an ephemeral port)")
	noOpen := fs.Bool("no-open", false, "Do not open the local Console in a browser")
	offline := fs.Bool("offline", false, "Refuse optional network checks during first run")
	reset := fs.Bool("reset", false, "Replace HELM-owned first-run state")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		fmt.Fprintf(stderr, "setup: unexpected argument %q\n", fs.Arg(0))
		return 2
	}
	supplied := make(map[string]bool)
	consolePortSet := false
	fs.Visit(func(f *flag.Flag) {
		supplied[f.Name] = true
		consolePortSet = consolePortSet || f.Name == "console-port"
	})
	if rejectSetupFrontDoorModeFlags(stderr, supplied, *quickstart, *printConfig, *jsonOut) {
		return 2
	}
	if *quickstart {
		if (*noOpen || consolePortSet) && !*console {
			fmt.Fprintln(stderr, "setup: --console-port and --no-open require --console")
			return 2
		}
		return runSetupQuickstart(setupQuickstartRequest{
			Profile:     *profile,
			Yes:         *yes,
			DryRun:      *dryRun,
			JSON:        *jsonOut,
			DataDir:     *dataDir,
			Console:     *console,
			ConsolePort: *consolePort,
			NoOpen:      *noOpen,
			Offline:     *offline,
			Reset:       *reset,
		}, stdout, stderr)
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

// rejectSetupFrontDoorModeFlags prevents a parsed option from being silently
// ignored by a different front-door mode. supplied is built with FlagSet.Visit
// so default values do not become errors merely because they exist.
func rejectSetupFrontDoorModeFlags(stderr io.Writer, supplied map[string]bool, quickstart, printConfig, jsonOut bool) bool {
	quickstartOnly := []string{"profile", "yes", "dry-run", "data-dir", "console", "console-port", "no-open", "offline", "reset"}
	if quickstart {
		return rejectSetupFrontDoorFlags(stderr, supplied, "--quickstart", "client", "print-config")
	}
	if jsonOut {
		if rejectSetupFrontDoorFlags(stderr, supplied, "the support-matrix mode", "client", "print-config") {
			return true
		}
		return rejectSetupQuickstartOnlyFlags(stderr, supplied, quickstartOnly)
	}
	if printConfig {
		return rejectSetupQuickstartOnlyFlags(stderr, supplied, quickstartOnly)
	}
	if supplied["client"] {
		fmt.Fprintln(stderr, "setup: --client requires --print-config")
		return true
	}
	return rejectSetupQuickstartOnlyFlags(stderr, supplied, quickstartOnly)
}

func rejectSetupQuickstartOnlyFlags(stderr io.Writer, supplied map[string]bool, names []string) bool {
	for _, name := range names {
		if supplied[name] {
			fmt.Fprintf(stderr, "setup: --%s requires --quickstart\n", name)
			return true
		}
	}
	return false
}

func rejectSetupFrontDoorFlags(stderr io.Writer, supplied map[string]bool, mode string, names ...string) bool {
	for _, name := range names {
		if supplied[name] {
			fmt.Fprintf(stderr, "setup: --%s is not valid with %s\n", name, mode)
			return true
		}
	}
	return false
}

type setupQuickstartRequest struct {
	Profile     string
	Yes         bool
	DryRun      bool
	JSON        bool
	DataDir     string
	Console     bool
	ConsolePort int
	NoOpen      bool
	Offline     bool
	Reset       bool
}

// runSetupQuickstart keeps the first-run alias behind setup's explicit
// confirmation contract. It is intentionally only a thin forwarding layer;
// Quickstart remains the single owner of local-state preparation and reset
// validation.
func runSetupQuickstart(request setupQuickstartRequest, stdout, stderr io.Writer) int {
	if request.NoOpen && !request.Console {
		fmt.Fprintln(stderr, "setup: --no-open requires --console")
		return 2
	}
	args := setupQuickstartArgs(
		normalizeSetupQuickstartProfile(request.Profile),
		request.DataDir,
		request.Console,
		request.ConsolePort,
		request.NoOpen,
		request.Offline,
		request.Reset,
		request.Yes,
	)
	if request.DryRun {
		previewArgs := append([]string(nil), args...)
		if request.Reset && !request.Yes {
			previewArgs = append(previewArgs, "--yes")
		}
		previewArgs = append(previewArgs, "--dry-run")
		if request.JSON {
			previewArgs = append(previewArgs, "--json")
		}
		return setupRunFirstRun(previewArgs, stdout, stderr)
	}
	if !request.Yes {
		previewArgs := append([]string(nil), args...)
		// Quickstart requires --yes before it will inspect a reset target. The
		// paired --dry-run still makes this authorization read-only, while
		// letting the preview exercise the same ownership guards as apply.
		if request.Reset {
			previewArgs = append(previewArgs, "--yes")
		}
		previewArgs = append(previewArgs, "--dry-run")
		if code := setupRunFirstRun(previewArgs, stdout, stderr); code != 0 {
			return code
		}
		fmt.Fprintf(stderr, "setup: no changes made; rerun `%s` to apply this preview\n", setupQuickstartRerunCommand(request))
		return 2
	}
	if request.JSON {
		args = append(args, "--json")
	}
	return setupRunFirstRun(args, stdout, stderr)
}

func normalizeSetupQuickstartProfile(profile string) string {
	if strings.EqualFold(strings.TrimSpace(profile), "claude-code") {
		return "claude"
	}
	return strings.ToLower(strings.TrimSpace(profile))
}

func setupQuickstartArgs(profile, dataDir string, console bool, consolePort int, noOpen, offline, reset, yes bool) []string {
	args := []string{"--profile", profile, "--data-dir", dataDir}
	if console {
		args = append(args, "--console", "--console-port", strconv.Itoa(consolePort))
		if noOpen {
			args = append(args, "--no-open")
		}
	}
	if offline {
		args = append(args, "--offline")
	}
	if reset {
		args = append(args, "--reset")
	}
	if yes {
		args = append(args, "--yes")
	}
	return args
}

func setupQuickstartRerunCommand(request setupQuickstartRequest) string {
	args := []string{"helm-ai-kernel", "setup", "--quickstart"}
	args = append(args, setupQuickstartArgs(
		normalizeSetupQuickstartProfile(request.Profile),
		request.DataDir,
		request.Console,
		request.ConsolePort,
		request.NoOpen,
		request.Offline,
		request.Reset,
		true,
	)...)
	if request.JSON {
		args = append(args, "--json")
	}
	for index, arg := range args {
		if index < 3 || strings.HasPrefix(arg, "--") {
			continue
		}
		args[index] = shellQuote(arg)
	}
	return strings.Join(args, " ")
}

func setupConfirmationCapabilities(chrome io.Writer) ui.Capabilities {
	file, ok := chrome.(*os.File)
	if !ok {
		return ui.Capabilities{Width: ui.DefaultTerminalWidth}
	}
	return ui.DetectCapabilities(os.Stdin, file, ui.TerminalOptions{
		Format: ui.FormatText,
		Color:  ui.ColorAuto,
	})
}

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
		Details: []ui.KeyValue{
			{Key: "Scope", Value: summary.Scope},
			{Key: "Workspace", Value: summary.Workspace},
			{Key: "MCP config", Value: summary.ClientConfigPath},
			{Key: "Hook config", Value: summary.HookConfigPath},
			{Key: "Data dir", Value: summary.DataDir},
			{Key: "Recovery", Value: summary.RecoveryCommand},
		},
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
	}
	plan := []setupStep{
		{"provision the local signing key and draft policy artifacts", func() error { return provisionSetupLocalState(opts, summary) }},
		{"configure the HELM MCP server in " + summary.ClientConfigPath, func() error { return setupInstallMCP(opts, summary.BinaryPath) }},
		{"configure the HELM PreToolUse hook in " + summary.HookConfigPath, func() error { return setupInstallHook(opts, summary.BinaryPath) }},
		{"clear the recovery marker", func() error { return clearSetupRecovery(opts) }},
	}
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
			switch i {
			case 1:
				applyErr = fmt.Errorf("install MCP server: %w", err)
			case 2:
				applyErr = fmt.Errorf("install pre-tool hook: %w", err)
			case 3:
				applyErr = fmt.Errorf("clear recovery marker: %w", err)
			default:
				applyErr = err
			}
			continue
		}
		steps[i] = ui.Step{Status: ui.StatusPass, Title: s.title}
	}
	return steps, applyErr
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
	next := "restart " + summary.Target + " to activate governance"
	if summary.CodexTrustPending {
		next = "trust this workspace in Codex, then restart it — governance is not active until then"
	}
	r.WriteCompletion(ui.CompletionCard{
		Title: "Setup complete",
		Fields: []ui.KeyValue{
			{Key: "Client", Value: summary.Target},
			{Key: "Scope", Value: summary.Scope},
			{Key: "MCP server", Value: summary.ClientConfigPath},
			{Key: "PreToolUse hook", Value: summary.HookConfigPath},
			{Key: "Data dir", Value: summary.DataDir},
		},
		NextAction: next,
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
		case strings.Contains(s.Title, "PreToolUse hook"):
			written = append(written, "PreToolUse hook")
		case strings.Contains(s.Title, "signing key"):
			written = append(written, "local signing key and draft artifacts")
		}
	}
	if len(written) == 0 {
		return "nothing written"
	}
	return strings.Join(written, ", ") + " (governance is NOT fully active until repair completes)"
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
		return reportSetupRecovery(stderr, opts, applyErr)
	}
	summary.MCPInstalled = true
	summary.HookInstalled = true
	summary.ClientDetected = true
	summary.ClientState = "configured"
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

func runSetupStatusCmd(args []string, stdout, stderr io.Writer) int {
	if isHelpRequest(args) {
		printSetupInspectUsage(stdout, "status", false)
		return 0
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
	if grade := readSetupScanGrade(filepath.Join(opts.DataDir, "autoconfigure", "inventory.json")); grade != "" {
		summary.ScanGrade = grade
	}
	printSetupSummary(stdout, summary, opts.JSON)
	// On-disk config alone is not healthy: the client must be present and
	// confirm that it loaded HELM, with no explicit trust step still pending.
	if summary.MCPInstalled && summary.HookInstalled && summary.ClientDetected && summary.NativeLoaded && !summary.CodexTrustPending {
		return 0
	}
	return 1
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
	if !summary.MCPInstalled {
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

func printSetupUsage(w io.Writer) {
	fmt.Fprintln(w, "Choose a local agent profile (project scope is the default):")
	fmt.Fprintln(w, "  helm-ai-kernel setup claude-code --yes")
	fmt.Fprintln(w, "  helm-ai-kernel setup codex --yes")
	fmt.Fprintln(w, "  helm-ai-kernel setup --quickstart --profile mcp --yes")
	fmt.Fprintln(w, "  helm-ai-kernel setup --client cursor --print-config")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "Inspect first:")
	fmt.Fprintln(w, "  helm-ai-kernel setup claude-code --dry-run --json")
	fmt.Fprintln(w, "  helm-ai-kernel setup --json")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "Manage:")
	fmt.Fprintln(w, "  helm-ai-kernel setup codex --scope project --workspace DIR --dry-run --json")
	fmt.Fprintln(w, "  helm-ai-kernel setup status <claude-code|codex> [--scope user|project] [--workspace DIR] [--json] [--data-dir DIR]")
	fmt.Fprintln(w, "  helm-ai-kernel setup repair <claude-code|codex> [--scope user|project] [--workspace DIR] [--yes] [--dry-run] [--json] [--data-dir DIR]")
	fmt.Fprintln(w, "  helm-ai-kernel setup remove <claude-code|codex> [--scope user|project] [--workspace DIR] [--yes] [--dry-run] [--json] [--data-dir DIR]")
	fmt.Fprintln(w, "")
	printSupportMatrix(w)
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "Interactive terminals show the scoped preview and require APPROVE; pipes and JSON require --yes. Setup starts Quickstart only with --quickstart.")
}

func printSetupFrontDoorUsage(w io.Writer) {
	fmt.Fprintln(w, "Usage: helm-ai-kernel setup [front-door options]")
	fmt.Fprintln(w, "Use one read-only discovery mode or start the local first-run proof path.")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "Modes:")
	fmt.Fprintln(w, "  --quickstart                                  Start the local first-run proof path")
	fmt.Fprintln(w, "  --client CLIENT --print-config                Print config for Cursor, Windsurf, or VS Code")
	fmt.Fprintln(w, "  --json                                        Print the machine-readable support matrix")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "Quickstart options:")
	fmt.Fprintln(w, "  --profile claude|codex|mcp|openai-compatible  First-run profile (default mcp)")
	fmt.Fprintln(w, "  --data-dir DIR                                Local first-run state directory")
	fmt.Fprintln(w, "  --console [--console-port PORT] [--no-open]  Start the verified local Policies and Receipts Console")
	fmt.Fprintln(w, "  --offline | --reset | --dry-run | --json     Constrain, reset, preview, or automate the first run")
	fmt.Fprintln(w, "  --yes                                         Apply the first run; otherwise HELM previews and exits")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "Safety: only --quickstart can make local changes, and it requires --yes. Use --dry-run to inspect its exact plan.")
}

func printSetupInstallUsage(w io.Writer) {
	fmt.Fprintln(w, "Usage: helm-ai-kernel setup <claude-code|codex> [options]")
	fmt.Fprintln(w, "Install a scoped HELM MCP server and PreToolUse hook for one local coding agent.")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "Options:")
	fmt.Fprintln(w, "  --scope user|project                          Install scope (default project)")
	fmt.Fprintln(w, "  --workspace DIR                               Project-scope workspace (defaults to the current directory)")
	fmt.Fprintln(w, "  --data-dir DIR                                HELM local state directory")
	fmt.Fprintln(w, "  --dry-run | --json | --yes                    Preview, automate output, or approve installation")
	fmt.Fprintln(w, "  --no-quickstart | --quickstart                Keep setup headless (default) or start the proof path")
	fmt.Fprintln(w, "  --console [--console-port PORT] [--no-open]   Start the verified local Policies and Receipts Console with Quickstart")
	fmt.Fprintln(w, "  --signing-seed-file FILE | --policy-profile FILE  Supply explicit local signing or policy material")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "Safety: --dry-run writes nothing. Interactive terminals require typing APPROVE; pipes and --json require --yes.")
}

func printSetupInspectUsage(w io.Writer, operation string, includeYes bool) {
	fmt.Fprintf(w, "Usage: helm-ai-kernel setup %s <claude-code|codex> [options]\n", operation)
	if operation == "status" {
		fmt.Fprintln(w, "Inspect the installed local HELM integration without changing configuration.")
	} else {
		fmt.Fprintf(w, "%s HELM-owned local integration configuration.\n", strings.ToUpper(operation[:1])+operation[1:])
	}
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "Options:")
	fmt.Fprintln(w, "  --scope user|project                          Installation scope (default user)")
	fmt.Fprintln(w, "  --workspace DIR                               Project-scope workspace (defaults to the current directory)")
	fmt.Fprintln(w, "  --data-dir DIR | --policy-profile FILE        Inspect explicit local state or policy material")
	fmt.Fprintln(w, "  --dry-run | --json                            Preview or emit machine-readable output")
	if includeYes {
		fmt.Fprintln(w, "  --yes                                         Required before repair or removal changes")
		fmt.Fprintln(w, "")
		fmt.Fprintln(w, "Safety: --dry-run writes nothing; repair and removal require --yes.")
	}
}

func parseSetupInstallArgs(args []string, stderr io.Writer) (setupOptions, int) {
	opts := setupOptions{Scope: "project", NoQuickstart: true}
	fs := flag.NewFlagSet("setup", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.StringVar(&opts.Scope, "scope", opts.Scope, "Install scope: user or project")
	fs.StringVar(&opts.Workspace, "workspace", "", "Workspace to scan and configure (defaults to the current directory for project scope)")
	fs.BoolVar(&opts.Yes, "yes", false, "Install without prompting")
	fs.BoolVar(&opts.DryRun, "dry-run", false, "Print planned changes without writing config")
	fs.BoolVar(&opts.JSON, "json", false, "Print machine-readable summary")
	fs.BoolVar(&opts.NoQuickstart, "no-quickstart", opts.NoQuickstart, "Install without starting the blocking Quickstart server")
	fs.BoolVar(&opts.Quickstart, "quickstart", false, "Start the blocking Quickstart server after setup")
	fs.BoolVar(&opts.Console, "console", false, "Start the packaged local Console with Quickstart")
	fs.IntVar(&opts.ConsolePort, "console-port", 3400, "Local Console port (0 chooses an ephemeral port)")
	fs.BoolVar(&opts.NoOpen, "no-open", false, "Do not open the local Console in a browser")
	fs.StringVar(&opts.DataDir, "data-dir", "", "Directory for HELM local state")
	fs.StringVar(&opts.SigningSeedFile, "signing-seed-file", "", "Path to 0600 file containing a 32-byte Ed25519 seed as hex")
	fs.StringVar(&opts.PolicyProfile, "policy-profile", "", "Policy profile JSON path for installed pre-tool hooks")
	if err := fs.Parse(args[1:]); err != nil {
		return opts, 2
	}
	consolePortSet := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "workspace" {
			opts.WorkspaceSet = true
		}
		if f.Name == "console-port" {
			consolePortSet = true
		}
	})
	if opts.Quickstart {
		opts.NoQuickstart = false
	}
	if opts.NoOpen && !opts.Console {
		fmt.Fprintln(stderr, "setup: --no-open requires --console")
		return opts, 2
	}
	if consolePortSet && !opts.Console {
		fmt.Fprintln(stderr, "setup: --console-port requires --console")
		return opts, 2
	}
	if opts.Console && opts.NoQuickstart {
		fmt.Fprintln(stderr, "setup: --console requires --quickstart")
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
	fs.StringVar(&opts.Workspace, "workspace", "", "Workspace to inspect or remove from (defaults to the current directory for project scope)")
	fs.BoolVar(&opts.DryRun, "dry-run", false, "Print planned changes without writing config")
	fs.BoolVar(&opts.JSON, "json", false, "Print machine-readable summary")
	fs.BoolVar(&opts.NoQuickstart, "no-quickstart", false, "Report a headless setup without a Quickstart server")
	fs.StringVar(&opts.DataDir, "data-dir", "", "Directory for HELM local state")
	fs.StringVar(&opts.SigningSeedFile, "signing-seed-file", "", "Path to 0600 file containing a 32-byte Ed25519 seed as hex")
	fs.StringVar(&opts.PolicyProfile, "policy-profile", "", "Policy profile JSON path for installed pre-tool hooks")
	if includeYes {
		fs.BoolVar(&opts.Yes, "yes", false, "Remove without prompting")
	}
	if err := fs.Parse(args[1:]); err != nil {
		return opts, 2
	}
	fs.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "workspace":
			opts.WorkspaceSet = true
		case "policy-profile":
			opts.PolicyProfileSet = true
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
	// These file paths get baked into the installed hook command, which later
	// runs from an arbitrary working directory. Relative paths would resolve
	// against that directory instead of the operator's intended files.
	if strings.TrimSpace(opts.SigningSeedFile) != "" {
		if abs, err := filepath.Abs(opts.SigningSeedFile); err == nil {
			opts.SigningSeedFile = abs
		}
	}
	if strings.TrimSpace(opts.PolicyProfile) != "" {
		if abs, err := filepath.Abs(opts.PolicyProfile); err == nil {
			opts.PolicyProfile = abs
		}
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

// populateSetupPolicyProfileDigest validates a custom policy before setup
// writes a hook command, then records the exact raw-file digest that the hook
// must continue to see on every later decision. Re-running setup is the
// explicit operator approval path for a changed policy file.
func populateSetupPolicyProfileDigest(opts *setupOptions) error {
	opts.PolicyProfileSHA256 = ""
	if strings.TrimSpace(opts.PolicyProfile) == "" {
		return nil
	}
	_, digest, err := workstation.LoadPolicyProfileFileWithDigest(opts.PolicyProfile)
	if err != nil {
		return err
	}
	opts.PolicyProfileSHA256 = digest
	return nil
}

// discoverSetupStatusPolicyProfile recovers a custom profile only from one
// matching, statically parseable installed hook. The later status comparison
// still uses the full current command, including the recomputed digest.
func discoverSetupStatusPolicyProfile(opts *setupOptions, path, bin string) error {
	root, err := readJSONObject(path)
	if err != nil {
		return fmt.Errorf("read hook config: %w", err)
	}
	hooks, ok := root["hooks"].(map[string]any)
	if !ok {
		return nil
	}
	expectedKey := hookCommandKey(setupHookCommand(*opts, bin))
	var profilePath string
	matched := false
	for _, item := range arrayValue(hooks, "PreToolUse") {
		obj, ok := item.(map[string]any)
		if !ok {
			continue
		}
		for _, hook := range arrayValue(obj, "hooks") {
			command := hookCommandFromAny(hook)
			if command == "" {
				continue
			}
			if hookCommandKey(command) != expectedKey {
				continue
			}
			if matched {
				return fmt.Errorf("ambiguous matching installed hook commands")
			}
			profile, _, custom, err := installedHookPolicyProfile(command)
			if err != nil {
				return fmt.Errorf("parse matching installed hook command: %w", err)
			}
			matched = true
			if custom {
				profilePath = profile
			}
		}
	}
	if profilePath != "" {
		opts.PolicyProfile = profilePath
	}
	return nil
}

func installedHookPolicyProfile(command string) (profile, digest string, custom bool, err error) {
	words, err := staticSetupHookWords(command)
	if err != nil {
		return "", "", false, err
	}
	seenProfile, seenDigest := false, false
	for i := 0; i < len(words); i++ {
		if words[i] != "--policy-profile" && words[i] != "--policy-profile-sha256" {
			continue
		}
		if i+1 == len(words) || words[i+1] == "--policy-profile" || words[i+1] == "--policy-profile-sha256" {
			return "", "", false, fmt.Errorf("%s requires one static argument", words[i])
		}
		i++
		if words[i-1] == "--policy-profile" {
			if seenProfile {
				return "", "", false, errors.New("duplicate --policy-profile")
			}
			profile, seenProfile = words[i], true
		} else {
			if seenDigest {
				return "", "", false, errors.New("duplicate --policy-profile-sha256")
			}
			digest, seenDigest = words[i], true
		}
	}
	if seenProfile != seenDigest || (seenProfile && (profile == "" || digest == "")) {
		return "", "", false, errors.New("matching installed hook has unpaired --policy-profile arguments")
	}
	return profile, digest, seenProfile, nil
}

func staticSetupHookWords(command string) ([]string, error) {
	file, err := syntax.NewParser().Parse(strings.NewReader(command), "")
	if err != nil {
		return nil, err
	}
	if len(file.Stmts) != 1 {
		return nil, fmt.Errorf("must contain one command")
	}
	stmt := file.Stmts[0]
	if stmt.Negated || stmt.Background || stmt.Coprocess || len(stmt.Redirs) != 0 {
		return nil, fmt.Errorf("must be a direct command without shell operators")
	}
	call, ok := stmt.Cmd.(*syntax.CallExpr)
	if !ok || len(call.Assigns) != 0 {
		return nil, fmt.Errorf("must be a direct static command")
	}
	words := make([]string, 0, len(call.Args))
	for _, word := range call.Args {
		value, ok := staticSetupHookWord(word)
		if !ok {
			return nil, fmt.Errorf("contains a non-static argument")
		}
		words = append(words, value)
	}
	return words, nil
}

func staticSetupHookWord(word *syntax.Word) (string, bool) {
	var value strings.Builder
	for _, part := range word.Parts {
		switch part := part.(type) {
		case *syntax.Lit:
			value.WriteString(unescapeSetupHookLiteral(part.Value))
		case *syntax.SglQuoted:
			if part.Dollar {
				return "", false
			}
			value.WriteString(part.Value)
		case *syntax.DblQuoted:
			if part.Dollar {
				return "", false
			}
			for _, inner := range part.Parts {
				literal, ok := inner.(*syntax.Lit)
				if !ok {
					return "", false
				}
				value.WriteString(literal.Value)
			}
		default:
			return "", false
		}
	}
	return value.String(), true
}

func unescapeSetupHookLiteral(value string) string {
	var out strings.Builder
	for i := 0; i < len(value); i++ {
		if value[i] == '\\' && i+1 < len(value) {
			i++
		}
		out.WriteByte(value[i])
	}
	return out.String()
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

func setupInstallActions(opts setupOptions) []string {
	actions := []string{
		"create or reuse the local receipt signing key under " + filepath.Join(opts.DataDir, workstationSigningKeyDirectory),
		"write draft-only inventory and policy artifacts under " + filepath.Join(opts.DataDir, "autoconfigure"),
		"configure the HELM MCP server in " + setupClientConfigPath(opts),
		"configure the HELM PreToolUse hook in " + setupHookConfigPath(opts),
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

func setupRepairActions(summary setupSummary) []string {
	actions := make([]string, 0, 3)
	if summary.RecoveryRequired {
		actions = append(actions, "resume the incomplete HELM setup")
	}
	if !summary.MCPInstalled {
		actions = append(actions, "configure the HELM MCP server in "+summary.ClientConfigPath)
	}
	if !summary.HookInstalled {
		actions = append(actions, "configure the HELM PreToolUse hook in "+summary.HookConfigPath)
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
		actions = append(actions, "remove the HELM PreToolUse hook from "+summary.HookConfigPath)
	}
	return actions
}

func setupClientCommand(target string) string {
	if target == "claude-code" {
		return "claude"
	}
	return "codex"
}

func preflightSetup(opts setupOptions, summary *setupSummary) error {
	if err := preflightSetupDataDir(opts.DataDir); err != nil {
		return err
	}
	client, err := setupFindClient(opts.Target)
	if err != nil {
		return fmt.Errorf("%s client is not available on PATH; install %q and retry", opts.Target, setupClientCommand(opts.Target))
	}
	summary.ClientBinaryPath = client
	summary.ClientDetected = true
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
	}
	return nil
}

func preflightSetupHookConfig(opts setupOptions) error {
	path := setupHookConfigPath(opts)
	if _, err := privateFileWritePath(path, setupPrivateFileRoot(opts)); err != nil {
		return err
	}
	if _, err := readJSONObject(path); err != nil {
		return fmt.Errorf("parse existing hook config: %w", err)
	}
	return nil
}

func observeSetupClientState(opts setupOptions, summary *setupSummary) {
	summary.ClientDetected = false
	summary.NativeLoaded = false
	if !summary.MCPInstalled && !summary.HookInstalled {
		summary.ClientState = "absent"
		return
	}
	if !summary.MCPInstalled || !summary.HookInstalled {
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
	if err := setupProbeClient(opts.Target, setupCommandDir(opts)); err != nil {
		summary.ClientState = "configured_unverified"
		return
	}
	summary.NativeLoaded = true
	summary.ClientState = "native_loaded"
}

func printSetupPlan(w io.Writer, summary setupSummary) {
	actions := summary.PlannedActions
	if len(actions) == 0 {
		switch summary.Operation {
		case "install":
			actions = []string{
				"create or reuse local HELM state under " + summary.DataDir,
				"configure the HELM MCP server in " + summary.ClientConfigPath,
				"configure the HELM PreToolUse hook in " + summary.HookConfigPath,
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

func setupRecoveryCommand(opts setupOptions) string {
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
		"helm-ai-kernel setup repair %s --scope %s%s --yes --data-dir %s%s%s",
		opts.Target,
		opts.Scope,
		workspace,
		shellQuote(opts.DataDir),
		signingSeedFile,
		policyProfile,
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
		fmt.Fprintf(stdout, "  Client state:  %s (detected=%v native_loaded=%v)\n", summary.ClientState, summary.ClientDetected, summary.NativeLoaded)
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
		fmt.Fprintf(stdout, "  Next:          restart %s to activate governance\n", summary.Target)
	}
	if summary.RetainedData {
		fmt.Fprintln(stdout, "  Local state:   retained (keys, evidence, and receipts were not removed)")
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
	if filepath.Clean(path) != filepath.Clean(setupHookConfigPath(opts)) {
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
	config, err := readJSONObject(readPath)
	if err != nil {
		return false
	}
	hooks, ok := config["hooks"].(map[string]any)
	if !ok {
		return false
	}
	return hookCommandConfigPresent(arrayValue(hooks, "PreToolUse"), setupHookCommand(opts, bin))
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
	if strings.TrimSpace(opts.PolicyProfile) != "" {
		command += " --policy-profile " + shellQuote(opts.PolicyProfile)
		if strings.TrimSpace(opts.PolicyProfileSHA256) != "" {
			command += " --policy-profile-sha256 " + shellQuote(opts.PolicyProfileSHA256)
		}
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
		// Same hook identity: rewrite the stored command in place so a
		// re-install with a new --signing-seed-file updates the config
		// instead of silently keeping the old seed path.
		key := hookCommandKey(command)
		for _, item := range pre {
			obj, ok := item.(map[string]any)
			if !ok {
				continue
			}
			hookItems, ok := obj["hooks"].([]any)
			if !ok {
				continue
			}
			for _, h := range hookItems {
				hookObj, ok := h.(map[string]any)
				if !ok {
					continue
				}
				if hookCommandKey(hookCommandFromAny(h)) == key {
					hookObj["command"] = command
				}
			}
		}
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
			if hookCommandKey(hookCommandFromAny(h)) != hookCommandKey(command) {
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

// hookManagedFileArgPattern matches optional managed arguments of an installed
// hook command, with their shell-quoted or bare arguments. The
// argument alternation mirrors shellQuote output: a sequence of
// single-quoted chunks, escaped quotes (the '\” idiom), and bare
// non-space characters.
var hookManagedFileArgPattern = regexp.MustCompile(` --(?:signing-seed-file|policy-profile|policy-profile-sha256) (?:'[^']*'|\\'|[^\s'])+`)

// hookSignerFileArgPattern omits only the signer source. A user may omit a
// secret seed path when inspecting setup, but policy path and digest must stay
// part of the status comparison so a stale custom policy is never reported as
// active.
var hookSignerFileArgPattern = regexp.MustCompile(` --signing-seed-file (?:'[^']*'|\\'|[^\s'])+`)

// hookCommandKey reduces an installed hook command to its generic identity
// for reinstall/remove. Managed arguments are deployment details, so `setup
// remove` must match the hook whether or not (and with whichever path form)
// they were passed on its own invocation.
func hookCommandKey(command string) string {
	return hookManagedFileArgPattern.ReplaceAllString(command, "")
}

// hookCommandConfigKey preserves the approved policy path and digest for
// status checks while allowing the signer source to remain private.
func hookCommandConfigKey(command string) string {
	return hookSignerFileArgPattern.ReplaceAllString(command, "")
}

func hookCommandPresent(pre []any, command string) bool {
	key := hookCommandKey(command)
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
			if hookCommandKey(hookCommandFromAny(h)) == key {
				return true
			}
		}
	}
	return false
}

func hookCommandConfigPresent(pre []any, command string) bool {
	key := hookCommandConfigKey(command)
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
			if hookCommandConfigKey(hookCommandFromAny(h)) == key {
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

func defaultQuickstartDataDir() string {
	if dataDir := defaultSetupDataDir(); dataDir != "" {
		return filepath.Join(dataDir, "quickstart")
	}
	return ""
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
