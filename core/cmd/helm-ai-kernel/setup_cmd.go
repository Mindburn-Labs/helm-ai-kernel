// quantum_posture: the setup flags accept a classical Ed25519 signing-seed path.

package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/internal/cli/ui"
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
	setupCompensateMCP = removeSetupMCP
	setupProbeClient   = func(target, dir string) error {
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

func init() {
	Register(Subcommand{
		Name:  "setup",
		Usage: "Install local Claude Code or Codex MCP/hook integration, or a Hermes or DeepSeek fail-closed shell hook",
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
	fmt.Fprintln(stderr, "  3) Hermes — fail-closed shell pre_tool_call (user scope)")
	fmt.Fprintln(stderr, "  4) DeepSeek — fail-closed Kernel hook + stock DSH bridge (user scope)")
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
	case "3", "hermes":
		return runSetupInstallCmdWithInput([]string{"hermes", "--scope", "user"}, stdout, stderr, input, caps)
	case "4", "deepseek":
		return runSetupInstallCmdWithInput([]string{"deepseek", "--scope", "user"}, stdout, stderr, input, caps)
	case "q", "quit", "cancel":
		fmt.Fprintln(stderr, "setup: no changes made; run `helm-ai-kernel setup claude-code --scope project --dry-run` when ready")
		return 0
	default:
		fmt.Fprintf(stderr, "setup: unknown choice %q; choose 1, 2, 3, 4, or q\n", strings.TrimSpace(choice))
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
	formatFlag := ui.RegisterFormat(fs, ui.FormatText)
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
	if formatFlag.IsJSON() {
		*jsonOut = true
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

func printSetupUsage(w io.Writer) {
	fmt.Fprintln(w, "Choose a local agent profile (project scope is the default):")
	fmt.Fprintln(w, "  helm-ai-kernel setup claude-code --yes")
	fmt.Fprintln(w, "  helm-ai-kernel setup codex --yes")
	fmt.Fprintln(w, "  helm-ai-kernel setup hermes --scope user --yes")
	fmt.Fprintln(w, "  helm-ai-kernel setup deepseek --scope user --yes")
	fmt.Fprintln(w, "  helm-ai-kernel setup --quickstart --profile mcp --yes")
	fmt.Fprintln(w, "  helm-ai-kernel setup --client cursor --print-config")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "Inspect first:")
	fmt.Fprintln(w, "  helm-ai-kernel setup claude-code --dry-run --json")
	fmt.Fprintln(w, "  helm-ai-kernel setup --json")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "Manage:")
	fmt.Fprintln(w, "  helm-ai-kernel setup codex --scope project --workspace DIR --dry-run --json")
	fmt.Fprintln(w, "  helm-ai-kernel setup status [--all|--format json]   inspect every supported client")
	fmt.Fprintln(w, "  helm-ai-kernel setup status <claude-code|codex|hermes|deepseek|cursor|vscode|windsurf> [--scope user|project] [--workspace DIR] [--json] [--data-dir DIR]")
	fmt.Fprintln(w, "  helm-ai-kernel setup repair <claude-code|codex|hermes|deepseek> [--scope user|project] [--workspace DIR] [--yes] [--dry-run] [--json] [--data-dir DIR]")
	fmt.Fprintln(w, "  helm-ai-kernel setup remove <claude-code|codex|hermes|deepseek> [--scope user|project] [--workspace DIR] [--yes] [--dry-run] [--json] [--data-dir DIR]")
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
	fmt.Fprintln(w, "Usage: helm-ai-kernel setup <claude-code|codex|hermes|deepseek> [options]")
	fmt.Fprintln(w, "Install a scoped HELM integration for one local coding agent.")
	fmt.Fprintln(w, "Claude Code and Codex write an MCP server plus a PreToolUse hook.")
	fmt.Fprintln(w, "Hermes writes a fail-closed pre_tool_call shell hook only.")
	fmt.Fprintln(w, "DeepSeek writes a fail-closed Kernel hook file plus a stock DSH hook-bridge configPath.")
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
	if operation == "status" {
		fmt.Fprintln(w, "Usage: helm-ai-kernel setup status [<claude-code|codex|hermes|deepseek|cursor|vscode|windsurf>|--all] [options]")
		fmt.Fprintln(w, "Inspect local HELM integration without changing configuration.")
		fmt.Fprintln(w, "No target inspects every supported client at both user and project locations where supported. Print-config clients never claim native_loaded.")
	} else {
		fmt.Fprintf(w, "Usage: helm-ai-kernel setup %s <claude-code|codex|hermes|deepseek> [options]\n", operation)
		fmt.Fprintf(w, "%s HELM-owned local integration configuration.\n", strings.ToUpper(operation[:1])+operation[1:])
	}
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "Options:")
	if operation == "status" {
		fmt.Fprintln(w, "  --scope user|project                          Scope for a named client (default project for Claude Code/Codex; user for Hermes/DeepSeek)")
	} else {
		fmt.Fprintln(w, "  --scope user|project                          Installation scope (default user)")
	}
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
	formatFlag := ui.RegisterFormat(fs, ui.FormatText)
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
	opts.JSON = opts.JSON || formatFlag.IsJSON()
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
	if name == "setup status" && len(args) > 0 {
		if target, err := normalizeSetupTarget(args[0]); err == nil {
			opts.Scope = setupInspectionScopes(target)[0]
		}
	}
	if len(args) == 0 {
		fmt.Fprintf(stderr, "%s: expected <claude-code|codex|hermes|deepseek>\n", name)
		return opts, 2
	}
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.StringVar(&opts.Scope, "scope", opts.Scope, "Install scope: user or project")
	fs.StringVar(&opts.Workspace, "workspace", "", "Workspace to inspect or remove from (defaults to the current directory for project scope)")
	fs.BoolVar(&opts.DryRun, "dry-run", false, "Print planned changes without writing config")
	fs.BoolVar(&opts.JSON, "json", false, "Print machine-readable summary")
	formatFlag := ui.RegisterFormat(fs, ui.FormatText)
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
	opts.JSON = opts.JSON || formatFlag.IsJSON()
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

func normalizeSetupTarget(target string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(target)) {
	case "claude", "claude-code", "claude_code":
		return "claude-code", nil
	case "codex":
		return "codex", nil
	case "hermes":
		return "hermes", nil
	case "deepseek":
		return "deepseek", nil
	default:
		return "", fmt.Errorf("target must be claude-code, codex, hermes, or deepseek, got %q", target)
	}
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
