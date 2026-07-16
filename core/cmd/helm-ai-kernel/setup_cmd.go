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

	"github.com/BurntSushi/toml"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/shadow"
)

const setupMCPServerName = "helm-ai-kernel-governance"

const (
	setupHookOwnershipStatus = "HELM native client setup v1"
	setupLegacyHookStatus    = "Checking HELM policy"
	setupMCPOwnershipMarker  = "HELM native client setup v1"
)

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

	// lifecycleReceiptID is set only by the durable Codex-project recovery
	// journal so a resumed operation can prove or complete the same receipt.
	lifecycleReceiptID       string
	lifecycleRecoveryManaged bool
}

type setupSummary struct {
	Target                  string `json:"target"`
	BinaryPath              string `json:"binary_path"`
	ClientConfigPath        string `json:"client_config_path"`
	HookConfigPath          string `json:"hook_config_path"`
	DataDir                 string `json:"data_dir"`
	KernelURL               string `json:"kernel_url"`
	ScanGrade               string `json:"scan_grade"`
	DraftPolicyPath         string `json:"draft_policy_path"`
	UninstallCommand        string `json:"uninstall_command"`
	Scope                   string `json:"scope,omitempty"`
	MCPConfigured           bool   `json:"mcp_configured"`
	HookConfigured          bool   `json:"hook_configured"`
	LocalConfigVerified     bool   `json:"local_config_verified"`
	Configured              bool   `json:"configured"`
	ClientLoadObserved      bool   `json:"client_load_observed"`
	SyntheticDenialVerified bool   `json:"synthetic_denial_verified,omitempty"`
	LifecycleReceiptID      string `json:"lifecycle_receipt_id,omitempty"`
	LifecycleEvidencePath   string `json:"lifecycle_evidence_path,omitempty"`
	RecoveryRequired        bool   `json:"recovery_required,omitempty"`
	RecoveryCleanupPending  bool   `json:"recovery_cleanup_pending,omitempty"`
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
	case "migrate":
		return runSetupMigrateCmd(args[1:], stdout, stderr)
	case "remove":
		return runSetupRemoveCmd(args[1:], stdout, stderr)
	case "recover":
		return runSetupRecoverCmd(args[1:], stdout, stderr)
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
	if opts.Target == "codex" && opts.Scope == "project" {
		securedDataDir, authorityErr := validateSetupAuthorityDataDirIfPresent(opts.DataDir)
		if authorityErr != nil {
			fmt.Fprintf(stderr, "setup: unsafe Codex project authority state: %v\n", authorityErr)
			return 1
		}
		opts.DataDir = securedDataDir
		summary.DataDir = securedDataDir
		pending, recoveryErr := setupRecoveryRequired(opts.DataDir)
		if recoveryErr != nil {
			fmt.Fprintf(stderr, "setup: inspect Codex project recovery state: %v\n", recoveryErr)
			return 1
		}
		if pending {
			fmt.Fprintln(stderr, "setup: Codex project recovery is required before changing local config; run `helm-ai-kernel setup recover codex --scope project --yes`")
			return 1
		}
		// Keep invalid profile/configuration preflight read-only. The lock itself
		// creates a secure authority root, so acquire it only after checks that
		// must not leave local state behind have passed; prepare repeats them
		// under the lock before any configuration mutation.
		if err := validateSetupLifecycleReceiptProfile(); err != nil {
			fmt.Fprintf(stderr, "setup: prepare crash-safe Codex project setup: %v\n", err)
			return 1
		}
		if err := preflightCodexProjectSetup(opts, summary); err != nil {
			fmt.Fprintf(stderr, "setup: prepare crash-safe Codex project setup: %v\n", err)
			return 1
		}
		lifecycleLock, lockErr := acquireSetupCodexProjectLifecycleLock(opts.DataDir)
		if lockErr != nil {
			fmt.Fprintf(stderr, "setup: acquire Codex project lifecycle lock: %v\n", lockErr)
			return 1
		}
		defer func() { _ = lifecycleLock.Close() }()
		// Another lifecycle command can complete between the read-only preflight
		// and lock acquisition. Re-check under the lock before publishing a
		// recovery journal or changing client configuration.
		pending, recoveryErr = setupRecoveryRequired(opts.DataDir)
		if recoveryErr != nil {
			fmt.Fprintf(stderr, "setup: inspect Codex project recovery state after lifecycle lock: %v\n", recoveryErr)
			return 1
		}
		if pending {
			fmt.Fprintln(stderr, "setup: Codex project recovery is required before changing local config; run `helm-ai-kernel setup recover codex --scope project --yes`")
			return 1
		}
		preparation, err := prepareCodexProjectRecoveryInstall(opts, summary)
		if err != nil {
			fmt.Fprintf(stderr, "setup: prepare crash-safe Codex project setup: %v\n", err)
			return 1
		}
		lifecycle, recoveredSummary, err := resumeCodexProjectRecovery(opts, preparation.summary, preparation.journal)
		if err != nil {
			fmt.Fprintf(stderr, "setup: Codex project setup did not complete; local recovery is required before retrying: %v\n", err)
			return 1
		}
		summary = recoveredSummary
		summary.SyntheticDenialVerified = lifecycle.SyntheticDenialVerified
		summary.LifecycleReceiptID = lifecycle.ReceiptID
		summary.LifecycleEvidencePath = lifecycle.EvidencePath
		printSetupSummary(stdout, summary, opts.JSON)
		// Codex project configuration starts the MCP server over stdio on demand.
		// A separate quickstart HTTP server neither proves nor enables that client
		// lifecycle, and would keep this setup command running indefinitely.
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
	refreshSetupConfiguration(opts, &summary)
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
	refreshSetupConfiguration(opts, &summary)
	if opts.Target == "codex" && opts.Scope == "project" {
		inspection, recoveryErr := inspectSetupRecovery(opts.DataDir)
		if recoveryErr != nil {
			fmt.Fprintf(stderr, "setup status: inspect Codex project recovery state: %v\n", recoveryErr)
			return 2
		}
		summary.RecoveryRequired = inspection.State == setupRecoveryStatePrepared || inspection.State == setupRecoveryStatePending
		summary.RecoveryCleanupPending = inspection.State == setupRecoveryStateCommitted
	}
	scanInventoryPath := filepath.Join(opts.DataDir, "autoconfigure", "inventory.json")
	if opts.Target == "codex" && opts.Scope == "project" {
		scanInventoryPath = filepath.Join(setupCodexProjectArtifactsDir(opts.DataDir), "inventory.json")
	}
	if grade := readSetupScanGrade(scanInventoryPath); grade != "" {
		summary.ScanGrade = grade
	}
	printSetupSummary(stdout, summary, opts.JSON)
	if summary.Configured && !summary.RecoveryRequired {
		return 0
	}
	return 1
}

func runSetupRecoverCmd(args []string, stdout, stderr io.Writer) int {
	opts, code := parseSetupInspectArgs("setup recover", args, stderr, true)
	if code != 0 {
		return code
	}
	if opts.Target != "codex" || opts.Scope != "project" {
		fmt.Fprintln(stderr, "setup recover: recovery is available only for Codex project scope")
		return 2
	}
	if !opts.DryRun {
		securedDataDir, authorityErr := requireSetupAuthorityDataDir(opts.DataDir)
		if authorityErr != nil {
			fmt.Fprintf(stderr, "setup recover: unsafe Codex project authority state: %v\n", authorityErr)
			return 1
		}
		opts.DataDir = securedDataDir
	}
	summary, err := buildSetupSummary(opts)
	if err != nil {
		fmt.Fprintf(stderr, "setup recover: %v\n", err)
		return 2
	}
	inspection, err := inspectSetupRecovery(opts.DataDir)
	if err != nil {
		fmt.Fprintf(stderr, "setup recover: inspect recovery state: %v\n", err)
		return 1
	}
	if inspection.State == setupRecoveryStateAbsent {
		fmt.Fprintln(stderr, "setup recover: no pending Codex project recovery journal")
		return 1
	}
	if opts.DryRun {
		summary.RecoveryRequired = inspection.State == setupRecoveryStatePrepared || inspection.State == setupRecoveryStatePending
		summary.RecoveryCleanupPending = inspection.State == setupRecoveryStateCommitted
		printSetupSummary(stdout, summary, opts.JSON)
		return 0
	}
	if !opts.Yes {
		fmt.Fprintln(stderr, "setup recover: pass --yes to resume the recorded local transaction")
		return 2
	}
	lifecycleLock, lockErr := acquireSetupCodexProjectLifecycleLock(opts.DataDir)
	if lockErr != nil {
		fmt.Fprintf(stderr, "setup recover: acquire Codex project lifecycle lock: %v\n", lockErr)
		return 1
	}
	defer func() { _ = lifecycleLock.Close() }()
	// Re-read durable recovery state under the lock; an install/remove process
	// may have completed or published a new transaction after the earlier
	// inspection.
	inspection, err = inspectSetupRecovery(opts.DataDir)
	if err != nil {
		fmt.Fprintf(stderr, "setup recover: inspect recovery state after lifecycle lock: %v\n", err)
		return 1
	}
	if inspection.State == setupRecoveryStateAbsent {
		fmt.Fprintln(stderr, "setup recover: no pending Codex project recovery journal")
		return 1
	}
	if inspection.State == setupRecoveryStatePrepared {
		if err := cleanupIncompleteSetupRecoveryDirectory(opts.DataDir); err != nil {
			fmt.Fprintf(stderr, "setup recover: remove incomplete pre-journal residue: %v\n", err)
			return 1
		}
		refreshSetupConfiguration(opts, &summary)
		printSetupSummary(stdout, summary, opts.JSON)
		return 0
	}
	if inspection.State == setupRecoveryStateCommitted {
		if err := cleanupCommittedSetupRecoveryDirectory(opts.DataDir); err != nil {
			fmt.Fprintf(stderr, "setup recover: remove committed transaction residue: %v\n", err)
			return 1
		}
		refreshSetupConfiguration(opts, &summary)
		printSetupSummary(stdout, summary, opts.JSON)
		return 0
	}
	journal := inspection.Journal
	if journal == nil {
		fmt.Fprintln(stderr, "setup recover: recovery state has no resumable journal")
		return 1
	}
	lifecycle, recoveredSummary, err := resumeCodexProjectRecovery(opts, summary, journal)
	if err != nil {
		fmt.Fprintf(stderr, "setup recover: recovery did not complete; the journal was retained: %v\n", err)
		return 1
	}
	recoveredSummary.LifecycleReceiptID = lifecycle.ReceiptID
	recoveredSummary.LifecycleEvidencePath = lifecycle.EvidencePath
	recoveredSummary.SyntheticDenialVerified = lifecycle.SyntheticDenialVerified
	printSetupSummary(stdout, recoveredSummary, opts.JSON)
	return 0
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
	if opts.DryRun {
		refreshSetupConfiguration(opts, &summary)
		printSetupSummary(stdout, summary, opts.JSON)
		return 0
	}
	if opts.Target == "codex" && opts.Scope == "project" {
		securedDataDir, authorityErr := validateSetupAuthorityDataDirIfPresent(opts.DataDir)
		if authorityErr != nil {
			fmt.Fprintf(stderr, "setup remove: unsafe Codex project authority state: %v\n", authorityErr)
			return 1
		}
		opts.DataDir = securedDataDir
		summary.DataDir = securedDataDir
		pending, recoveryErr := setupRecoveryRequired(opts.DataDir)
		if recoveryErr != nil {
			fmt.Fprintf(stderr, "setup remove: inspect Codex project recovery state: %v\n", recoveryErr)
			return 1
		}
		if pending {
			fmt.Fprintln(stderr, "setup remove: Codex project recovery is required before changing local config; run `helm-ai-kernel setup recover codex --scope project --yes`")
			return 1
		}
		if err := validateSetupLifecycleReceiptProfile(); err != nil {
			fmt.Fprintf(stderr, "setup remove: prepare crash-safe Codex project removal: %v\n", err)
			return 1
		}
		// Preserve the no-op removal contract: unowned/missing configuration must
		// not create a lifecycle root merely to take a lock. This mirrors the
		// non-mutating branches in prepareCodexProjectRecoveryRemove; a possible
		// owned configuration still takes the lock and is fully revalidated below.
		clientBefore, inspectErr := readSetupFileState(summary.ClientConfigPath)
		if inspectErr != nil {
			fmt.Fprintf(stderr, "setup remove: prepare crash-safe Codex project removal: %v\n", inspectErr)
			return 1
		}
		hookBefore, inspectErr := readSetupFileState(summary.HookConfigPath)
		if inspectErr != nil {
			fmt.Fprintf(stderr, "setup remove: prepare crash-safe Codex project removal: %v\n", inspectErr)
			return 1
		}
		if inspectErr := requireCodexProjectHookSourceForRemoval(clientBefore.Data); inspectErr != nil {
			fmt.Fprintf(stderr, "setup remove: prepare crash-safe Codex project removal: %v\n", inspectErr)
			return 1
		}
		mcp, inspectErr := readCodexMCPServerFromBytes(clientBefore.Data)
		if inspectErr != nil {
			fmt.Fprintf(stderr, "setup remove: prepare crash-safe Codex project removal: %v\n", inspectErr)
			return 1
		}
		if mcp == nil || !isHELMCodexMCPServerCore(*mcp) {
			if strings.Contains(string(hookBefore.Data), setupHookOwnershipStatus) {
				if mcp == nil {
					fmt.Fprintln(stderr, "setup remove: Codex hook looks HELM-managed but no MCP install binding can prove automatic removal")
				} else {
					fmt.Fprintln(stderr, "setup remove: Codex hook looks HELM-managed but its MCP server is not a proven HELM installation")
				}
				return 1
			}
			refreshSetupConfiguration(opts, &summary)
			printSetupSummary(stdout, summary, opts.JSON)
			return 0
		}
		lifecycleLock, lockErr := acquireSetupCodexProjectLifecycleLock(opts.DataDir)
		if lockErr != nil {
			fmt.Fprintf(stderr, "setup remove: acquire Codex project lifecycle lock: %v\n", lockErr)
			return 1
		}
		defer func() { _ = lifecycleLock.Close() }()
		pending, recoveryErr = setupRecoveryRequired(opts.DataDir)
		if recoveryErr != nil {
			fmt.Fprintf(stderr, "setup remove: inspect Codex project recovery state after lifecycle lock: %v\n", recoveryErr)
			return 1
		}
		if pending {
			fmt.Fprintln(stderr, "setup remove: Codex project recovery is required before changing local config; run `helm-ai-kernel setup recover codex --scope project --yes`")
			return 1
		}
		preparation, err := prepareCodexProjectRecoveryRemove(opts, summary)
		if err != nil {
			fmt.Fprintf(stderr, "setup remove: prepare crash-safe Codex project removal: %v\n", err)
			return 1
		}
		if preparation.journal != nil {
			lifecycle, recoveredSummary, err := resumeCodexProjectRecovery(opts, preparation.summary, preparation.journal)
			if err != nil {
				fmt.Fprintf(stderr, "setup remove: Codex project removal did not complete; local recovery is required before retrying: %v\n", err)
				return 1
			}
			summary = recoveredSummary
			summary.LifecycleReceiptID = lifecycle.ReceiptID
			summary.LifecycleEvidencePath = lifecycle.EvidencePath
		}
	} else if !opts.DryRun {
		if err := removeSetupHook(opts, summary.BinaryPath); err != nil {
			fmt.Fprintf(stderr, "setup remove: remove hook: %v\n", err)
			return 1
		}
		if err := removeSetupMCP(opts); err != nil {
			fmt.Fprintf(stderr, "setup remove: remove MCP server: %v\n", err)
			return 1
		}
		refreshSetupConfiguration(opts, &summary)
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
	fmt.Fprintln(w, "  helm-ai-kernel setup status <claude-code|codex> [--scope user|project] [--json] [--data-dir DIR]")
	fmt.Fprintln(w, "  helm-ai-kernel setup migrate codex --scope project --yes [--dry-run] [--json] [--data-dir DIR]")
	fmt.Fprintln(w, "  helm-ai-kernel setup remove <claude-code|codex> [--scope user|project] [--yes] [--dry-run] [--json] [--data-dir DIR]")
	fmt.Fprintln(w, "  helm-ai-kernel setup recover codex --scope project --yes [--json] [--data-dir DIR]")
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
	dataDir, err := normalizeSetupDataDir(opts.DataDir)
	if err != nil {
		fmt.Fprintf(stderr, "setup: %v\n", err)
		return opts, 2
	}
	opts.DataDir = dataDir
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
	identity, err := inspectSetupKernelBinary(bin)
	if err != nil {
		return setupSummary{}, err
	}
	draftPolicyPath := filepath.Join(opts.DataDir, "autoconfigure", "policy.draft.json")
	if opts.Target == "codex" && opts.Scope == "project" {
		paths, err := newSetupCodexProjectPaths(opts)
		if err != nil {
			return setupSummary{}, err
		}
		draftPolicyPath = filepath.Join(paths.ArtifactsDir, "policy.draft.json")
	}
	return setupSummary{
		Target:           opts.Target,
		BinaryPath:       identity.Path,
		ClientConfigPath: setupClientConfigPath(opts),
		HookConfigPath:   setupHookConfigPath(opts),
		DataDir:          opts.DataDir,
		KernelURL:        "http://127.0.0.1:7714",
		ScanGrade:        "not_run",
		DraftPolicyPath:  draftPolicyPath,
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
	fmt.Fprintf(stdout, "  Local config:  mcp=%v hook=%v exact=%v\n", summary.MCPConfigured, summary.HookConfigured, summary.LocalConfigVerified)
	fmt.Fprintf(stdout, "  Integration:   configured=%v client_load_observed=%v (local config is not client-session proof)\n", summary.Configured, summary.ClientLoadObserved)
	if summary.RecoveryRequired {
		fmt.Fprintln(stdout, "  Recovery:      required=true (MCP startup is blocked until `setup recover` completes)")
	}
	if summary.RecoveryCleanupPending {
		fmt.Fprintln(stdout, "  Recovery:      committed cleanup is pending (the completed transaction is safe; `setup recover --yes` removes only HELM residue)")
	}
	if summary.SyntheticDenialVerified {
		fmt.Fprintf(stdout, "  Synthetic deny: verified=true (Kernel-only, no client session)\n")
	}
	if summary.LifecycleReceiptID != "" {
		fmt.Fprintf(stdout, "  Lifecycle receipt: %s\n", summary.LifecycleReceiptID)
	}
	if summary.LifecycleEvidencePath != "" {
		fmt.Fprintf(stdout, "  Lifecycle evidence: %s\n", summary.LifecycleEvidencePath)
	}
}

func runSetupAutoconfigure(dataDir string) (string, string, error) {
	return runSetupAutoconfigureWithWriter(dataDir, writeJSONArtifact)
}

func runSetupAutoconfigureWithWriter(dataDir string, writeArtifact func(string, any) error) (string, string, error) {
	return runSetupAutoconfigureTo(filepath.Join(dataDir, "autoconfigure"), writeArtifact)
}

func runSetupAutoconfigureTo(outDir string, writeArtifact func(string, any) error) (string, string, error) {
	report, err := shadow.NewScanner().Scan(".")
	if err != nil {
		return "", "", err
	}
	inv := buildInventory(report)
	if err := writeArtifact(filepath.Join(outDir, "inventory.json"), inv); err != nil {
		return "", "", err
	}
	draft, plan := buildPolicyDraft(inv)
	policyPath := filepath.Join(outDir, "policy.draft.json")
	if err := writeArtifact(policyPath, draft); err != nil {
		return "", "", err
	}
	if err := writeArtifact(filepath.Join(outDir, "mcp_quarantine_plan.json"), plan); err != nil {
		return "", "", err
	}
	return inv.Grade.Letter, policyPath, nil
}

func marshalSetupJSONArtifact(value any) ([]byte, error) {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

func installSetupMCP(opts setupOptions, bin string) error {
	switch opts.Target {
	case "claude-code":
		claude, err := resolveSetupClaudeCodeBinary()
		if err != nil {
			return err
		}
		return setupExecCommand(claude, "mcp", "add", "--transport", "stdio", "--scope", opts.Scope, setupMCPServerName, "--", bin, "mcp", "serve", "--transport", "stdio", "--data-dir", opts.DataDir)
	case "codex":
		if opts.Scope == "project" {
			return upsertCodexProjectMCP(setupClientConfigPath(opts), bin, opts.DataDir)
		}
		return setupExecCommand("codex", "mcp", "add", setupMCPServerName, "--", bin, "mcp", "serve", "--transport", "stdio", "--data-dir", opts.DataDir)
	default:
		return fmt.Errorf("unsupported target %q", opts.Target)
	}
}

func removeSetupMCP(opts setupOptions) error {
	switch opts.Target {
	case "claude-code":
		claude, err := resolveSetupClaudeCodeBinary()
		if err != nil {
			return err
		}
		return setupExecCommand(claude, "mcp", "remove", "--scope", opts.Scope, setupMCPServerName)
	case "codex":
		if opts.Scope == "project" {
			return removeCodexProjectMCP(setupClientConfigPath(opts), opts.DataDir)
		}
		return setupExecCommand("codex", "mcp", "remove", setupMCPServerName)
	default:
		return fmt.Errorf("unsupported target %q", opts.Target)
	}
}

func installSetupHook(opts setupOptions, bin string) error {
	return upsertOwnedSetupHookConfig(setupHookConfigPath(opts), setupHookMatcher(opts.Target), setupHookCommand(opts, bin), opts.Target)
}

func removeSetupHook(opts setupOptions, bin string) error {
	return removeOwnedSetupHookConfig(setupHookConfigPath(opts), opts.Target, setupHookCommand(opts, bin))
}

func setupMCPConfigured(opts setupOptions, path, bin string) bool {
	if opts.Target != "codex" {
		// The external Claude Code CLI owns its config serialization. Until that
		// exact schema is inspected rather than guessed, configuration is not
		// reported as observed.
		return false
	}
	server, ok, err := readCodexMCPServer(path)
	if err != nil || !ok {
		return false
	}
	return isOwnedCodexMCPServer(server) && server.Command == bin && sameSetupStringSlice(server.Args, setupMCPServerArgs(opts.DataDir))
}

func setupHookConfigured(opts setupOptions, path, bin string) bool {
	if opts.Target == "codex" && opts.Scope == "project" {
		source, err := inspectCodexProjectHookSourcePath(setupClientConfigPath(opts))
		if err != nil || source.HooksDisabled || source.InlineHooks {
			return false
		}
	}
	_, pre, err := readSetupHookConfig(path)
	if err != nil {
		return false
	}
	for _, entry := range pre {
		if !isStrictOwnedSetupHookEntryForCommand(entry, opts.Target, setupHookCommand(opts, bin)) {
			continue
		}
		group := entry.(map[string]any)
		hooks := group["hooks"].([]any)
		if hookCommandFromAny(hooks[0]) == setupHookCommand(opts, bin) {
			return true
		}
	}
	return false
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

func setupMCPServerArgs(dataDir string) []string {
	return []string{"mcp", "serve", "--transport", "stdio", "--data-dir", dataDir}
}

func sameSetupStringSlice(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
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

func upsertOwnedSetupHookConfig(path, matcher, command, target string) error {
	state, err := readSetupFileState(path)
	if err != nil {
		return err
	}
	next, err := buildUpsertOwnedSetupHookState(state, matcher, command, target)
	if err != nil {
		return err
	}
	return restoreSetupFileState(next)
}

func removeOwnedSetupHookConfig(path, target, expectedCommand string) error {
	state, err := readSetupFileState(path)
	if err != nil {
		return err
	}
	next, err := buildRemoveOwnedSetupHookState(state, target, expectedCommand)
	if err != nil {
		return err
	}
	if sameSetupFileState(state, next) {
		return nil
	}
	return restoreSetupFileState(next)
}

func buildUpsertOwnedSetupHookState(state setupFileState, matcher, command, target string) (setupFileState, error) {
	root, pre, err := parseSetupHookConfig(state.Data)
	if err != nil {
		return setupFileState{}, err
	}
	if err := requireMutableSetupHookEntries(pre, target, command); err != nil {
		return setupFileState{}, err
	}
	filtered := make([]any, 0, len(pre)+1)
	for _, existing := range pre {
		if !isStrictOwnedSetupHookEntryForCommand(existing, target, command) {
			filtered = append(filtered, existing)
		}
	}
	entry := map[string]any{
		"matcher": matcher,
		"hooks": []any{
			map[string]any{
				"type":          "command",
				"command":       command,
				"timeout":       float64(30),
				"statusMessage": setupHookOwnershipStatus,
			},
		},
	}
	if err := setSetupPreToolUse(root, append(filtered, entry)); err != nil {
		return setupFileState{}, err
	}
	data, err := json.MarshalIndent(root, "", "  ")
	if err != nil {
		return setupFileState{}, err
	}
	return setupFileState{Path: state.Path, Exists: true, Data: append(data, '\n')}, nil
}

func buildRemoveOwnedSetupHookState(state setupFileState, target, expectedCommand string) (setupFileState, error) {
	if !state.Exists {
		return state, nil
	}
	root, pre, err := parseSetupHookConfig(state.Data)
	if err != nil {
		return setupFileState{}, err
	}
	if err := requireMutableSetupHookEntries(pre, target, expectedCommand); err != nil {
		return setupFileState{}, err
	}
	filtered := make([]any, 0, len(pre))
	found := false
	for _, entry := range pre {
		if isStrictOwnedSetupHookEntryForCommand(entry, target, expectedCommand) {
			found = true
			continue
		}
		filtered = append(filtered, entry)
	}
	if !found {
		return state, nil
	}
	if err := setSetupPreToolUse(root, filtered); err != nil {
		return setupFileState{}, err
	}
	data, err := json.MarshalIndent(root, "", "  ")
	if err != nil {
		return setupFileState{}, err
	}
	return setupFileState{Path: state.Path, Exists: true, Data: append(data, '\n')}, nil
}

func removeHookConfig(path string, remove func(hook any) bool) error {
	state, err := readSetupFileState(path)
	if err != nil {
		return err
	}
	if !state.Exists {
		return nil
	}
	root, err := readJSONObject(path)
	if err != nil {
		return err
	}
	hooks := objectValue(root, "hooks")
	pre := arrayValue(hooks, "PreToolUse")
	filtered := filterHookEntries(pre, remove)
	hooks["PreToolUse"] = filtered
	root["hooks"] = hooks
	return writeJSONObject(path, root)
}

func filterHookEntries(pre []any, remove func(hook any) bool) []any {
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
			if !remove(hook) {
				keptHooks = append(keptHooks, hook)
			}
		}
		if len(keptHooks) > 0 {
			obj["hooks"] = keptHooks
			filtered = append(filtered, obj)
		}
	}
	return filtered
}

func isOwnedSetupHook(hook any, target string) bool {
	status := hookStatusMessageFromAny(hook)
	switch status {
	case setupHookOwnershipStatus:
		return isSetupHookCommandShape(hookCommandFromAny(hook), target)
	case setupLegacyHookStatus:
		return isSetupHookCommandShape(hookCommandFromAny(hook), target)
	default:
		return false
	}
}

func hasUnownedMatchingSetupHook(pre []any, command, target string) bool {
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
			if hookCommandFromAny(hook) == command && !isOwnedSetupHook(hook, target) {
				return true
			}
		}
	}
	return false
}

func isSetupHookCommandShape(command, target string) bool {
	separator := " hook pre-tool --client " + target + " --data-dir "
	parts := strings.SplitN(command, separator, 2)
	if len(parts) != 2 || !strings.HasPrefix(parts[0], "'") || !strings.HasSuffix(parts[0], "'") {
		return false
	}
	if !isHELMKernelExecutable(strings.Trim(parts[0], "'")) {
		return false
	}
	return strings.HasPrefix(parts[1], "'") && strings.HasSuffix(parts[1], "'")
}

// setupHookDataDirArgument returns the exact shell-quoted data-dir argument
// emitted by setupHookCommand. Keeping it lexical avoids treating a differently
// quoted or extended shell fragment as equivalent ownership.
func setupHookDataDirArgument(command, target string) (string, bool) {
	if !isSetupHookCommandShape(command, target) {
		return "", false
	}
	separator := " hook pre-tool --client " + target + " --data-dir "
	parts := strings.SplitN(command, separator, 2)
	if len(parts) != 2 {
		return "", false
	}
	return parts[1], true
}

func sameSetupHookDataDirArgument(current, expected, target string) bool {
	currentArg, currentOK := setupHookDataDirArgument(current, target)
	expectedArg, expectedOK := setupHookDataDirArgument(expected, target)
	return currentOK && expectedOK && currentArg == expectedArg
}

func readJSONObject(path string) (map[string]any, error) {
	state, err := readSetupFileState(path)
	if err != nil {
		return nil, err
	}
	if !state.Exists {
		return map[string]any{}, nil
	}
	if strings.TrimSpace(string(state.Data)) == "" {
		return map[string]any{}, nil
	}
	var root map[string]any
	if err := json.Unmarshal(state.Data, &root); err != nil {
		return nil, err
	}
	if root == nil {
		root = map[string]any{}
	}
	return root, nil
}

func writeJSONObject(path string, root map[string]any) error {
	data, err := json.MarshalIndent(root, "", "  ")
	if err != nil {
		return err
	}
	return writeSetupPrivateFile(path, append(data, '\n'))
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

// readSetupHookConfig validates the concrete JSON shape before any mutation.
// Missing hooks are initializable; an existing value of the wrong type is
// user state and must never be coerced into a replacement object or array.
func readSetupHookConfig(path string) (map[string]any, []any, error) {
	state, err := readSetupFileState(path)
	if err != nil {
		return nil, nil, err
	}
	return parseSetupHookConfig(state.Data)
}

func parseSetupHookConfig(raw []byte) (map[string]any, []any, error) {
	if len(strings.TrimSpace(string(raw))) == 0 {
		return map[string]any{}, []any{}, nil
	}
	var root map[string]any
	if err := json.Unmarshal(raw, &root); err != nil {
		return nil, nil, err
	}
	if root == nil {
		return map[string]any{}, []any{}, nil
	}
	rawHooks, hasHooks := root["hooks"]
	if !hasHooks {
		return root, []any{}, nil
	}
	hooks, ok := rawHooks.(map[string]any)
	if !ok {
		return nil, nil, fmt.Errorf("hooks must be an object when present")
	}
	rawPreToolUse, hasPreToolUse := hooks["PreToolUse"]
	if !hasPreToolUse {
		return root, []any{}, nil
	}
	preToolUse, ok := rawPreToolUse.([]any)
	if !ok {
		return nil, nil, fmt.Errorf("hooks.PreToolUse must be an array when present")
	}
	return root, preToolUse, nil
}

func setSetupPreToolUse(root map[string]any, entries []any) error {
	rawHooks, hasHooks := root["hooks"]
	var hooks map[string]any
	if !hasHooks {
		hooks = map[string]any{}
	} else {
		var ok bool
		hooks, ok = rawHooks.(map[string]any)
		if !ok {
			return fmt.Errorf("hooks must be an object when present")
		}
	}
	hooks["PreToolUse"] = entries
	root["hooks"] = hooks
	return nil
}

func exactSetupObjectKeys(obj map[string]any, want ...string) bool {
	if len(obj) != len(want) {
		return false
	}
	for _, key := range want {
		if _, ok := obj[key]; !ok {
			return false
		}
	}
	return true
}

func isStrictOwnedSetupHookEntry(entry any, target string) bool {
	group, ok := entry.(map[string]any)
	if !ok || !exactSetupObjectKeys(group, "matcher", "hooks") {
		return false
	}
	matcher, _ := group["matcher"].(string)
	if matcher != setupHookMatcher(target) {
		return false
	}
	hooks, ok := group["hooks"].([]any)
	return ok && len(hooks) == 1 && isStrictOwnedSetupHook(hooks[0], target)
}

// isStrictOwnedSetupHookEntryForCommand preserves automatic binary upgrades
// while making the selected Kernel state directory part of HELM ownership. A
// changed data-dir changes the scope of local state and must be treated as
// user-managed rather than silently rewritten or removed.
func isStrictOwnedSetupHookEntryForCommand(entry any, target, expectedCommand string) bool {
	if !isStrictOwnedSetupHookEntry(entry, target) {
		return false
	}
	group := entry.(map[string]any)
	hooks := group["hooks"].([]any)
	return sameSetupHookDataDirArgument(hookCommandFromAny(hooks[0]), expectedCommand, target)
}

func isStrictOwnedSetupHook(hook any, target string) bool {
	obj, ok := hook.(map[string]any)
	if !ok || !exactSetupObjectKeys(obj, "type", "command", "timeout", "statusMessage") {
		return false
	}
	typ, _ := obj["type"].(string)
	command, _ := obj["command"].(string)
	status, _ := obj["statusMessage"].(string)
	timeout, ok := obj["timeout"].(float64)
	return typ == "command" && timeout == 30 && status == setupHookOwnershipStatus && isSetupHookCommandShape(command, target) && ok
}

func isHELMSetupHookCandidate(entry any, target string) bool {
	group, ok := entry.(map[string]any)
	if !ok {
		return false
	}
	hooks, ok := group["hooks"].([]any)
	if !ok {
		return false
	}
	for _, hook := range hooks {
		status := hookStatusMessageFromAny(hook)
		if status == setupHookOwnershipStatus || status == setupLegacyHookStatus || isSetupHookCommandShape(hookCommandFromAny(hook), target) {
			return true
		}
	}
	return false
}

func requireMutableSetupHookEntries(entries []any, target, expectedCommand string) error {
	if _, ok := setupHookDataDirArgument(expectedCommand, target); !ok {
		return fmt.Errorf("invalid expected HELM hook command")
	}
	for _, entry := range entries {
		if isHELMSetupHookCandidate(entry, target) && !isStrictOwnedSetupHookEntryForCommand(entry, target, expectedCommand) {
			return fmt.Errorf("Codex hook has user-managed fields or an unproven HELM ownership marker; refusing automatic mutation")
		}
	}
	return nil
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

func hookStatusMessageFromAny(v any) string {
	obj, ok := v.(map[string]any)
	if !ok {
		return ""
	}
	statusMessage, _ := obj["statusMessage"].(string)
	return statusMessage
}

func hasOwnedSetupHookInBytes(raw []byte, target, expectedCommand string) (bool, error) {
	_, pre, err := parseSetupHookConfig(raw)
	if err != nil {
		return false, fmt.Errorf("parse hook config: %w", err)
	}
	if err := requireMutableSetupHookEntries(pre, target, expectedCommand); err != nil {
		return false, err
	}
	for _, entry := range pre {
		if isStrictOwnedSetupHookEntryForCommand(entry, target, expectedCommand) {
			return true, nil
		}
	}
	return false, nil
}

type codexMCPServerConfig struct {
	Command         string   `toml:"command"`
	Args            []string `toml:"args"`
	UnmanagedKeys   []string `toml:"-"`
	OwnershipMarker bool     `toml:"-"`
}

func readCodexMCPServer(path string) (codexMCPServerConfig, bool, error) {
	state, err := readSetupFileState(path)
	if err != nil {
		return codexMCPServerConfig{}, false, err
	}
	if !state.Exists {
		return codexMCPServerConfig{}, false, nil
	}
	server, err := readCodexMCPServerFromBytes(state.Data)
	if err != nil {
		return codexMCPServerConfig{}, false, err
	}
	if server == nil {
		return codexMCPServerConfig{}, false, nil
	}
	return *server, true, nil
}

func readCodexMCPServerFromBytes(raw []byte) (*codexMCPServerConfig, error) {
	var config struct {
		MCPServers map[string]codexMCPServerConfig `toml:"mcp_servers"`
	}
	metadata, err := toml.Decode(string(raw), &config)
	if err != nil {
		return nil, fmt.Errorf("parse Codex MCP config: %w", err)
	}
	server, ok := config.MCPServers[setupMCPServerName]
	if !ok {
		return nil, nil
	}
	for _, key := range metadata.Undecoded() {
		if len(key) > 2 && key[0] == "mcp_servers" && key[1] == setupMCPServerName {
			server.UnmanagedKeys = append(server.UnmanagedKeys, key.String())
		}
	}
	server.OwnershipMarker = hasCodexMCPOwnershipMarker(raw)
	return &server, nil
}

type codexProjectHookSource struct {
	HooksDisabled bool
	InlineHooks   bool
}

// inspectCodexProjectHookSource checks the project config layer only. It does
// not claim anything about trusted user/system/plugin layers; those still need
// a real Codex client session. Within the project layer, however, mixed inline
// and hooks.json sources or a disabled feature make this local setup unsafe.
func inspectCodexProjectHookSource(raw []byte) (codexProjectHookSource, error) {
	if len(strings.TrimSpace(string(raw))) == 0 {
		return codexProjectHookSource{}, nil
	}
	var config map[string]any
	if _, err := toml.Decode(string(raw), &config); err != nil {
		return codexProjectHookSource{}, fmt.Errorf("parse Codex config: %w", err)
	}
	source := codexProjectHookSource{}
	if _, present := config["hooks"]; present {
		source.InlineHooks = true
	}
	featuresRaw, hasFeatures := config["features"]
	if !hasFeatures {
		return source, nil
	}
	features, ok := featuresRaw.(map[string]any)
	if !ok {
		return codexProjectHookSource{}, fmt.Errorf("Codex features must be a table")
	}
	hooks, hasHooks, err := codexHookFeatureValue(features, "hooks")
	if err != nil {
		return codexProjectHookSource{}, err
	}
	legacy, hasLegacy, err := codexHookFeatureValue(features, "codex_hooks")
	if err != nil {
		return codexProjectHookSource{}, err
	}
	if hasHooks && hasLegacy && hooks != legacy {
		return codexProjectHookSource{}, fmt.Errorf("Codex hooks and codex_hooks feature values conflict")
	}
	source.HooksDisabled = (hasHooks && !hooks) || (hasLegacy && !legacy)
	return source, nil
}

func codexHookFeatureValue(features map[string]any, key string) (bool, bool, error) {
	raw, ok := features[key]
	if !ok {
		return false, false, nil
	}
	value, ok := raw.(bool)
	if !ok {
		return false, false, fmt.Errorf("Codex features.%s must be a boolean", key)
	}
	return value, true, nil
}

func inspectCodexProjectHookSourcePath(path string) (codexProjectHookSource, error) {
	state, err := readSetupFileState(path)
	if err != nil {
		return codexProjectHookSource{}, err
	}
	return inspectCodexProjectHookSource(state.Data)
}

func requireCodexProjectHookSourceForInstall(raw []byte) error {
	source, err := inspectCodexProjectHookSource(raw)
	if err != nil {
		return err
	}
	if source.HooksDisabled {
		return fmt.Errorf("Codex hooks are disabled in project config; refusing to install an inactive hook")
	}
	if source.InlineHooks {
		return fmt.Errorf("Codex project config already defines inline hooks; refusing to mix config.toml and hooks.json sources")
	}
	return nil
}

func requireCodexProjectHookSourceForRemoval(raw []byte) error {
	source, err := inspectCodexProjectHookSource(raw)
	if err != nil {
		return err
	}
	if source.InlineHooks {
		return fmt.Errorf("Codex project config defines inline hooks; refusing automatic removal across mixed hook sources")
	}
	return nil
}

func hasCodexMCPOwnershipMarker(raw []byte) bool {
	insideServer := false
	for _, line := range strings.Split(string(raw), "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") {
			insideServer = trimmed == "[mcp_servers."+setupMCPServerName+"]"
			continue
		}
		if insideServer && trimmed == "# "+setupMCPOwnershipMarker {
			return true
		}
	}
	return false
}

func hasCodexProjectOwnedConfig(clientConfigPath, hookConfigPath, expectedDataDir, expectedHookCommand string) (bool, error) {
	clientState, err := readSetupFileState(clientConfigPath)
	if err != nil {
		return false, err
	}
	if err := requireCodexProjectHookSourceForRemoval(clientState.Data); err != nil {
		return false, err
	}
	mcp, hasMCP, err := readCodexMCPServer(clientConfigPath)
	if err != nil {
		return false, err
	}
	if hasMCP {
		if err := requireSafeCodexMCPRemoval(&mcp, expectedDataDir); err != nil {
			return false, err
		}
	}
	hookState, err := readSetupFileState(hookConfigPath)
	if err != nil {
		return false, err
	}
	hasHook := false
	if hookState.Exists {
		hasHook, err = hasOwnedSetupHookInBytes(hookState.Data, "codex", expectedHookCommand)
		if err != nil {
			return false, err
		}
	}
	return (hasMCP && isOwnedCodexMCPServerForDataDir(mcp, expectedDataDir)) || hasHook, nil
}

func upsertCodexProjectMCP(path, bin, dataDir string) error {
	state, err := readSetupFileState(path)
	if err != nil {
		return err
	}
	next, err := buildUpsertCodexProjectMCPState(state, bin, dataDir)
	if err != nil {
		return err
	}
	return restoreSetupFileState(next)
}

func removeCodexProjectMCP(path, expectedDataDir string) error {
	state, err := readSetupFileState(path)
	if err != nil {
		return err
	}
	next, err := buildRemoveCodexProjectMCPState(state, expectedDataDir)
	if err != nil {
		return err
	}
	if sameSetupFileState(state, next) {
		return nil
	}
	return restoreSetupFileState(next)
}

func buildUpsertCodexProjectMCPState(state setupFileState, bin, dataDir string) (setupFileState, error) {
	if err := requireCodexProjectHookSourceForInstall(state.Data); err != nil {
		return setupFileState{}, err
	}
	existing, err := readCodexMCPServerFromBytes(state.Data)
	if err != nil {
		return setupFileState{}, err
	}
	if err := requireMutableCodexMCPServer(existing, dataDir); err != nil {
		return setupFileState{}, err
	}
	current := removeTOMLTable(string(state.Data), "[mcp_servers."+setupMCPServerName+"]")
	block := fmt.Sprintf("[mcp_servers.%s]\n# %s\ncommand = %q\nargs = [\"mcp\", \"serve\", \"--transport\", \"stdio\", \"--data-dir\", %q]\n", setupMCPServerName, setupMCPOwnershipMarker, bin, dataDir)
	next := strings.TrimRight(current, "\n")
	if next != "" {
		next += "\n\n"
	}
	next += block
	return setupFileState{Path: state.Path, Exists: true, Data: []byte(next)}, nil
}

func buildRemoveCodexProjectMCPState(state setupFileState, expectedDataDir string) (setupFileState, error) {
	return buildRemoveCodexProjectMCPStateForBinary(state, expectedDataDir, "")
}

func buildRemoveCodexProjectMCPStateForBinary(state setupFileState, expectedDataDir, expectedBinary string) (setupFileState, error) {
	if !state.Exists {
		return state, nil
	}
	if err := requireCodexProjectHookSourceForRemoval(state.Data); err != nil {
		return setupFileState{}, err
	}
	existing, err := readCodexMCPServerFromBytes(state.Data)
	if err != nil {
		return setupFileState{}, err
	}
	owned := existing != nil && isOwnedCodexMCPServerForDataDir(*existing, expectedDataDir)
	if owned && expectedBinary != "" {
		owned = existing.Command == expectedBinary
	}
	if !owned {
		if existing != nil && isHELMCodexMCPServerCore(*existing) {
			if expectedBinary != "" && existing.Command != expectedBinary {
				return setupFileState{}, fmt.Errorf("Codex MCP server %q points at a different Kernel binary; refusing to remove it", setupMCPServerName)
			}
			if !existing.OwnershipMarker {
				return setupFileState{}, fmt.Errorf("Codex MCP server %q has no HELM ownership marker; refusing to remove it", setupMCPServerName)
			}
			if isHELMCodexMCPServerCore(*existing) && !sameSetupStringSlice(existing.Args, setupMCPServerArgs(expectedDataDir)) {
				return setupFileState{}, fmt.Errorf("Codex MCP server %q has a user-managed data-dir; refusing to remove it", setupMCPServerName)
			}
			return setupFileState{}, fmt.Errorf("Codex MCP server %q has user-managed fields (%s); refusing to remove it", setupMCPServerName, strings.Join(existing.UnmanagedKeys, ", "))
		}
		return state, nil
	}
	next := removeTOMLTable(string(state.Data), "[mcp_servers."+setupMCPServerName+"]")
	return setupFileState{Path: state.Path, Exists: true, Data: []byte(strings.TrimRight(next, "\n") + "\n")}, nil
}

func isOwnedCodexMCPServer(server codexMCPServerConfig) bool {
	return server.OwnershipMarker && isHELMCodexMCPServerCore(server) && len(server.UnmanagedKeys) == 0
}

func isOwnedCodexMCPServerForDataDir(server codexMCPServerConfig, expectedDataDir string) bool {
	return isOwnedCodexMCPServer(server) && sameSetupStringSlice(server.Args, setupMCPServerArgs(expectedDataDir))
}

func isOwnedCodexMCPServerForBinaryAndDataDir(server codexMCPServerConfig, expectedBinary, expectedDataDir string) bool {
	return server.Command == expectedBinary && isOwnedCodexMCPServerForDataDir(server, expectedDataDir)
}

func isHELMCodexMCPServerCore(server codexMCPServerConfig) bool {
	return isHELMKernelExecutable(server.Command) && isOwnedCodexMCPArgs(server.Args)
}

func requireMutableCodexMCPServer(server *codexMCPServerConfig, expectedDataDir string) error {
	if server == nil {
		return nil
	}
	if !isHELMCodexMCPServerCore(*server) {
		return fmt.Errorf("Codex MCP server %q exists but is not HELM-owned; refusing to replace it", setupMCPServerName)
	}
	if !server.OwnershipMarker {
		return fmt.Errorf("Codex MCP server %q has no HELM ownership marker; refusing to replace it", setupMCPServerName)
	}
	if len(server.UnmanagedKeys) > 0 {
		return fmt.Errorf("Codex MCP server %q has user-managed fields (%s); refusing to replace it", setupMCPServerName, strings.Join(server.UnmanagedKeys, ", "))
	}
	if !sameSetupStringSlice(server.Args, setupMCPServerArgs(expectedDataDir)) {
		return fmt.Errorf("Codex MCP server %q has a user-managed data-dir; refusing to replace it", setupMCPServerName)
	}
	return nil
}

// Removal may coexist with an unrelated user-owned server of the same name
// while removing a separately owned hook. Only a HELM-shaped server without
// provenance or with extra fields is ambiguous enough to block automatic
// removal.
func requireSafeCodexMCPRemoval(server *codexMCPServerConfig, expectedDataDir string) error {
	if server == nil || !isHELMCodexMCPServerCore(*server) {
		return nil
	}
	if !server.OwnershipMarker {
		return fmt.Errorf("Codex MCP server %q has no HELM ownership marker; refusing automatic removal", setupMCPServerName)
	}
	if len(server.UnmanagedKeys) > 0 {
		return fmt.Errorf("Codex MCP server %q has user-managed fields (%s); refusing automatic removal", setupMCPServerName, strings.Join(server.UnmanagedKeys, ", "))
	}
	if !sameSetupStringSlice(server.Args, setupMCPServerArgs(expectedDataDir)) {
		return fmt.Errorf("Codex MCP server %q has a user-managed data-dir; refusing automatic removal", setupMCPServerName)
	}
	return nil
}

func isOwnedCodexMCPArgs(args []string) bool {
	const prefixLength = 5
	if len(args) != prefixLength+1 {
		return false
	}
	for index, want := range []string{"mcp", "serve", "--transport", "stdio", "--data-dir"} {
		if args[index] != want {
			return false
		}
	}
	return filepath.IsAbs(args[5])
}

func isHELMKernelExecutable(path string) bool {
	if !filepath.IsAbs(path) {
		return false
	}
	base := strings.TrimSuffix(filepath.Base(path), ".exe")
	return base == "helm-ai-kernel" || base == "helm-ai-kernel.test"
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
