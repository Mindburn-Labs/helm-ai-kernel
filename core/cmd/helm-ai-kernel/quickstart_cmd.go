// quantum_posture: quickstart migration validates classical Ed25519 local root
// material only; it does not provide or claim post-quantum assurance.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	helmauth "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/auth"
)

type quickstartOptions struct {
	Addr        string
	Port        int
	DataDir     string
	Reset       bool
	Offline     bool
	Profile     string
	JSON        bool
	DryRun      bool
	Yes         bool
	Console     bool
	ConsolePort int
	NoOpen      bool
}

func init() {
	Register(Subcommand{
		Name:   "quickstart",
		Usage:  "Start local Kernel onboarding proof path",
		RunFn:  runQuickstartCmd,
		HelpFn: printQuickstartUsage,
	})
}

func runQuickstartCmd(args []string, stdout, stderr io.Writer) int {
	return runQuickstartCmdWithReady(args, stdout, stderr, nil)
}

var runQuickstartServer = runServerWithOptions

func runQuickstartCmdWithReady(args []string, stdout, stderr io.Writer, onReady func()) int {
	if isHelpRequest(args) {
		printQuickstartUsage(stdout)
		return 0
	}
	opts, code := parseQuickstartArgs(args, stderr)
	if code != 0 {
		return code
	}
	if err := validateQuickstartOptions(opts); err != nil {
		fmt.Fprintf(stderr, "quickstart: %v\n", err)
		return 2
	}
	planned, err := planQuickstart(opts)
	if err != nil {
		fmt.Fprintf(stderr, "quickstart: %v\n", err)
		return 1
	}
	if opts.DryRun {
		// A reset preview must exercise the same ownership and target guard as a
		// real reset. The guard is read-only; emitting a success preview before
		// it passes would falsely imply that deletion is authorized.
		_, planned, err = preflightQuickstartReset(opts, planned)
		if err != nil {
			fmt.Fprintf(stderr, "quickstart: %v\n", err)
			return 1
		}
		_ = json.NewEncoder(stdout).Encode(planned.summary("preview"))
		return 0
	}
	prepared, err := prepareQuickstart(opts)
	if err != nil {
		fmt.Fprintf(stderr, "quickstart: %v\n", err)
		return 1
	}
	var console *localConsoleSupervisor
	if opts.Console {
		console, err = newLocalConsoleSupervisor(prepared.ConsoleBundle, opts.ConsolePort, prepared.Runtime)
		if err != nil {
			fmt.Fprintf(stderr, "quickstart: %v\n", err)
			return 1
		}
	}
	installQuickstartRuntimeEnv(prepared.Runtime)

	if err := runQuickstartServer(serverOptions{
		Mode:             "quickstart",
		BindAddr:         opts.Addr,
		Port:             opts.Port,
		DataDir:          opts.DataDir,
		PolicyPath:       prepared.PolicyPath,
		Quickstart:       prepared.Runtime,
		ConsoleMode:      opts.Console,
		ConsolePeerProof: consolePeerProof(console),
		RuntimeExit:      consoleDone(console),
		OnShutdown:       consoleStop(console),
		JSON:             opts.JSON,
		OnReady: func(bindAddr string, port int) error {
			consoleURL := ""
			if console != nil {
				kernelURL := localKernelOrigin(bindAddr, port)
				var err error
				consoleURL, err = console.Start(kernelURL)
				if err != nil {
					return err
				}
				if err := ensureLocalConsoleReadyThenOpen(console.WaitReady, opts.NoOpen, consoleURL); err != nil {
					return err
				}
			}
			if onReady != nil {
				onReady()
			}
			writeQuickstartReady(stdout, prepared, bindAddr, port, consoleURL, opts.JSON)
			return nil
		},
		Stdout: stdout,
		Stderr: stderr,
	}); err != nil {
		fmt.Fprintf(stderr, "quickstart: start Kernel: %v\n", err)
		return 1
	}
	return 0
}

func installQuickstartRuntimeEnv(runtime *quickstartRuntime) {
	if runtime == nil {
		return
	}
	_ = os.Setenv(helmauth.AdminAPIKeyEnv, runtime.SessionToken)
	_ = os.Setenv(runtimeTenantIDEnv, runtime.TenantID)
	_ = os.Setenv(runtimePrincipalIDEnv, runtime.PrincipalID)
	_ = os.Setenv(quickstartExpiresAtEnv, runtime.ExpiresAt.Format(time.RFC3339Nano))
}

func parseQuickstartArgs(args []string, stderr io.Writer) (quickstartOptions, int) {
	opts := quickstartOptions{
		Addr:    "127.0.0.1",
		Port:    7714,
		DataDir: "data",
		Profile: "mcp",
	}
	fs := flag.NewFlagSet("quickstart", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.StringVar(&opts.Addr, "addr", opts.Addr, "Loopback bind address")
	fs.IntVar(&opts.Port, "port", opts.Port, "Local Kernel port")
	fs.StringVar(&opts.DataDir, "data-dir", opts.DataDir, "Directory for local SQLite state, keys, policy, and evidence")
	fs.BoolVar(&opts.Reset, "reset", false, "Remove the quickstart data directory before initialization")
	fs.BoolVar(&opts.Offline, "offline", false, "Refuse optional network checks during setup")
	fs.StringVar(&opts.Profile, "profile", opts.Profile, "Onboarding profile: claude, codex, mcp, openai-compatible")
	fs.BoolVar(&opts.JSON, "json", false, "Print machine-readable startup summary")
	fs.BoolVar(&opts.DryRun, "dry-run", false, "Print a startup preview without changing local state")
	fs.BoolVar(&opts.Yes, "yes", false, "Confirm --reset deletion of HELM-owned quickstart state")
	fs.BoolVar(&opts.Console, "console", false, "Start the packaged local Console sidecar")
	fs.IntVar(&opts.ConsolePort, "console-port", 3400, "Local Console port (0 chooses a loopback ephemeral port)")
	fs.BoolVar(&opts.NoOpen, "no-open", false, "Do not open the local Console in a browser")
	if err := fs.Parse(args); err != nil {
		return opts, 2
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "quickstart: unexpected argument %q\n", fs.Arg(0))
		return opts, 2
	}
	return opts, 0
}

func validateQuickstartOptions(opts quickstartOptions) error {
	if strings.TrimSpace(opts.DataDir) == "" {
		return fmt.Errorf("--data-dir must not be empty")
	}
	if opts.Reset && !opts.Yes {
		return fmt.Errorf("--reset requires --yes")
	}
	ip := net.ParseIP(opts.Addr)
	if ip == nil || !ip.IsLoopback() {
		return fmt.Errorf("--addr must be a loopback address, got %q", opts.Addr)
	}
	if opts.Port <= 0 || opts.Port > 65535 {
		return fmt.Errorf("--port must be between 1 and 65535")
	}
	if opts.Console {
		if opts.ConsolePort < 0 || opts.ConsolePort > 65535 {
			return fmt.Errorf("--console-port must be between 0 and 65535")
		}
		if err := rejectLocalConsoleOverrides(); err != nil {
			return err
		}
	}
	switch strings.ToLower(strings.TrimSpace(opts.Profile)) {
	case "claude", "codex", "mcp", "openai-compatible":
		return nil
	default:
		return fmt.Errorf("--profile must be one of claude, codex, mcp, openai-compatible")
	}
}

type quickstartPrepared struct {
	DataDir                    string
	KernelURL                  string
	PolicyPath                 string
	Profile                    string
	PlannedActions             []string
	Runtime                    *quickstartRuntime
	LocalSessionCredentialPath string
	ConsoleBundle              localConsoleBundle
	Console                    bool
}

func (p quickstartPrepared) summary(operation string) map[string]any {
	summary := map[string]any{
		"operation":          operation,
		"data_dir":           p.DataDir,
		"kernel_url":         p.KernelURL,
		"policy_path":        p.PolicyPath,
		"profile":            p.Profile,
		"entitlements":       []string{"OSS_CORE"},
		"planned_actions":    p.PlannedActions,
		"start_onboarding":   true,
		"requires_cloud":     false,
		"requires_docker":    false,
		"requires_model_key": false,
	}
	if p.Console {
		summary["console"] = true
	}
	if operation == "start" && p.Runtime != nil && !p.Console {
		summary["tenant_id"] = p.Runtime.TenantID
		summary["principal_id"] = p.Runtime.PrincipalID
		summary["local_session_ttl"] = time.Until(p.Runtime.ExpiresAt).String()
		summary["local_session_exchange_url"] = p.KernelURL + "/api/v1/local-session/exchange"
		if p.LocalSessionCredentialPath != "" {
			summary["local_session_credential_path"] = p.LocalSessionCredentialPath
		}
		// The bootstrap token exchanges for a local session and must never be
		// emitted in machine-readable command output, where it is commonly
		// redirected to logs or a pipe. The private local credential document
		// gives interactive clients a usable delivery path without doing so.
	}
	return summary
}

func planQuickstart(opts quickstartOptions) (quickstartPrepared, error) {
	dataDir, err := resolveQuickstartDataDir(opts.DataDir)
	if err != nil {
		return quickstartPrepared{}, err
	}
	plannedActions := []string{
		"create local evidence and artifact directories",
		"initialize local SQLite state",
		"generate a local trust root",
		"write the local quickstart policy and reference pack",
		"start the local Kernel",
	}
	if opts.Reset {
		plannedActions = append([]string{"reset HELM-owned quickstart state"}, plannedActions...)
	}
	prepared := quickstartPrepared{
		DataDir:        dataDir,
		KernelURL:      localKernelOrigin(opts.Addr, opts.Port),
		PolicyPath:     filepath.Join(dataDir, "quickstart", "oss_local_first_run.toml"),
		Profile:        strings.ToLower(opts.Profile),
		PlannedActions: plannedActions,
		Console:        opts.Console,
	}
	if opts.Console {
		bundle, err := discoverLocalConsoleBundle()
		if err != nil {
			return quickstartPrepared{}, err
		}
		prepared.ConsoleBundle = bundle
		prepared.PlannedActions = append(prepared.PlannedActions, "start the packaged local Console sidecar")
	}
	return prepared, nil
}

func prepareQuickstart(opts quickstartOptions) (quickstartPrepared, error) {
	prepared, err := planQuickstart(opts)
	if err != nil {
		return quickstartPrepared{}, err
	}
	opts, prepared, err = preflightQuickstartReset(opts, prepared)
	if err != nil {
		return quickstartPrepared{}, err
	}
	if opts.Reset {
		if err := os.RemoveAll(opts.DataDir); err != nil {
			return quickstartPrepared{}, fmt.Errorf("reset data dir %q: %w", opts.DataDir, err)
		}
	}
	if err := ensureQuickstartDataDirOwnership(opts.DataDir); err != nil {
		return quickstartPrepared{}, err
	}
	if err := os.MkdirAll(filepath.Join(opts.DataDir, "evidence"), 0750); err != nil {
		return quickstartPrepared{}, fmt.Errorf("create evidence dir: %w", err)
	}
	if err := os.MkdirAll(filepath.Join(opts.DataDir, "artifacts"), 0750); err != nil {
		return quickstartPrepared{}, fmt.Errorf("create artifacts dir: %w", err)
	}
	db, _, _, err := setupLiteModeWithDataDir(context.Background(), opts.DataDir)
	if err != nil {
		return quickstartPrepared{}, fmt.Errorf("initialize local sqlite store: %w", err)
	}
	_ = db.Close()
	if _, err := loadOrGenerateSignerWithDataDir(opts.DataDir); err != nil {
		return quickstartPrepared{}, fmt.Errorf("initialize trust root: %w", err)
	}
	policyPath, err := ensureQuickstartPolicy(opts)
	if err != nil {
		return quickstartPrepared{}, err
	}
	runtime, err := newQuickstartRuntime(strings.ToLower(opts.Profile), 30*time.Minute)
	if err != nil {
		return quickstartPrepared{}, fmt.Errorf("generate local session: %w", err)
	}
	credentialPath := ""
	if opts.Console {
		runtime.BootstrapToken = ""
	} else {
		credentialPath, err = writeQuickstartSessionCredential(opts.DataDir, prepared.KernelURL, runtime)
		if err != nil {
			return quickstartPrepared{}, err
		}
	}
	prepared.PolicyPath = policyPath
	prepared.Runtime = runtime
	prepared.LocalSessionCredentialPath = credentialPath
	return prepared, nil
}

// preflightQuickstartReset performs the non-mutating reset ownership and
// target validation shared by real resets and dry-run previews. It also keeps
// the prepared paths canonical after symlink resolution.
func preflightQuickstartReset(opts quickstartOptions, prepared quickstartPrepared) (quickstartOptions, quickstartPrepared, error) {
	opts.DataDir = prepared.DataDir
	if !opts.Reset {
		return opts, prepared, nil
	}
	resetTarget, err := validateQuickstartResetTarget(opts)
	if err != nil {
		return opts, prepared, err
	}
	opts.DataDir = resetTarget
	prepared.DataDir = resetTarget
	prepared.PolicyPath = filepath.Join(resetTarget, "quickstart", "oss_local_first_run.toml")
	return opts, prepared, nil
}

const (
	quickstartOwnershipMarker         = ".helm-ai-kernel-quickstart"
	quickstartOwnershipMarkerContents = "HELM AI Kernel quickstart state v1\n"
	quickstartSessionCredentialFile   = ".helm-local-session.json"
	quickstartSQLiteHeader            = "SQLite format 3\x00"
)

const quickstartReferencePackContents = `{
  "pack_id": "oss-local-first-run",
  "label": "OSS Local First Run",
  "version": 1,
  "runtime_actions": [
    {"action": "HELM_ONBOARDING_HEALTH", "expression": "true", "description": "local health proof"},
    {"action": "HELM_ONBOARDING_POLICY", "expression": "true", "description": "local policy proof"},
    {"action": "HELM_ONBOARDING_ALLOW", "expression": "true", "description": "safe allow proof"}
  ]
}
`

var errQuickstartOwnershipMarkerMissing = errors.New("quickstart ownership marker is missing")

func printQuickstartUsage(stdout io.Writer) {
	fmt.Fprintln(stdout, "Usage: helm-ai-kernel quickstart [--addr ADDR] [--port PORT] [--data-dir DIR] [--profile PROFILE] [--console --console-port PORT --no-open] [--offline] [--json] [--dry-run]")
	fmt.Fprintln(stdout, "Pass --reset --yes only to replace HELM-owned quickstart state.")
}

func consoleDone(console *localConsoleSupervisor) <-chan struct{} {
	if console == nil {
		return nil
	}
	return console.Done()
}

func consolePeerProof(console *localConsoleSupervisor) *localConsolePeerProof {
	if console == nil {
		return nil
	}
	return console.PeerProof()
}

func consoleStop(console *localConsoleSupervisor) func() {
	if console == nil {
		return nil
	}
	return console.Stop
}

func writeQuickstartReady(stdout io.Writer, prepared quickstartPrepared, bindAddr string, port int, consoleURL string, jsonOutput bool) {
	if jsonOutput {
		summary := prepared.summary("start")
		if prepared.Console {
			summary["console_url"] = consoleURL
		}
		_ = json.NewEncoder(stdout).Encode(summary)
		return
	}
	fmt.Fprintf(stdout, "HELM quickstart ready\n\n")
	fmt.Fprintf(stdout, "Kernel:  %s\n", localKernelOrigin(bindAddr, port))
	if prepared.Console {
		fmt.Fprintf(stdout, "Console: %s\n", consoleURL)
	}
	fmt.Fprintf(stdout, "Policy:  %s\n\n", prepared.PolicyPath)
}

func validateQuickstartResetTarget(opts quickstartOptions) (string, error) {
	if !opts.Yes {
		return "", fmt.Errorf("--reset requires --yes")
	}
	if strings.TrimSpace(opts.DataDir) == "" {
		return "", fmt.Errorf("--data-dir must not be empty")
	}
	if filepath.Clean(opts.DataDir) == "." {
		return "", fmt.Errorf("refusing to reset current working directory")
	}
	target, err := resolveQuickstartDataDir(opts.DataDir)
	if err != nil {
		return "", err
	}
	if target == filesystemRoot(target) {
		return "", fmt.Errorf("refusing to reset filesystem root %q", target)
	}
	cwd, err := resolveQuickstartDataDir(".")
	if err != nil {
		return "", fmt.Errorf("resolve current working directory: %w", err)
	}
	if isPathSameOrAncestor(target, cwd) {
		return "", fmt.Errorf("refusing to reset protected current workspace target %q", target)
	}
	home, err := os.UserHomeDir()
	if err != nil || !filepath.IsAbs(home) {
		return "", fmt.Errorf("resolve absolute home directory before reset")
	}
	home, err = resolveQuickstartDataDir(home)
	if err != nil {
		return "", fmt.Errorf("resolve home directory: %w", err)
	}
	if isPathSameOrAncestor(target, home) {
		return "", fmt.Errorf("refusing to reset protected home target %q", target)
	}
	info, err := os.Stat(target)
	if os.IsNotExist(err) {
		return target, nil
	}
	if err != nil {
		return "", fmt.Errorf("inspect reset target %q: %w", target, err)
	}
	if !info.IsDir() {
		return "", fmt.Errorf("refusing to reset non-directory target %q", target)
	}
	if _, err := validateQuickstartDataDirOwnership(target); err != nil {
		return "", fmt.Errorf("refusing to reset unmarked target %q; preserve it or initialize a new quickstart directory: %w", target, err)
	}
	return target, nil
}

func resolveQuickstartDataDir(path string) (string, error) {
	if strings.TrimSpace(path) == "" {
		return "", fmt.Errorf("--data-dir must not be empty")
	}
	absPath, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("resolve data directory %q: %w", path, err)
	}
	return resolveExistingSymlinks(filepath.Clean(absPath))
}

func resolveExistingSymlinks(path string) (string, error) {
	ancestor := path
	var missing []string
	for {
		if _, err := os.Lstat(ancestor); err == nil {
			resolved, err := filepath.EvalSymlinks(ancestor)
			if err != nil {
				return "", fmt.Errorf("resolve symlinks for %q: %w", path, err)
			}
			return filepath.Join(append([]string{resolved}, missing...)...), nil
		} else if !os.IsNotExist(err) {
			return "", fmt.Errorf("inspect data directory %q: %w", ancestor, err)
		}
		parent := filepath.Dir(ancestor)
		if parent == ancestor {
			return "", fmt.Errorf("resolve data directory %q", path)
		}
		missing = append([]string{filepath.Base(ancestor)}, missing...)
		ancestor = parent
	}
}

func filesystemRoot(path string) string {
	return filepath.VolumeName(path) + string(filepath.Separator)
}

func isPathSameOrAncestor(target, protected string) bool {
	rel, err := filepath.Rel(target, protected)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// ensureQuickstartDataDirOwnership creates and marks only a directory that
// this invocation created. An existing directory must already carry the exact
// marker, so normal startup cannot turn unrelated files into resettable state.
func ensureQuickstartDataDirOwnership(dataDir string) error {
	info, err := os.Lstat(dataDir)
	if os.IsNotExist(err) {
		if err := os.MkdirAll(filepath.Dir(dataDir), 0750); err != nil {
			return fmt.Errorf("create quickstart parent directory: %w", err)
		}
		if err := os.Mkdir(dataDir, 0750); err == nil {
			return writeQuickstartOwnershipMarker(dataDir)
		} else if !os.IsExist(err) {
			return fmt.Errorf("create quickstart data directory: %w", err)
		}
		info, err = os.Lstat(dataDir)
	}
	if err != nil {
		return fmt.Errorf("inspect quickstart data directory %q: %w", dataDir, err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("refusing non-directory quickstart data target %q", dataDir)
	}
	legacy, err := validateQuickstartDataDirOwnership(dataDir)
	if err != nil {
		return fmt.Errorf("refusing to initialize existing data directory %q without a valid HELM quickstart ownership marker: %w", dataDir, err)
	}
	if legacy {
		// v0.7 quickstart predates the explicit marker. Its complete, static
		// layout is a migration proof; arbitrary existing directories fail it.
		if err := writeQuickstartOwnershipMarker(dataDir); err != nil {
			return fmt.Errorf("migrate legacy quickstart ownership marker: %w", err)
		}
	}
	return nil
}

// validateQuickstartDataDirOwnership accepts either the current marker or the
// complete read-only v0.7 quickstart layout. A malformed marker never falls
// back to legacy detection, so it cannot be replaced by a newly trusted one.
func validateQuickstartDataDirOwnership(dataDir string) (legacy bool, err error) {
	err = validateQuickstartOwnershipMarker(dataDir)
	if err == nil {
		return false, nil
	}
	if !errors.Is(err, errQuickstartOwnershipMarkerMissing) {
		return false, err
	}
	if err := validateLegacyQuickstartDataDir(dataDir); err != nil {
		return false, fmt.Errorf("legacy quickstart layout is not a complete ownership proof: %w", err)
	}
	return true, nil
}

func validateQuickstartOwnershipMarker(dataDir string) error {
	markerPath := filepath.Join(dataDir, quickstartOwnershipMarker)
	info, err := os.Lstat(markerPath)
	if os.IsNotExist(err) {
		return errQuickstartOwnershipMarkerMissing
	}
	if err != nil {
		return fmt.Errorf("inspect quickstart ownership marker: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return errors.New("quickstart ownership marker must be a regular file")
	}
	marker, err := os.ReadFile(markerPath)
	if err != nil {
		return fmt.Errorf("read quickstart ownership marker: %w", err)
	}
	if string(marker) != quickstartOwnershipMarkerContents {
		return errors.New("quickstart ownership marker is invalid")
	}
	return nil
}

// validateLegacyQuickstartDataDir recognizes only the exact state generated
// by the v0.7 local quickstart. It is intentionally stricter than normal
// startup because its success permits migration (and explicit reset).
func validateLegacyQuickstartDataDir(dataDir string) error {
	if err := validateLegacyQuickstartEntries(dataDir, map[string]bool{
		"artifacts": true, "evidence": true, "helm.db": true, "helm.db-journal": true,
		"helm.db-shm": true, "helm.db-wal": true, "quickstart": true, "root.key": true,
		"root.mldsa65.key": true, "root.pub": true,
	}); err != nil {
		return err
	}
	for _, name := range []string{"artifacts", "evidence", "quickstart"} {
		if err := validateLegacyQuickstartDirectory(filepath.Join(dataDir, name)); err != nil {
			return err
		}
	}
	quickstartDir := filepath.Join(dataDir, "quickstart")
	if err := validateLegacyQuickstartEntries(quickstartDir, map[string]bool{
		"oss_local_first_run.toml": true, "reference_packs": true,
	}); err != nil {
		return err
	}
	refDir := filepath.Join(quickstartDir, "reference_packs")
	if err := validateLegacyQuickstartDirectory(refDir); err != nil {
		return err
	}
	if err := validateLegacyQuickstartEntries(refDir, map[string]bool{"oss_local_first_run.v1.json": true}); err != nil {
		return err
	}
	if err := validateLegacyQuickstartSQLite(filepath.Join(dataDir, "helm.db")); err != nil {
		return err
	}
	if err := validateLegacyQuickstartRootKey(dataDir); err != nil {
		return err
	}
	policyPath := filepath.Join(quickstartDir, "oss_local_first_run.toml")
	if err := validateLegacyQuickstartRegularFile(policyPath, true); err != nil {
		return err
	}
	policy, err := loadServePolicy(policyPath)
	if err != nil {
		return fmt.Errorf("read legacy quickstart policy: %w", err)
	}
	if policy.Name != "oss_local_first_run" || policy.Profile != "oss_core" || policy.ReferencePack != "./reference_packs/oss_local_first_run.v1.json" || policy.Receipts.Store != "sqlite" || policy.Receipts.Path != "../helm.db" {
		return errors.New("legacy quickstart policy does not match the v0.7 local profile")
	}
	if ip := net.ParseIP(policy.Server.Bind); ip == nil || !ip.IsLoopback() {
		return errors.New("legacy quickstart policy must use a loopback server bind")
	}
	refPath := filepath.Join(refDir, "oss_local_first_run.v1.json")
	if err := validateLegacyQuickstartRegularFile(refPath, true); err != nil {
		return err
	}
	ref, err := os.ReadFile(refPath)
	if err != nil {
		return fmt.Errorf("read legacy quickstart reference pack: %w", err)
	}
	if string(ref) != quickstartReferencePackContents {
		return errors.New("legacy quickstart reference pack does not match the v0.7 local profile")
	}
	if err := validateOptionalLegacyQuickstartPrivateFile(filepath.Join(dataDir, "root.mldsa65.key")); err != nil {
		return err
	}
	return nil
}

func validateLegacyQuickstartEntries(dir string, allowed map[string]bool) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("read legacy quickstart directory %q: %w", dir, err)
	}
	for _, entry := range entries {
		if !allowed[entry.Name()] {
			return fmt.Errorf("legacy quickstart directory %q contains unexpected entry %q", dir, entry.Name())
		}
	}
	return nil
}

func validateLegacyQuickstartDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect legacy quickstart directory %q: %w", path, err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("legacy quickstart path %q must be a directory, not a symlink or special file", path)
	}
	return nil
}

func validateLegacyQuickstartRegularFile(path string, private bool) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect legacy quickstart file %q: %w", path, err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return fmt.Errorf("legacy quickstart path %q must be a regular file, not a symlink or special file", path)
	}
	if private && info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("legacy quickstart file %q must not be readable by group or others", path)
	}
	return nil
}

func validateOptionalLegacyQuickstartPrivateFile(path string) error {
	if _, err := os.Lstat(path); os.IsNotExist(err) {
		return nil
	}
	return validateLegacyQuickstartRegularFile(path, true)
}

func validateLegacyQuickstartSQLite(path string) error {
	if err := validateLegacyQuickstartRegularFile(path, false); err != nil {
		return err
	}
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open legacy quickstart sqlite store: %w", err)
	}
	defer file.Close()
	header := make([]byte, len(quickstartSQLiteHeader))
	if _, err := io.ReadFull(file, header); err != nil {
		return fmt.Errorf("read legacy quickstart sqlite header: %w", err)
	}
	if string(header) != quickstartSQLiteHeader {
		return errors.New("legacy quickstart helm.db is not a SQLite database")
	}
	return nil
}

func validateLegacyQuickstartRootKey(dataDir string) error {
	keyPath := filepath.Join(dataDir, "root.key")
	if err := validateLegacyQuickstartRegularFile(keyPath, true); err != nil {
		return err
	}
	key, err := os.ReadFile(keyPath)
	if err != nil {
		return fmt.Errorf("read legacy quickstart root key: %w", err)
	}
	seed, err := hex.DecodeString(strings.TrimSpace(string(key)))
	if err != nil || len(seed) != ed25519.SeedSize {
		return errors.New("legacy quickstart root key is not an Ed25519 seed")
	}
	pubPath := filepath.Join(dataDir, "root.pub")
	if _, err := os.Lstat(pubPath); os.IsNotExist(err) {
		return nil // v0.7 logged but did not fail if writing root.pub failed.
	}
	if err := validateLegacyQuickstartRegularFile(pubPath, false); err != nil {
		return err
	}
	pub, err := os.ReadFile(pubPath)
	if err != nil {
		return fmt.Errorf("read legacy quickstart root public key: %w", err)
	}
	decoded, err := hex.DecodeString(strings.TrimSpace(string(pub)))
	if err != nil || len(decoded) != ed25519.PublicKeySize {
		return errors.New("legacy quickstart root public key is invalid")
	}
	expected := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	if subtle.ConstantTimeCompare(expected, decoded) != 1 {
		return errors.New("legacy quickstart root key pair does not match")
	}
	return nil
}

func writeQuickstartOwnershipMarker(dataDir string) error {
	markerPath := filepath.Join(dataDir, quickstartOwnershipMarker)
	marker, err := os.OpenFile(markerPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return fmt.Errorf("create quickstart ownership marker: %w", err)
	}
	if _, err := marker.WriteString(quickstartOwnershipMarkerContents); err != nil {
		_ = marker.Close()
		return fmt.Errorf("write quickstart ownership marker: %w", err)
	}
	if err := marker.Close(); err != nil {
		return fmt.Errorf("close quickstart ownership marker: %w", err)
	}
	return nil
}

// writeQuickstartSessionCredential supplies the one-time bootstrap token only
// through a private local file. Command output may name this path but never
// carries the secret itself.
func writeQuickstartSessionCredential(dataDir, kernelURL string, runtime *quickstartRuntime) (string, error) {
	if runtime == nil || runtime.BootstrapToken == "" {
		return "", errors.New("local quickstart bootstrap credential is required")
	}
	document, err := json.Marshal(struct {
		Schema         string `json:"schema"`
		ExchangeURL    string `json:"exchange_url"`
		BootstrapToken string `json:"bootstrap_token"`
		ExpiresAt      string `json:"expires_at"`
	}{
		Schema:         "helm.local-session-bootstrap/v1",
		ExchangeURL:    kernelURL + "/api/v1/local-session/exchange",
		BootstrapToken: runtime.BootstrapToken,
		ExpiresAt:      runtime.ExpiresAt.Format(time.RFC3339),
	})
	if err != nil {
		return "", fmt.Errorf("encode local quickstart credential: %w", err)
	}
	credentialPath := filepath.Join(dataDir, quickstartSessionCredentialFile)
	if err := writePrivateFileAtomicAtPath(credentialPath, append(document, '\n')); err != nil {
		return "", fmt.Errorf("write local quickstart credential: %w", err)
	}
	runtime.BootstrapCredentialPath = credentialPath
	return credentialPath, nil
}

func ensureQuickstartPolicy(opts quickstartOptions) (string, error) {
	root := filepath.Join(opts.DataDir, "quickstart")
	refDir := filepath.Join(root, "reference_packs")
	if err := os.MkdirAll(refDir, 0750); err != nil {
		return "", fmt.Errorf("create quickstart reference pack dir: %w", err)
	}
	refPath := filepath.Join(refDir, "oss_local_first_run.v1.json")
	if _, err := os.Stat(refPath); os.IsNotExist(err) {
		if err := os.WriteFile(refPath, []byte(quickstartReferencePackContents), 0600); err != nil {
			return "", fmt.Errorf("write quickstart reference pack: %w", err)
		}
	}
	policyPath := filepath.Join(root, "oss_local_first_run.toml")
	if _, err := os.Stat(policyPath); os.IsNotExist(err) {
		policy := fmt.Sprintf(`name = "oss_local_first_run"
profile = "oss_core"
reference_pack = "./reference_packs/oss_local_first_run.v1.json"

[server]
bind = "%s"
port = %d

[receipts]
store = "sqlite"
path = "../helm.db"
`, opts.Addr, opts.Port)
		if err := os.WriteFile(policyPath, []byte(policy), 0600); err != nil {
			return "", fmt.Errorf("write quickstart policy: %w", err)
		}
	}
	return policyPath, nil
}
