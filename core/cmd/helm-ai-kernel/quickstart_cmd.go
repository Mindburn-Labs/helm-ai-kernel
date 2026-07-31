package main

import (
	"context"
	"encoding/json"
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
	Addr    string
	Port    int
	DataDir string
	Reset   bool
	Offline bool
	Profile string
	JSON    bool
	DryRun  bool
	Yes     bool
}

func init() {
	Register(Subcommand{
		Name:  "quickstart",
		Usage: "Start local Kernel onboarding proof path",
		RunFn: runQuickstartCmd,
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
	installQuickstartRuntimeEnv(prepared.Runtime)

	if err := runQuickstartServer(serverOptions{
		Mode:       "quickstart",
		BindAddr:   opts.Addr,
		Port:       opts.Port,
		DataDir:    opts.DataDir,
		PolicyPath: prepared.PolicyPath,
		Quickstart: prepared.Runtime,
		JSON:       opts.JSON,
		OnReady: func(bindAddr string, port int) {
			if onReady != nil {
				onReady()
			}
			if opts.JSON {
				_ = json.NewEncoder(stdout).Encode(prepared.summary("start"))
			} else {
				fmt.Fprintf(stdout, "HELM quickstart ready\n\n")
				fmt.Fprintf(stdout, "Kernel:  http://%s:%d\n", bindAddr, port)
				fmt.Fprintf(stdout, "Policy:  %s\n\n", prepared.PolicyPath)
			}
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
	switch strings.ToLower(strings.TrimSpace(opts.Profile)) {
	case "claude", "codex", "mcp", "openai-compatible":
		return nil
	default:
		return fmt.Errorf("--profile must be one of claude, codex, mcp, openai-compatible")
	}
}

type quickstartPrepared struct {
	DataDir        string
	KernelURL      string
	PolicyPath     string
	Profile        string
	PlannedActions []string
	Runtime        *quickstartRuntime
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
	if operation == "start" && p.Runtime != nil {
		summary["tenant_id"] = p.Runtime.TenantID
		summary["principal_id"] = p.Runtime.PrincipalID
		summary["local_session_ttl"] = time.Until(p.Runtime.ExpiresAt).String()
		summary["local_session_exchange_url"] = p.KernelURL + "/api/v1/local-session/exchange"
		// The bootstrap token exchanges for a local session and must never be
		// emitted in machine-readable command output, where it is commonly
		// redirected to logs or a pipe.
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
	return quickstartPrepared{
		DataDir:        dataDir,
		KernelURL:      fmt.Sprintf("http://%s:%d", opts.Addr, opts.Port),
		PolicyPath:     filepath.Join(dataDir, "quickstart", "oss_local_first_run.toml"),
		Profile:        strings.ToLower(opts.Profile),
		PlannedActions: plannedActions,
	}, nil
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
	if err := writeQuickstartOwnershipMarker(opts.DataDir); err != nil {
		return quickstartPrepared{}, err
	}
	prepared.PolicyPath = policyPath
	prepared.Runtime = runtime
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
)

func printQuickstartUsage(stdout io.Writer) {
	fmt.Fprintln(stdout, "Usage: helm-ai-kernel quickstart [--addr ADDR] [--port PORT] [--data-dir DIR] [--profile PROFILE] [--offline] [--json] [--dry-run]")
	fmt.Fprintln(stdout, "Pass --reset --yes only to replace HELM-owned quickstart state.")
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
	marker, err := os.ReadFile(filepath.Join(target, quickstartOwnershipMarker))
	if os.IsNotExist(err) {
		return "", fmt.Errorf("refusing to reset unmarked target %q; preserve it or initialize a new quickstart directory", target)
	}
	if err != nil {
		return "", fmt.Errorf("read quickstart ownership marker in %q: %w", target, err)
	}
	if string(marker) != quickstartOwnershipMarkerContents {
		return "", fmt.Errorf("refusing to reset target %q with an invalid quickstart ownership marker", target)
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

func writeQuickstartOwnershipMarker(dataDir string) error {
	if err := os.WriteFile(filepath.Join(dataDir, quickstartOwnershipMarker), []byte(quickstartOwnershipMarkerContents), 0600); err != nil {
		return fmt.Errorf("write quickstart ownership marker: %w", err)
	}
	return nil
}

func ensureQuickstartPolicy(opts quickstartOptions) (string, error) {
	root := filepath.Join(opts.DataDir, "quickstart")
	refDir := filepath.Join(root, "reference_packs")
	if err := os.MkdirAll(refDir, 0750); err != nil {
		return "", fmt.Errorf("create quickstart reference pack dir: %w", err)
	}
	refPath := filepath.Join(refDir, "oss_local_first_run.v1.json")
	if _, err := os.Stat(refPath); os.IsNotExist(err) {
		ref := `{
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
		if err := os.WriteFile(refPath, []byte(ref), 0600); err != nil {
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
