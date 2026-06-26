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
}

func init() {
	Register(Subcommand{
		Name:  "quickstart",
		Usage: "Start local Kernel onboarding proof path",
		RunFn: runQuickstartCmd,
	})
}

func runQuickstartCmd(args []string, stdout, stderr io.Writer) int {
	opts, code := parseQuickstartArgs(args, stderr)
	if code != 0 {
		return code
	}
	if err := validateQuickstartOptions(opts); err != nil {
		fmt.Fprintf(stderr, "quickstart: %v\n", err)
		return 2
	}
	prepared, err := prepareQuickstart(opts)
	if err != nil {
		fmt.Fprintf(stderr, "quickstart: %v\n", err)
		return 1
	}
	if opts.JSON || opts.DryRun {
		_ = json.NewEncoder(stdout).Encode(prepared.summary())
	}
	if opts.DryRun {
		return 0
	}

	installQuickstartRuntimeEnv(prepared.Runtime)

	runServerWithOptions(serverOptions{
		Mode:       "quickstart",
		BindAddr:   opts.Addr,
		Port:       opts.Port,
		DataDir:    opts.DataDir,
		PolicyPath: prepared.PolicyPath,
		Quickstart: prepared.Runtime,
		OnReady: func(bindAddr string, port int) {
			if !opts.JSON {
				fmt.Fprintf(stdout, "HELM quickstart ready\n\n")
				fmt.Fprintf(stdout, "Kernel:  http://%s:%d\n", bindAddr, port)
				fmt.Fprintf(stdout, "Policy:  %s\n\n", prepared.PolicyPath)
			}
		},
		Stdout: stdout,
		Stderr: stderr,
	})
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
	fs.BoolVar(&opts.DryRun, "dry-run", false, "Prepare and print startup summary without starting the server")
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
	KernelURL  string
	PolicyPath string
	Runtime    *quickstartRuntime
}

func (p quickstartPrepared) summary() map[string]any {
	return map[string]any{
		"kernel_url":         p.KernelURL,
		"policy_path":        p.PolicyPath,
		"tenant_id":          p.Runtime.TenantID,
		"principal_id":       p.Runtime.PrincipalID,
		"profile":            p.Runtime.Profile,
		"entitlements":       []string{"OSS_CORE"},
		"local_session_ttl":  time.Until(p.Runtime.ExpiresAt).String(),
		"start_onboarding":   true,
		"requires_cloud":     false,
		"requires_docker":    false,
		"requires_model_key": false,
	}
}

func prepareQuickstart(opts quickstartOptions) (quickstartPrepared, error) {
	if opts.Reset {
		if err := os.RemoveAll(opts.DataDir); err != nil {
			return quickstartPrepared{}, fmt.Errorf("reset data dir: %w", err)
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
	kernelURL := fmt.Sprintf("http://%s:%d", opts.Addr, opts.Port)
	return quickstartPrepared{
		KernelURL:  kernelURL,
		PolicyPath: policyPath,
		Runtime:    runtime,
	}, nil
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
