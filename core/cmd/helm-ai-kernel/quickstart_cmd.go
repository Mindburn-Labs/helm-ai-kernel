package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
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
	logger, logFormat, err := configureServerLogger(stderr, "quickstart")
	if err != nil {
		fmt.Fprintf(stderr, "quickstart: %v\n", err)
		return 2
	}
	var parseOutput strings.Builder
	opts, err := parseQuickstartArgs(args, &parseOutput)
	if err != nil {
		if logFormat == "json" || parseOutput.Len() == 0 {
			writeQuickstartError(logger, logFormat, stderr, err, "")
		} else {
			_, _ = io.WriteString(stderr, parseOutput.String())
		}
		return 2
	}
	if err := validateQuickstartOptions(opts); err != nil {
		writeQuickstartError(logger, logFormat, stderr, err, "")
		return 2
	}
	planned, err := planQuickstart(opts)
	if err != nil {
		writeQuickstartError(logger, logFormat, stderr, err, "")
		return 1
	}
	if opts.DryRun {
		// A reset preview must exercise the same ownership and target guard as a
		// real reset. The guard is read-only; emitting a success preview before
		// it passes would falsely imply that deletion is authorized.
		_, planned, err = preflightQuickstartReset(opts, planned)
		if err != nil {
			writeQuickstartError(logger, logFormat, stderr, err, "")
			return 1
		}
		_ = json.NewEncoder(stdout).Encode(planned.summary("preview"))
		return 0
	}
	prepared, err := prepareQuickstart(opts)
	if err != nil {
		writeQuickstartError(logger, logFormat, stderr, err, "")
		return 1
	}
	var console *localConsoleSupervisor
	if opts.Console {
		console, err = newLocalConsoleSupervisor(prepared.ConsoleBundle, opts.ConsolePort, prepared.Runtime)
		if err != nil {
			writeQuickstartError(logger, logFormat, stderr, err, "")
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
		writeQuickstartError(logger, logFormat, stderr, fmt.Errorf("start Kernel: %w", err), quickstartErrorRoute(err, opts))
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

func parseQuickstartArgs(args []string, stderr io.Writer) (quickstartOptions, error) {
	opts := quickstartOptions{
		Addr:    "127.0.0.1",
		Port:    7714,
		DataDir: defaultQuickstartDataDir(),
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
		return opts, err
	}
	if fs.NArg() > 0 {
		return opts, fmt.Errorf("unexpected argument %q", fs.Arg(0))
	}
	return opts, nil
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

var errQuickstartOwnershipMarkerMissing = errors.New("quickstart ownership marker is missing")

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
