// quantum_posture: legacy onboarding invokes the existing classical Ed25519
// trust-root helper; this compatibility path adds no post-quantum or hybrid
// cryptographic control.

package main

import (
	"context"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/shadow"
)

// onboard is retained as a compatibility shim for scripts that used the
// former first-run command. New operators should use setup so profile choice,
// preview, confirmation, and recovery all live in one journey.
var runOnboardSetup = runSetupFrontDoorFlags

func runOnboardCmd(args []string, stdout, stderr io.Writer) int {
	if isHelpRequest(args) {
		printOnboardUsage(stdout)
		return 0
	}
	if isLegacyOnboardInvocation(args) {
		return runLegacyOnboardCmd(args, stdout, stderr)
	}
	fs := flag.NewFlagSet("onboard", flag.ContinueOnError)
	fs.SetOutput(stderr)
	profile := fs.String("profile", "mcp", "Compatibility first-run profile")
	yes := fs.Bool("yes", false, "Confirm first-run changes")
	dryRun := fs.Bool("dry-run", false, "Preview without changing local state")
	jsonOut := fs.Bool("json", false, "Print machine-readable Quickstart output")
	dataDir := fs.String("data-dir", "data", "Directory for HELM first-run state")
	console := fs.Bool("console", false, "Start the packaged local Console")
	consolePort := fs.Int("console-port", 3400, "Local Console port (0 chooses an ephemeral port)")
	noOpen := fs.Bool("no-open", false, "Do not open the local Console in a browser")
	offline := fs.Bool("offline", false, "Refuse optional network checks during first run")
	reset := fs.Bool("reset", false, "Replace HELM-owned first-run state")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		fmt.Fprintf(stderr, "onboard: unexpected argument %q\n", fs.Arg(0))
		return 2
	}
	consolePortSet := false
	fs.Visit(func(f *flag.Flag) {
		consolePortSet = consolePortSet || f.Name == "console-port"
	})
	if !*jsonOut {
		fmt.Fprintln(stderr, "onboard is deprecated; forwarding to `helm-ai-kernel setup --quickstart`. Existing --yes scripts remain supported.")
	}
	forwarded := []string{
		"--quickstart",
		"--profile", *profile,
		"--data-dir", *dataDir,
	}
	if *yes {
		forwarded = append(forwarded, "--yes")
	}
	if *dryRun {
		forwarded = append(forwarded, "--dry-run")
	}
	if *jsonOut {
		forwarded = append(forwarded, "--json")
	}
	if *console {
		forwarded = append(forwarded, "--console", "--console-port", fmt.Sprint(*consolePort))
	} else if consolePortSet {
		// Preserve an explicitly supplied port so setup remains the single
		// validation owner for the Console option contract.
		forwarded = append(forwarded, "--console-port", fmt.Sprint(*consolePort))
	}
	if *noOpen {
		forwarded = append(forwarded, "--no-open")
	}
	if *offline {
		forwarded = append(forwarded, "--offline")
	}
	if *reset {
		forwarded = append(forwarded, "--reset")
	}
	return runOnboardSetup(forwarded, stdout, stderr)
}

// isLegacyOnboardInvocation keeps the documented, explicitly confirmed script
// contract. New flags deliberately route to the guided Quickstart flow.
func isLegacyOnboardInvocation(args []string) bool {
	confirmed := false
	for index := 0; index < len(args); index++ {
		switch arg := args[index]; {
		case arg == "--yes" || arg == "--yes=true":
			confirmed = true
		case arg == "--data-dir":
			if index+1 >= len(args) {
				return false
			}
			index++
		case strings.HasPrefix(arg, "--data-dir="):
		default:
			return false
		}
	}
	return confirmed
}

// runLegacyOnboardCmd preserves the on-disk contract used by existing
// `onboard --yes [--data-dir DIR]` scripts. It is intentionally not promoted
// in the first-run UX; use setup --quickstart for profile-aware onboarding.
func runLegacyOnboardCmd(args []string, stdout, stderr io.Writer) int {
	cmd := flag.NewFlagSet("onboard", flag.ContinueOnError)
	cmd.SetOutput(stderr)

	var (
		yes     bool
		dataDir string
	)
	cmd.BoolVar(&yes, "yes", false, "Skip interactive confirmation")
	cmd.StringVar(&dataDir, "data-dir", "data", "Directory for HELM data (SQLite, keys, evidence)")
	if err := cmd.Parse(args); err != nil {
		return 2
	}

	fmt.Fprintf(stdout, "\n%s🚀 HELM Onboard%s\n", ColorBold+ColorBlue, ColorReset)
	fmt.Fprintf(stdout, "%s   Local fail-closed execution controls.%s\n\n", ColorGray, ColorReset)

	fmt.Fprintf(stdout, "%s[1/5]%s Creating data directory...  ", ColorBold, ColorReset)
	if err := os.MkdirAll(filepath.Join(dataDir, "artifacts"), 0750); err != nil {
		fmt.Fprintf(stderr, "\n❌ Failed: %v\n", err)
		return 2
	}
	if err := os.MkdirAll(filepath.Join(dataDir, "evidence"), 0750); err != nil {
		fmt.Fprintf(stderr, "\n❌ Failed: %v\n", err)
		return 2
	}
	fmt.Fprintf(stdout, "%s✓%s %s\n", ColorGreen, ColorReset, dataDir)

	fmt.Fprintf(stdout, "%s[2/5]%s Initializing local store...  ", ColorBold, ColorReset)
	db, _, _, err := setupLiteModeWithDataDir(context.Background(), dataDir)
	if err != nil {
		fmt.Fprintf(stderr, "\n❌ Failed: %v\n", err)
		return 2
	}
	defer db.Close()
	fmt.Fprintf(stdout, "%s✓%s SQLite at %s/helm.db\n", ColorGreen, ColorReset, dataDir)

	fmt.Fprintf(stdout, "%s[3/5]%s Generating trust root...    ", ColorBold, ColorReset)
	signer, err := loadOrGenerateSignerWithDataDir(dataDir)
	if err != nil {
		fmt.Fprintf(stderr, "\n❌ Failed: %v\n", err)
		return 2
	}
	pubKeyHex := hex.EncodeToString(signer.PublicKeyBytes())
	fmt.Fprintf(stdout, "%s✓%s Ed25519 %s...%s\n", ColorGreen, ColorReset, pubKeyHex[:16], pubKeyHex[len(pubKeyHex)-8:])

	fmt.Fprintf(stdout, "%s[4/5]%s Writing configuration...    ", ColorBold, ColorReset)
	if _, err := os.Stat("helm.yaml"); os.IsNotExist(err) {
		config := `# HELM Configuration — generated by 'helm-ai-kernel onboard'
version: "0.2"
kernel:
  profile: CORE
  store: sqlite
  data_dir: ` + strconv.Quote(dataDir) + `
trust:
  root_public_key: "` + pubKeyHex + `"
`
		if err := os.WriteFile("helm.yaml", []byte(config), 0600); err != nil {
			fmt.Fprintf(stderr, "\n❌ Failed: %v\n", err)
			return 2
		}
		fmt.Fprintf(stdout, "%s✓%s helm.yaml\n", ColorGreen, ColorReset)
	} else {
		fmt.Fprintf(stdout, "%s✓%s helm.yaml (exists)\n", ColorGreen, ColorReset)
	}

	fmt.Fprintf(stdout, "%s[5/5]%s Detecting agent surface...  ", ColorBold, ColorReset)
	report, scanErr := shadow.NewScanner().Scan(".")
	if scanErr != nil {
		fmt.Fprintf(stdout, "%sskipped (%v)%s\n", ColorYellow, scanErr, ColorReset)
	} else {
		fmt.Fprintf(stdout, "%s✓%s grade %s — %s\n", ColorGreen, ColorReset, report.Grade.Letter, report.Grade.Reason)
	}

	fmt.Fprintf(stdout, "\n%s────────────────────────────────────────────────%s\n", ColorCyan, ColorReset)
	fmt.Fprintf(stdout, "%s✅ HELM is ready.%s\n\n", ColorBold+ColorGreen, ColorReset)
	fmt.Fprintf(stdout, "%sNext steps:%s\n\n", ColorBold, ColorReset)
	fmt.Fprintf(stdout, "  %s1.%s Continue with the guided local proof:\n", ColorBold+ColorCyan, ColorReset)
	fmt.Fprintf(stdout, "     %shelm-ai-kernel setup --quickstart --profile mcp --yes%s\n\n", ColorBold, ColorReset)
	fmt.Fprintf(stdout, "%sDocs:%s https://github.com/Mindburn-Labs/helm-ai-kernel\n\n", ColorGray, ColorReset)

	return 0
}

func printOnboardUsage(w io.Writer) {
	fmt.Fprintln(w, "Deprecated: `onboard` preserves only the legacy explicit script contract.")
	fmt.Fprintln(w, "Use: helm-ai-kernel setup --quickstart --profile <claude|codex|mcp|openai-compatible> --yes")
	fmt.Fprintln(w, "Existing scripts can keep: helm-ai-kernel onboard --yes [--data-dir DIR]")
}

func init() {
	Register(Subcommand{
		Name:   "onboard",
		Usage:  "Deprecated legacy setup compatibility (explicit --yes scripts)",
		RunFn:  runOnboardCmd,
		HelpFn: printOnboardUsage,
	})
}
