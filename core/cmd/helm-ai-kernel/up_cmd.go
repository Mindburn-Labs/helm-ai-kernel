package main

import (
	"flag"
	"fmt"
	"io"
	"strings"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/launchkit"
	lpregistry "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/launchpad/registry"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/launchpad/session"
)

func init() {
	Register(Subcommand{Name: "up", Usage: "Launch an AppSpec through HELM LaunchKit", RunFn: runUpCmd})
}

func runUpCmd(args []string, stdout, stderr io.Writer) int {
	opts, jsonOut, code := parseUpArgs(args, stderr)
	if code != 0 {
		return code
	}
	catalog, err := lpregistry.LoadCatalog(opts.CatalogRoot)
	if err != nil {
		fmt.Fprintf(stderr, "launchkit registry error: %v\n", err)
		return 1
	}
	if err := catalog.Validate(); err != nil {
		fmt.Fprintf(stderr, "launchkit validation error: %v\n", err)
		return 1
	}
	store := session.NewStore(opts.StoreRoot)
	orchestrator := launchkit.New(catalog, store)
	result, err := orchestrator.Up(opts)
	if err != nil {
		fmt.Fprintf(stderr, "helm up error: %v\n", err)
		if jsonOut {
			return writeLaunchJSON(stdout, result)
		}
		return 1
	}
	if jsonOut {
		return writeLaunchJSON(stdout, result)
	}
	printUpSummary(stdout, result)
	if result.Run != nil && result.Run.KernelVerdict == "ALLOW" {
		return 0
	}
	if result.VerifyOnly && result.Plan != nil && result.Plan.KernelVerdict == "ALLOW" {
		return 0
	}
	return 1
}

func parseUpArgs(args []string, stderr io.Writer) (launchkit.Options, bool, int) {
	var opts launchkit.Options
	var jsonOut bool
	var modeSet bool
	fs := flag.NewFlagSet("up", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprintln(stderr, "Usage: helm up <app> [--target local|cloud|cloud:helm|cloud:aws|cloud:kubernetes] [--demo|--verify-only|--live] [--resume <run_id>] [--yes] [--json]")
	}
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch arg {
		case "--target":
			if i+1 >= len(args) {
				fs.Usage()
				return opts, false, 2
			}
			opts.Target = launchkit.NormalizeTarget(args[i+1])
			i++
		case "--demo":
			if modeSet {
				fmt.Fprintln(stderr, "choose only one of --demo, --verify-only, or --live")
				return opts, false, 2
			}
			opts.Mode = launchkit.ModeDemo
			modeSet = true
		case "--verify-only":
			if modeSet {
				fmt.Fprintln(stderr, "choose only one of --demo, --verify-only, or --live")
				return opts, false, 2
			}
			opts.Mode = launchkit.ModeVerifyOnly
			modeSet = true
		case "--live":
			if modeSet {
				fmt.Fprintln(stderr, "choose only one of --demo, --verify-only, or --live")
				return opts, false, 2
			}
			opts.Mode = launchkit.ModeLive
			modeSet = true
		case "--resume":
			if i+1 >= len(args) {
				fs.Usage()
				return opts, false, 2
			}
			opts.ResumeRunID = args[i+1]
			i++
		case "--yes", "-y":
			opts.Yes = true
		case "--json":
			jsonOut = true
		case "--help", "-h":
			fs.Usage()
			return opts, false, 0
		default:
			if strings.HasPrefix(arg, "-") {
				fmt.Fprintf(stderr, "unknown helm up flag: %s\n", arg)
				return opts, false, 2
			}
			if opts.AppID != "" {
				fmt.Fprintf(stderr, "unexpected extra argument: %s\n", arg)
				return opts, false, 2
			}
			opts.AppID = arg
		}
	}
	if opts.AppID == "" && opts.ResumeRunID != "" {
		run, err := session.NewStore(opts.StoreRoot).Get(opts.ResumeRunID)
		if err == nil {
			opts.AppID = run.AppID
		}
	}
	if opts.AppID == "" {
		fs.Usage()
		return opts, false, 2
	}
	if opts.Target == "" {
		opts.Target = launchkit.TargetLocal
	}
	if opts.Mode == "" {
		opts.Mode = launchkit.ModeAuto
	}
	return opts, jsonOut, 0
}

func printUpSummary(stdout io.Writer, result launchkit.Result) {
	appName := result.AppID
	fmt.Fprintf(stdout, "HELM launching %s\n\n", appName)
	for _, gate := range result.Gates {
		marker := "[..]"
		switch gate.Status {
		case launchkit.GateAllow:
			marker = "[OK]"
		case launchkit.GateDeny:
			marker = "[DENY]"
		case launchkit.GateEscalate:
			marker = "[ESC]"
		case launchkit.GateSkipped:
			marker = "[SKIP]"
		}
		if gate.Status == launchkit.GatePending {
			continue
		}
		line := gate.Label
		if gate.ReasonCode != "" {
			line += " (" + gate.ReasonCode + ")"
		}
		fmt.Fprintf(stdout, "%s %s\n", marker, line)
	}
	if result.Run != nil && result.Run.KernelVerdict != "ALLOW" {
		fmt.Fprintf(stdout, "\nHELM %s: %s\n", result.Run.KernelVerdict, firstNonEmpty(result.Run.ReasonCode, string(result.Run.State)))
		fmt.Fprintln(stdout, "No container was started.")
		fmt.Fprintln(stdout, "No MCP tools were granted.")
		fmt.Fprintln(stdout, "No side effects were dispatched.")
	}
	if result.Run != nil && result.Run.KernelVerdict == "ALLOW" {
		fmt.Fprintf(stdout, "\nStatus: %s\n", result.Run.State)
	}
	if result.OfflineVerifyCommand != "" {
		fmt.Fprintf(stdout, "\nVerify offline:\n%s\n", result.OfflineVerifyCommand)
	}
	if result.Run != nil && result.Run.KernelVerdict != "ALLOW" && result.ResumeCommand != "" {
		fmt.Fprintf(stdout, "\nResume:\n%s\n", result.ResumeCommand)
	}
	if result.VerifyOnly && result.Plan != nil {
		fmt.Fprintf(stdout, "\nVerify-only completed with verdict %s.\n", result.Plan.KernelVerdict)
	}
}
