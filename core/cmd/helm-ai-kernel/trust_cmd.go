package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/trust"
)

// runTrustCmd implements `helm-ai-kernel trust <subcommand>`.
//
// Currently supports:
//
//	helm-ai-kernel trust eu-list status [--json] [--fixture path] [--offline]
//
// Future trust subcommands (TUF root, SLSA roots, TEE PCRs) will register
// here using the same dispatch shape.
func runTrustCmd(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "Usage: helm-ai-kernel trust <subcommand> [flags]")
		fmt.Fprintln(stderr, "")
		fmt.Fprintln(stderr, "Subcommands:")
		fmt.Fprintln(stderr, "  eu-list status   Print EU LOTL refresh state, signer, and qualified-TSA count")
		return 2
	}

	switch args[0] {
	case "eu-list":
		return runTrustEUList(args[1:], stdout, stderr)
	case "--help", "-h", "help":
		fmt.Fprintln(stdout, "Usage: helm-ai-kernel trust <subcommand> [flags]")
		fmt.Fprintln(stdout, "  eu-list status   Print EU LOTL state (last refresh, signer, qualified-TSA count)")
		return 0
	default:
		fmt.Fprintf(stderr, "Unknown trust subcommand: %s\n", args[0])
		return 2
	}
}

func runTrustEUList(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "Usage: helm-ai-kernel trust eu-list <status>")
		return 2
	}
	switch args[0] {
	case "status":
		return runTrustEUListStatus(args[1:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "Unknown eu-list subcommand: %s\n", args[0])
		return 2
	}
}

func runTrustEUListStatus(args []string, stdout, stderr io.Writer) int {
	cmd := flag.NewFlagSet("trust eu-list status", flag.ContinueOnError)
	cmd.SetOutput(stderr)

	var (
		jsonOut    bool
		fixture    string
		offline    bool
		endpoint   string
		timeoutSec int
	)
	cmd.BoolVar(&jsonOut, "json", false, "Emit machine-readable JSON")
	cmd.StringVar(&fixture, "fixture", os.Getenv("HELM_LOTL_FIXTURE"), "Path to a local LOTL XML fixture (offline mode)")
	cmd.BoolVar(&offline, "offline", false, "Skip the network refresh and report only what is in the local cache")
	cmd.StringVar(&endpoint, "endpoint", "", "Override the LOTL endpoint URL")
	cmd.IntVar(&timeoutSec, "timeout", 30, "Seconds to wait for the LOTL fetch")

	if err := cmd.Parse(args); err != nil {
		return 2
	}

	cfg := trust.EUTrustedListConfig{}
	if endpoint != "" {
		cfg.Endpoint = endpoint
	}
	list := trust.NewEUTrustedListWithConfig(cfg)

	if fixture != "" {
		data, err := os.ReadFile(fixture)
		if err != nil {
			fmt.Fprintf(stderr, "Error: cannot read LOTL fixture %s: %v\n", fixture, err)
			return 2
		}
		if err := list.LoadFromBytes(data); err != nil {
			fmt.Fprintf(stderr, "Error: cannot parse LOTL fixture %s: %v\n", fixture, err)
			return 2
		}
	} else if !offline {
		ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeoutSec)*time.Second)
		defer cancel()
		if err := list.Refresh(ctx); err != nil {
			fmt.Fprintf(stderr, "Warning: LOTL refresh failed: %v\n", err)
			// Fall through and print what we have (likely an empty cache).
		}
	}

	st := list.Status()
	if jsonOut {
		out, _ := json.MarshalIndent(st, "", "  ")
		fmt.Fprintln(stdout, string(out))
		if st.QualifiedTSACount == 0 {
			return 1
		}
		return 0
	}

	fmt.Fprintf(stdout, "%sEU Trusted List status%s\n", ColorBold, ColorReset)
	fmt.Fprintf(stdout, "  endpoint:             %s\n", st.Endpoint)
	if st.LastRefresh.IsZero() {
		fmt.Fprintf(stdout, "  last refresh:         %s(never)%s\n", ColorRed, ColorReset)
	} else {
		fmt.Fprintf(stdout, "  last refresh:         %s\n", st.LastRefresh.Format(time.RFC3339))
		fmt.Fprintf(stdout, "  age:                  %s\n", st.Age.Truncate(time.Second))
	}
	fmt.Fprintf(stdout, "  scheme operator:      %s\n", fallbackString(st.SchemeOperator, "(unknown)"))
	fmt.Fprintf(stdout, "  qualified TSA count:  %d\n", st.QualifiedTSACount)
	fmt.Fprintf(stdout, "  member state count:   %d\n", st.MemberStateCount)
	if st.Stale {
		fmt.Fprintf(stdout, "  status:               %sSTALE%s\n", ColorRed, ColorReset)
	} else {
		fmt.Fprintf(stdout, "  status:               %sFRESH%s\n", ColorGreen, ColorReset)
	}

	if st.QualifiedTSACount == 0 {
		return 1
	}
	return 0
}

func fallbackString(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}

func init() {
	Register(Subcommand{
		Name:    "trust",
		Aliases: []string{},
		Usage:   "Inspect HELM trust roots (eu-list status)",
		RunFn:   runTrustCmd,
	})
}
