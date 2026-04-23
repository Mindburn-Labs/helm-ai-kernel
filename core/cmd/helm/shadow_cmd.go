package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"strings"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/shadow"
)

// runShadowCmd implements `helm shadow` — shadow-AI discovery scanner.
//
// Exit codes:
//
//	0 = clean scan, no MEDIUM+ findings
//	1 = findings at or above fail-on-severity threshold
//	2 = config error
func runShadowCmd(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "Usage: helm shadow <scan> [flags]")
		fmt.Fprintln(stderr, "")
		fmt.Fprintln(stderr, "Subcommands:")
		fmt.Fprintln(stderr, "  scan    Static scan of a directory for agent SDK imports, MCP configs, and API keys")
		return 2
	}
	switch args[0] {
	case "scan":
		return runShadowScan(args[1:], stdout, stderr)
	case "--help", "-h":
		fmt.Fprintln(stdout, "Usage: helm shadow <scan> [flags]")
		fmt.Fprintln(stdout, "")
		fmt.Fprintln(stdout, "Subcommands:")
		fmt.Fprintln(stdout, "  scan    Static scan of a directory for agent SDK imports, MCP configs, and API keys")
		return 0
	default:
		fmt.Fprintf(stderr, "Unknown shadow subcommand: %s\n", args[0])
		return 2
	}
}

func runShadowScan(args []string, stdout, stderr io.Writer) int {
	cmd := flag.NewFlagSet("shadow scan", flag.ContinueOnError)
	cmd.SetOutput(stderr)

	var (
		path    string
		jsonOut bool
		failOn  string
	)

	cmd.StringVar(&path, "path", ".", "Directory to scan (default: current directory)")
	cmd.BoolVar(&jsonOut, "json", false, "Emit JSON report to stdout")
	cmd.StringVar(&failOn, "fail-on-severity", "medium", "Exit 1 if any finding is >= this severity (info|low|medium|high)")

	if err := cmd.Parse(args); err != nil {
		return 2
	}

	thresholdRank, ok := shadowSeverityRank(strings.ToUpper(failOn))
	if !ok {
		fmt.Fprintf(stderr, "Error: --fail-on-severity must be one of info, low, medium, high (got %q)\n", failOn)
		return 2
	}

	scanner := shadow.NewScanner()
	report, err := scanner.Scan(path)
	if err != nil {
		fmt.Fprintf(stderr, "Error scanning %q: %v\n", path, err)
		return 2
	}

	exitCode := 0
	for _, f := range report.Findings {
		if r, ok := shadowSeverityRank(f.Severity); ok && r >= thresholdRank {
			exitCode = 1
			break
		}
	}

	if jsonOut {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(report)
		return exitCode
	}

	writeShadowReport(stdout, report, exitCode)
	return exitCode
}

func shadowSeverityRank(s string) (int, bool) {
	switch strings.ToUpper(s) {
	case "INFO":
		return 1, true
	case "LOW":
		return 2, true
	case "MEDIUM":
		return 3, true
	case "HIGH":
		return 4, true
	}
	return 0, false
}

func writeShadowReport(w io.Writer, r *shadow.Report, exitCode int) {
	fmt.Fprintf(w, "\n%sShadow-AI Scan Report%s\n", ColorBold+ColorBlue, ColorReset)
	fmt.Fprintf(w, "  Root:          %s\n", r.ScanRoot)
	fmt.Fprintf(w, "  Files scanned: %d\n", r.FilesScanned)
	fmt.Fprintf(w, "  Files skipped: %d\n", r.FilesSkipped)
	fmt.Fprintf(w, "  Duration:      %dms\n", r.ScanDurationMs)
	fmt.Fprintf(w, "  Findings:      %d\n", len(r.Findings))

	if r.HelmCoverage.Present {
		fmt.Fprintf(w, "  %sHELM: present (%d marker(s))%s\n", ColorGreen, r.HelmCoverage.Count, ColorReset)
	} else {
		fmt.Fprintf(w, "  %sHELM: NOT DETECTED in scanned tree%s\n", ColorYellow, ColorReset)
	}
	fmt.Fprintln(w)

	if len(r.Findings) == 0 {
		fmt.Fprintf(w, "%sNo agent SDK or MCP signals detected.%s\n\n", ColorGreen, ColorReset)
		return
	}

	// Group by vendor for readability
	byVendor := map[string][]shadow.Finding{}
	for _, f := range r.Findings {
		byVendor[f.Vendor] = append(byVendor[f.Vendor], f)
	}

	fmt.Fprintf(w, "%sFindings by vendor%s\n", ColorBold, ColorReset)
	for vendor, count := range r.SummaryByVendor {
		color := ColorReset
		switch vendor {
		case "helm":
			color = ColorGreen
		case "agent-os":
			color = ColorYellow
		}
		fmt.Fprintf(w, "  %s%-20s%s %d\n", color, vendor, ColorReset, count)
	}
	fmt.Fprintln(w)

	fmt.Fprintf(w, "%sFindings by severity%s\n", ColorBold, ColorReset)
	for _, sev := range []string{"HIGH", "MEDIUM", "LOW", "INFO"} {
		if n, ok := r.SummaryBySeverity[sev]; ok && n > 0 {
			fmt.Fprintf(w, "  %-10s %d\n", sev, n)
		}
	}
	fmt.Fprintln(w)

	// Show MEDIUM+ findings inline
	showed := 0
	for _, f := range r.Findings {
		if r, _ := shadowSeverityRank(f.Severity); r < 3 {
			continue
		}
		if showed == 0 {
			fmt.Fprintf(w, "%sMedium+ findings%s\n", ColorBold, ColorReset)
		}
		showed++
		fmt.Fprintf(w, "  [%s] %s :: %s :: %s:%d\n", f.Severity, f.Vendor, f.Kind, f.Path, f.Line)
		if f.Note != "" {
			fmt.Fprintf(w, "         %s\n", f.Note)
		}
	}
	if showed > 0 {
		fmt.Fprintln(w)
	}

	if exitCode != 0 {
		fmt.Fprintf(w, "%sFindings at or above fail-on-severity threshold — exit 1%s\n\n", ColorYellow, ColorReset)
	}
}

func init() {
	Register(Subcommand{
		Name:    "shadow",
		Aliases: []string{},
		Usage:   "Static scan for shadow-AI: agent SDKs, MCP configs, API keys",
		RunFn:   runShadowCmd,
	})
}
