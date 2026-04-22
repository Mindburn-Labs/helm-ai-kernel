package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/conform/adversarial"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/threatscan"
)

// runThreatCmd handles `helm threat scan` and `helm threat test` subcommands.
func runThreatCmd(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "Usage: helm threat <scan|test> [flags]")
		return 2
	}

	switch args[0] {
	case "scan":
		return runThreatScan(args[1:], stdout, stderr)
	case "test":
		return runThreatTest(args[1:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "Unknown threat subcommand: %s\n", args[0])
		fmt.Fprintln(stderr, "Usage: helm threat <scan|test> [flags]")
		return 2
	}
}

// runThreatScan scans text from --text or, if omitted, from stdin.
func runThreatScan(args []string, stdout, stderr io.Writer) int {
	cmd := flag.NewFlagSet("threat scan", flag.ContinueOnError)
	cmd.SetOutput(stderr)

	var (
		text       string
		channel    string
		trust      string
		jsonOutput bool
	)

	cmd.StringVar(&text, "text", "", "Text to scan (REQUIRED)")
	cmd.StringVar(&channel, "channel", "UNKNOWN", "Source channel (e.g. GITHUB_ISSUE, CHAT_USER)")
	cmd.StringVar(&trust, "trust", "EXTERNAL_UNTRUSTED", "Trust level (TRUSTED, INTERNAL_UNVERIFIED, EXTERNAL_UNTRUSTED, TAINTED)")
	cmd.BoolVar(&jsonOutput, "json", false, "Output result as JSON")

	if err := cmd.Parse(args); err != nil {
		return 2
	}

	if text == "" {
		data, err := io.ReadAll(os.Stdin)
		if err != nil {
			fmt.Fprintf(stderr, "Error: failed to read stdin: %v\n", err)
			return 2
		}
		text = strings.TrimSpace(string(data))
	}

	if text == "" {
		fmt.Fprintln(stderr, "Error: provide --text or stdin input")
		cmd.Usage()
		return 2
	}

	scanner := threatscan.New()
	result := scanner.ScanInput(text, contracts.SourceChannel(channel), contracts.InputTrustLevel(trust))

	if jsonOutput {
		data, _ := json.MarshalIndent(result, "", "  ")
		fmt.Fprintln(stdout, string(data))
	} else {
		if result.FindingCount == 0 {
			fmt.Fprintf(stdout, "%s✅ Clean%s — no threat signals detected\n", ColorGreen, ColorReset)
			fmt.Fprintf(stdout, "   Source:  %s (trust=%s)\n", result.SourceChannel, result.TrustLevel)
			fmt.Fprintf(stdout, "   Hash:    %s\n", result.RawInputHash)
		} else {
			fmt.Fprintf(stdout, "%s⚠️  %d threat signal(s) detected%s (max severity: %s%s%s)\n",
				ColorYellow, result.FindingCount, ColorReset,
				severityColor(result.MaxSeverity), result.MaxSeverity, ColorReset)
			fmt.Fprintf(stdout, "   Source:  %s (trust=%s)\n", result.SourceChannel, result.TrustLevel)
			fmt.Fprintf(stdout, "   Hash:    %s\n", result.RawInputHash)

			if result.Normalization != nil && result.Normalization.ZeroWidthsRemoved > 0 {
				fmt.Fprintf(stdout, "   Unicode: %d zero-width chars removed\n", result.Normalization.ZeroWidthsRemoved)
			}

			fmt.Fprintln(stdout)
			for i, f := range result.Findings {
				fmt.Fprintf(stdout, "  %s[%d]%s %s%s%s — %s\n",
					ColorBold, i+1, ColorReset,
					severityColor(f.Severity), f.Severity, ColorReset,
					f.Class)
				fmt.Fprintf(stdout, "       Rule:  %s\n", f.RuleID)
				if f.Notes != "" {
					fmt.Fprintf(stdout, "       Notes: %s\n", f.Notes)
				}
				if len(f.MatchedTokens) > 0 {
					fmt.Fprintf(stdout, "       Match: %s\n", strings.Join(f.MatchedTokens, ", "))
				}
			}
		}
	}

	return 0
}

// runThreatTest runs the adversarial test suite.
func runThreatTest(args []string, stdout, stderr io.Writer) int {
	cmd := flag.NewFlagSet("threat test", flag.ContinueOnError)
	cmd.SetOutput(stderr)

	var jsonOutput bool
	cmd.BoolVar(&jsonOutput, "json", false, "Output results as JSON")

	if err := cmd.Parse(args); err != nil {
		return 2
	}

	scanner := threatscan.New()
	results := adversarial.RunThreatScannerSuite(scanner)

	passed := 0
	failed := 0
	for _, r := range results {
		if r.Passed {
			passed++
		} else {
			failed++
		}
	}

	if jsonOutput {
		output := map[string]any{
			"total":   len(results),
			"passed":  passed,
			"failed":  failed,
			"results": results,
		}
		data, _ := json.MarshalIndent(output, "", "  ")
		fmt.Fprintln(stdout, string(data))
	} else {
		fmt.Fprintf(stdout, "\n%sThreat Scanner Adversarial Suite%s\n\n", ColorBold, ColorReset)
		for _, r := range results {
			if r.Passed {
				fmt.Fprintf(stdout, "  %s✅ PASS%s  %s\n", ColorGreen, ColorReset, r.Name)
			} else {
				fmt.Fprintf(stdout, "  %s❌ FAIL%s  %s — %s\n", ColorRed, ColorReset, r.Name, r.Reason)
			}
			fmt.Fprintf(stdout, "          %s\n", r.Summary)
		}
		fmt.Fprintln(stdout)
		fmt.Fprintf(stdout, "  %sTotal: %d  Passed: %d  Failed: %d%s\n", ColorBold, len(results), passed, failed, ColorReset)

		if failed > 0 {
			fmt.Fprintf(stdout, "\n  %s%d scenario(s) failed%s\n", ColorRed, failed, ColorReset)
		} else {
			fmt.Fprintf(stdout, "\n  %sAll scenarios passed ✓%s\n", ColorGreen, ColorReset)
		}
		fmt.Fprintln(stdout)
	}

	if failed > 0 {
		return 1
	}
	return 0
}

// severityColor returns ANSI color for severity level.
func severityColor(sev contracts.ThreatSeverity) string {
	switch sev {
	case contracts.ThreatSeverityCritical:
		return ColorRed + ColorBold
	case contracts.ThreatSeverityHigh:
		return ColorRed
	case contracts.ThreatSeverityMedium:
		return ColorYellow
	case contracts.ThreatSeverityLow:
		return ColorCyan
	default:
		return ColorGray
	}
}
