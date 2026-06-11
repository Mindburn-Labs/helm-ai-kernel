package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

// runCounterfactualCmd implements `helm-ai-kernel counterfactual` — the
// negative-space surface of the observe on-ramp. It folds a stream of signed
// counterfactual receipts (the verdicts the PDP WOULD have issued under an
// observe grant) into a deterministic summary: "HELM would have blocked these N
// actions", broken down by policy epoch, tool, MCP server, and reason code.
//
// Exit codes:
//
//	0 = success, no would-have blocks
//	1 = success, but counterfactual DENY/ESCALATE blocks were found
//	2 = config error
func runCounterfactualCmd(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		counterfactualUsage(stderr)
		return 2
	}
	switch args[0] {
	case "summary":
		return runCounterfactualSummary(args[1:], stdout, stderr)
	case "--help", "-h", "help":
		counterfactualUsage(stdout)
		return 0
	default:
		fmt.Fprintf(stderr, "Unknown counterfactual subcommand: %s\n\n", args[0])
		counterfactualUsage(stderr)
		return 2
	}
}

func counterfactualUsage(w io.Writer) {
	fmt.Fprintln(w, "Usage: helm-ai-kernel counterfactual summary [flags]")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "Aggregate signed counterfactual receipts from an observe grant into a")
	fmt.Fprintln(w, "deterministic would-have summary. Counterfactual receipts carry the verdict")
	fmt.Fprintln(w, "the PDP would have issued; they confer no execution authority.")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "Flags:")
	fmt.Fprintln(w, "  -in    Path to counterfactual receipts (JSON array or JSONL). '-' reads stdin.")
	fmt.Fprintln(w, "  -json  Emit the summary as JSON instead of the text report.")
}

// loadCounterfactualReceipts parses either a JSON array of receipts or a
// newline-delimited (JSONL) stream. Each receipt must validate as
// counterfactual — an enforced receipt in the stream is a hard error, never
// silently folded into the would-have narrative.
func loadCounterfactualReceipts(r io.Reader) ([]contracts.CounterfactualReceipt, error) {
	raw, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return nil, fmt.Errorf("no counterfactual receipts provided")
	}

	var receipts []contracts.CounterfactualReceipt
	if trimmed[0] == '[' {
		if err := json.Unmarshal(trimmed, &receipts); err != nil {
			return nil, fmt.Errorf("parse JSON array: %w", err)
		}
	} else {
		scanner := bufio.NewScanner(bytes.NewReader(trimmed))
		scanner.Buffer(make([]byte, 0, 1024*1024), 16*1024*1024)
		line := 0
		for scanner.Scan() {
			line++
			text := bytes.TrimSpace(scanner.Bytes())
			if len(text) == 0 {
				continue
			}
			var receipt contracts.CounterfactualReceipt
			if err := json.Unmarshal(text, &receipt); err != nil {
				return nil, fmt.Errorf("parse JSONL line %d: %w", line, err)
			}
			receipts = append(receipts, receipt)
		}
		if err := scanner.Err(); err != nil {
			return nil, err
		}
	}

	for i := range receipts {
		if err := receipts[i].Validate(); err != nil {
			return nil, fmt.Errorf("receipt %d failed counterfactual validation: %w", i, err)
		}
	}
	return receipts, nil
}

func runCounterfactualSummary(args []string, stdout, stderr io.Writer) int {
	cmd := flag.NewFlagSet("counterfactual summary", flag.ContinueOnError)
	cmd.SetOutput(stderr)
	var (
		in     string
		asJSON bool
	)
	cmd.StringVar(&in, "in", "-", "Path to counterfactual receipts (JSON array or JSONL); '-' for stdin")
	cmd.BoolVar(&asJSON, "json", false, "Emit summary as JSON")
	if err := cmd.Parse(args); err != nil {
		return 2
	}

	var reader io.Reader
	if in == "-" {
		reader = os.Stdin
	} else {
		f, err := os.Open(in)
		if err != nil {
			fmt.Fprintf(stderr, "Error opening %q: %v\n", in, err)
			return 2
		}
		defer f.Close()
		reader = f
	}

	return runCounterfactualSummaryFromReader(reader, stdout, stderr, asJSON)
}

// runCounterfactualSummaryFromReader is the I/O-free core of the summary
// command: it loads receipts from r, folds them, and writes the report. Split
// out so the deterministic summary path is testable without touching the
// filesystem.
func runCounterfactualSummaryFromReader(r io.Reader, stdout, stderr io.Writer, asJSON bool) int {
	receipts, err := loadCounterfactualReceipts(r)
	if err != nil {
		fmt.Fprintf(stderr, "Error: %v\n", err)
		return 2
	}

	// Deterministic generated_at: use the latest receipt timestamp, not wall
	// clock, so the same receipt stream produces byte-identical output.
	generatedAt := time.Time{}
	for _, r := range receipts {
		if r.CreatedAt.After(generatedAt) {
			generatedAt = r.CreatedAt
		}
	}

	summary, err := contracts.SummarizeCounterfactuals(receipts, generatedAt)
	if err != nil {
		fmt.Fprintf(stderr, "Error: %v\n", err)
		return 2
	}

	if asJSON {
		data, err := json.MarshalIndent(summary, "", "  ")
		if err != nil {
			fmt.Fprintf(stderr, "Error encoding summary: %v\n", err)
			return 2
		}
		fmt.Fprintln(stdout, string(data))
	} else {
		printCounterfactualSummary(stdout, summary)
	}

	if summary.WouldDeny > 0 || summary.WouldEscalate > 0 {
		return 1
	}
	return 0
}

func printCounterfactualSummary(w io.Writer, s contracts.CounterfactualSummary) {
	fmt.Fprintf(w, "\n%sCounterfactual Summary (observe mode)%s\n", ColorBold+ColorBlue, ColorReset)
	fmt.Fprintf(w, "  Observe grant:    %s\n", s.ObserveGrantID)
	fmt.Fprintf(w, "  Evaluated:        %d action(s)\n", s.TotalEvaluated)
	fmt.Fprintf(w, "  Would ALLOW:      %d\n", s.WouldAllow)
	fmt.Fprintf(w, "  %sWould DENY:       %d%s\n", ColorRed, s.WouldDeny, ColorReset)
	fmt.Fprintf(w, "  %sWould ESCALATE:   %d%s\n", ColorYellow, s.WouldEscalate, ColorReset)

	printCounterfactualDimension(w, "By policy epoch", s.ByPolicyEpoch)
	printCounterfactualDimension(w, "By tool", s.ByTool)
	printCounterfactualDimension(w, "By MCP server", s.ByMCPServer)
	printCounterfactualDimension(w, "By reason code", s.ByReasonCode)

	if s.WouldDeny == 0 && s.WouldEscalate == 0 {
		fmt.Fprintf(w, "\nNo would-have blocks in this window.\n\n")
		return
	}
	fmt.Fprintf(w, "\n%sHELM would have blocked %d action(s) under enforce mode.%s\n\n",
		ColorBold, s.WouldDeny+s.WouldEscalate, ColorReset)
}

func printCounterfactualDimension(w io.Writer, title string, entries []contracts.CounterfactualCountEntry) {
	if len(entries) == 0 {
		return
	}
	fmt.Fprintf(w, "\n  %s%s%s\n", ColorBold, title, ColorReset)
	for _, e := range entries {
		key := e.Key
		if key == "" {
			key = "(unattributed)"
		}
		fmt.Fprintf(w, "    %-40s deny=%d escalate=%d\n", truncateKey(key, 40), e.Deny, e.Escalate)
	}
}

func truncateKey(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-1] + "…"
}

func init() {
	Register(Subcommand{
		Name:    "counterfactual",
		Aliases: []string{"cf"},
		Usage:   "Summarize observe-mode counterfactual receipts (would-have DENY/ESCALATE by policy/tool/MCP server)",
		RunFn:   runCounterfactualCmd,
	})
}
