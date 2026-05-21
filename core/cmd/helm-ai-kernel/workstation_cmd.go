package main

import (
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/workstation"
)

func runWorkstationCmd(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		_, _ = fmt.Fprintln(stderr, "Usage: helm-ai-kernel workstation <import|view> [flags]")
		return 2
	}
	switch args[0] {
	case "import":
		return runWorkstationImportCmd(args[1:], stdout, stderr)
	case "view":
		return runWorkstationViewCmd(args[1:], stdout, stderr)
	case "decide":
		return runWorkstationDecisionCmd(args[1:], stdout, stderr)
	case "enforce":
		return runWorkstationEnforceCmd(args[1:], stdout, stderr)
	case "operator":
		return runWorkstationOperatorCmd("all", args[1:], stdout, stderr)
	case "list":
		return runWorkstationOperatorCmd("runs", args[1:], stdout, stderr)
	case "denied":
		return runWorkstationOperatorCmd("denied", args[1:], stdout, stderr)
	case "memory":
		return runWorkstationOperatorCmd("memory", args[1:], stdout, stderr)
	case "loops":
		return runWorkstationOperatorCmd("loops", args[1:], stdout, stderr)
	case "evidence":
		return runWorkstationEvidenceCmd(args[1:], stdout, stderr)
	case "certify":
		return runWorkstationCertifyCmd(args[1:], stdout, stderr)
	case "capture":
		return runWorkstationCaptureCmd(args[1:], stdout, stderr)
	default:
		_, _ = fmt.Fprintf(stderr, "Unknown workstation command: %s\n", args[0])
		_, _ = fmt.Fprintln(stderr, "Usage: helm-ai-kernel workstation <import|view|decide|enforce|operator|list|denied|memory|loops|evidence|certify|capture> [flags]")
		return 2
	}
}

func runWorkstationImportCmd(args []string, stdout, stderr io.Writer) int {
	cmd := flag.NewFlagSet("workstation import", flag.ContinueOnError)
	cmd.SetOutput(stderr)

	var (
		artifacts string
		out       string
		jsonOut   bool
		seedHex   string
	)
	cmd.StringVar(&artifacts, "artifacts", "", "Artifact directory containing run.manifest.json")
	cmd.StringVar(&out, "out", "", "Write canonical import result JSON to this path")
	cmd.BoolVar(&jsonOut, "json", false, "Print canonical import result JSON")
	cmd.StringVar(&seedHex, "signing-seed-hex", "", "Optional 32-byte Ed25519 seed as hex")

	if err := cmd.Parse(args); err != nil {
		return 2
	}
	if artifacts == "" {
		_, _ = fmt.Fprintln(stderr, "Error: --artifacts is required")
		return 2
	}
	seed, err := parseSigningSeed(seedHex)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: %v\n", err)
		return 2
	}
	result, err := workstation.ImportArtifactDir(artifacts, workstation.ImportOptions{SigningSeed: seed})
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: workstation import failed: %v\n", err)
		return 1
	}
	if out != "" {
		data, err := canonicalize.JCS(result)
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "Error: canonicalize result: %v\n", err)
			return 1
		}
		if err := os.WriteFile(out, append(data, '\n'), 0o600); err != nil {
			_, _ = fmt.Fprintf(stderr, "Error: write %s: %v\n", out, err)
			return 1
		}
	}
	if jsonOut {
		data, _ := canonicalize.JCS(result)
		_, _ = fmt.Fprintln(stdout, string(data))
		return 0
	}
	printWorkstationSummary(stdout, workstation.Summary(result.Receipt))
	if out != "" {
		_, _ = fmt.Fprintf(stdout, "Output: %s\n", out)
	}
	return 0
}

func runWorkstationViewCmd(args []string, stdout, stderr io.Writer) int {
	cmd := flag.NewFlagSet("workstation view", flag.ContinueOnError)
	cmd.SetOutput(stderr)

	var (
		receiptPath string
		jsonOut     bool
	)
	cmd.StringVar(&receiptPath, "receipt", "", "Agent Run Receipt or workstation import result JSON")
	cmd.BoolVar(&jsonOut, "json", false, "Print summary JSON")

	if err := cmd.Parse(args); err != nil {
		return 2
	}
	if receiptPath == "" {
		_, _ = fmt.Fprintln(stderr, "Error: --receipt is required")
		return 2
	}
	result, err := workstation.LoadResult(receiptPath)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: cannot read receipt: %v\n", err)
		return 1
	}
	ok, err := workstation.VerifyReceiptSignature(result.Receipt)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: receipt signature check failed: %v\n", err)
		return 1
	}
	summary := workstation.Summary(result.Receipt)
	summary["signature_valid"] = ok
	if result.ReplayRootHash != "" {
		summary["replay_root_hash"] = result.ReplayRootHash
	}
	if jsonOut {
		data, _ := json.MarshalIndent(summary, "", "  ")
		_, _ = fmt.Fprintln(stdout, string(data))
		return 0
	}
	printWorkstationSummary(stdout, summary)
	return 0
}

func parseSigningSeed(seedHex string) ([]byte, error) {
	if strings.TrimSpace(seedHex) == "" {
		return nil, nil
	}
	seed, err := hex.DecodeString(seedHex)
	if err != nil {
		return nil, fmt.Errorf("--signing-seed-hex must be hex: %w", err)
	}
	if len(seed) != 32 {
		return nil, fmt.Errorf("--signing-seed-hex must decode to 32 bytes")
	}
	return seed, nil
}

func printWorkstationSummary(stdout io.Writer, summary map[string]any) {
	_, _ = fmt.Fprintf(stdout, "%sAgent Run Receipt%s\n", ColorBold, ColorReset)
	_, _ = fmt.Fprintf(stdout, "  receipt:       %v\n", summary["receipt_id"])
	_, _ = fmt.Fprintf(stdout, "  run:           %v\n", summary["run_id"])
	_, _ = fmt.Fprintf(stdout, "  goal:          %v\n", summary["goal"])
	_, _ = fmt.Fprintf(stdout, "  surface:       %v\n", summary["agent_surface"])
	_, _ = fmt.Fprintf(stdout, "  policy:        %v\n", summary["policy_profile"])
	_, _ = fmt.Fprintf(stdout, "  tools:         %v\n", summary["tool_actions"])
	_, _ = fmt.Fprintf(stdout, "  changed files: %v\n", summary["changed_files"])
	_, _ = fmt.Fprintf(stdout, "  validations:   %v\n", summary["validation_count"])
	_, _ = fmt.Fprintf(stdout, "  memory writes: %v\n", summary["memory_effects"])
	_, _ = fmt.Fprintf(stdout, "  loops:         %v\n", summary["recurring_loops"])
	_, _ = fmt.Fprintf(stdout, "  denied:        %v\n", summary["denied_effects"])
	_, _ = fmt.Fprintf(stdout, "  receipt hash:  %v\n", summary["receipt_hash"])
	if signatureValid, ok := summary["signature_valid"]; ok {
		_, _ = fmt.Fprintf(stdout, "  signature:     %v\n", signatureValid)
	}
}

func init() {
	Register(Subcommand{
		Name:    "workstation",
		Aliases: []string{},
		Usage:   "Import and view observe-only workstation Agent Run Receipts",
		RunFn:   runWorkstationCmd,
	})
}
