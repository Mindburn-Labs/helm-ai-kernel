package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/verifier/decisionreceipt"
)

// runVerifyDecisionReceiptCmd verifies an external decision receipt (or bundle)
// against HELM's neutral classification ladder. It never treats an external
// receipt as HELM-native execution proof: the classification is always printed.
//
// Usage: helm-ai-kernel verify decision-receipt <file> [--format <id>]
//
//	[--public-key <hex>] [--json]
func runVerifyDecisionReceiptCmd(args []string, stdout, stderr io.Writer) int {
	cmd := flag.NewFlagSet("verify decision-receipt", flag.ContinueOnError)
	cmd.SetOutput(stderr)
	var (
		file       string
		format     string
		publicKey  string
		jsonOutput bool
	)
	cmd.StringVar(&file, "file", "", "Path to the receipt/bundle JSON (or pass as a positional argument)")
	cmd.StringVar(&format, "format", "", "Format id (e.g. helm_external.v1); empty = auto-detect")
	cmd.StringVar(&publicKey, "public-key", "", "Trusted Ed25519 public key hex. Without it, a bundle-disclosed key caps the result at crypto_compatible_non_conformant")
	cmd.BoolVar(&jsonOutput, "json", false, "Output the DecisionReport as JSON")
	if err := cmd.Parse(reorderFlagsFirst(args)); err != nil {
		return 2
	}
	if file == "" && cmd.NArg() > 0 {
		file = cmd.Arg(0)
	}
	if file == "" {
		fmt.Fprintln(stderr, "Error: provide a receipt file (positional argument or --file)")
		return 2
	}
	raw, err := os.ReadFile(file)
	if err != nil {
		fmt.Fprintf(stderr, "Error: read %s: %v\n", file, err)
		return 2
	}

	report, err := decisionreceipt.Default().VerifyBundle(raw, format, publicKey)
	if err != nil {
		fmt.Fprintf(stderr, "Error: %v\n", err)
		return 2
	}

	if jsonOutput {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(report); err != nil {
			fmt.Fprintf(stderr, "Error: encode report: %v\n", err)
			return 2
		}
	} else {
		status := "NOT VERIFIED"
		if report.Verified {
			status = "VERIFIED"
		}
		fmt.Fprintf(stdout, "%s  %s  (%d receipt(s))  classification=%s\n", status, report.FormatID, report.ReceiptCount, report.Classification)
		if report.Classification == contracts.ClassCryptoCompatibleNonConformant {
			fmt.Fprintln(stdout, "  note: decision-level proof only — NOT HELM execution proof")
		}
		for _, c := range report.Checks {
			mark := "ok  "
			detail := c.Detail
			if !c.Pass {
				mark = "FAIL"
				detail = c.Reason
			}
			fmt.Fprintf(stdout, "  [%s] %s  %s\n", mark, c.Name, detail)
		}
	}

	if !report.Verified || report.Classification == contracts.ClassUnverified {
		return 1
	}
	return 0
}

// reorderFlagsFirst moves flag tokens (and their values) ahead of positional
// args so `decision-receipt <file> --public-key <hex>` parses the same as
// `decision-receipt --public-key <hex> <file>` (Go's flag package stops at the
// first positional otherwise).
func reorderFlagsFirst(args []string) []string {
	valueFlags := map[string]bool{"file": true, "format": true, "public-key": true}
	var flags, positionals []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if !strings.HasPrefix(a, "-") {
			positionals = append(positionals, a)
			continue
		}
		flags = append(flags, a)
		name := strings.TrimLeft(a, "-")
		if strings.Contains(name, "=") {
			continue // value embedded as --flag=value
		}
		if valueFlags[name] && i+1 < len(args) {
			i++
			flags = append(flags, args[i])
		}
	}
	return append(flags, positionals...)
}
