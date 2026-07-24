package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/riskscan"
)

// runVerifyScanCmd verifies the narrow risk-scan/v1 profile. It is deliberately
// separate from `verify` because this artifact proves only local file/index/seal
// integrity, never a receipt chain, live authorization, or governed execution.
func runVerifyScanCmd(args []string, stdout, stderr io.Writer) int {
	cmd := flag.NewFlagSet("verify scan", flag.ContinueOnError)
	cmd.SetOutput(stderr)
	var bundle string
	var jsonOutput bool
	cmd.StringVar(&bundle, "bundle", "", "Path to a risk-scan/v1 EvidencePack directory or archive")
	cmd.BoolVar(&jsonOutput, "json", false, "Output the offline integrity result as JSON")
	normalized, err := normalizeVerifyArgs(args)
	if err != nil {
		fmt.Fprintf(stderr, "Error: %v\n", err)
		return 2
	}
	if err := cmd.Parse(normalized); err != nil {
		return 2
	}
	// Only the positional actually used as the bundle is consumed; anything
	// beyond it is a usage error, including when --bundle was supplied.
	consumed := 0
	if bundle == "" && cmd.NArg() > 0 {
		bundle = cmd.Arg(0)
		consumed = 1
	}
	if cmd.NArg() > consumed {
		fmt.Fprintf(stderr, "Error: unexpected argument: %s\n", cmd.Arg(consumed))
		return 2
	}
	if bundle == "" {
		fmt.Fprintln(stderr, "Error: risk-scan EvidencePack path is required")
		return 2
	}
	verifyTarget := bundle
	info, err := os.Stat(bundle)
	if err != nil {
		fmt.Fprintf(stderr, "Error: verification failed: %v\n", err)
		return 2
	}
	if !info.IsDir() {
		tempDir, err := os.MkdirTemp("", "helm-verify-risk-scan-*")
		if err != nil {
			fmt.Fprintf(stderr, "Error: cannot create verification workspace: %v\n", err)
			return 2
		}
		defer os.RemoveAll(tempDir)
		if err := extractEvidenceArchive(bundle, tempDir); err != nil {
			fmt.Fprintf(stderr, "Error: verification failed: %v\n", err)
			return 2
		}
		verifyTarget = tempDir
	}
	result := riskscan.VerifyEvidencePack(verifyTarget)
	if jsonOutput {
		data, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			fmt.Fprintf(stderr, "Error: serialize verification result: %v\n", err)
			return 2
		}
		fmt.Fprintln(stdout, string(data))
	} else if result.Verified {
		fmt.Fprintln(stdout, "VERIFIED · risk-scan/v1 offline integrity")
		fmt.Fprintf(stdout, "Envelope: %s\n", result.EnvelopeID)
		fmt.Fprintf(stdout, "Receipt provenance: %s\n", result.ReceiptProvenance)
		fmt.Fprintln(stdout, "Scope: local file/index/seal integrity only; no runtime receipt, authorization, execution, or live-posture claim was verified.")
	} else {
		fmt.Fprintln(stdout, "FAILED · risk-scan/v1 offline integrity")
		for _, issue := range result.Errors {
			fmt.Fprintf(stdout, "  - %s\n", issue)
		}
	}
	if result.Verified {
		return 0
	}
	return 1
}
