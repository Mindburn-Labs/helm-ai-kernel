package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/riskscan"
)

// runVerifyScanCmd checks a local risk-scan export against contracts.EvidencePack.
// It verifies archived artifact integrity only, not runtime authorization,
// governed execution, provenance, or live posture.
func runVerifyScanCmd(args []string, stdout, stderr io.Writer) int {
	cmd := flag.NewFlagSet("verify-scan", flag.ContinueOnError)
	cmd.SetOutput(stderr)
	var bundle string
	var jsonOutput bool
	cmd.StringVar(&bundle, "bundle", "", "Path to a scan EvidencePack archive or directory")
	cmd.BoolVar(&jsonOutput, "json", false, "Output the offline integrity result as JSON")
	normalized, err := normalizeVerifyArgs(args)
	if err != nil {
		fmt.Fprintf(stderr, "Error: %v\n", err)
		return 2
	}
	if err := cmd.Parse(normalized); err != nil {
		return 2
	}
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
		fmt.Fprintln(stderr, "Error: scan EvidencePack path is required")
		return 2
	}

	verifyTarget := bundle
	info, err := os.Stat(bundle)
	if err != nil {
		fmt.Fprintf(stderr, "Error: verification failed: %v\n", err)
		return 2
	}
	if !info.IsDir() {
		tempDir, err := os.MkdirTemp("", "helm-verify-scan-*")
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
		fmt.Fprintln(stdout, "VERIFIED · local scan EvidencePack artifact integrity")
		fmt.Fprintf(stdout, "Envelope: %s\n", result.EnvelopeID)
		fmt.Fprintln(stdout, "Scope: artifact integrity only; no runtime authorization, governed execution, provenance, or live-posture claim was verified.")
	} else {
		fmt.Fprintln(stdout, "FAILED · local scan EvidencePack artifact integrity")
		for _, issue := range result.Errors {
			fmt.Fprintf(stdout, "  - %s\n", issue)
		}
	}
	if result.Verified {
		return 0
	}
	return 1
}

func init() {
	Register(Subcommand{
		Name:  "verify-scan",
		Usage: "Verify a local risk-scan EvidencePack's contract-bound artifact integrity",
		RunFn: runVerifyScanCmd,
	})
}
