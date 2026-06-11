package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/evidencepack"
)

// runEvidenceProveEntry generates a privacy-preserving single-entry inclusion
// proof (MIN-512) from a pack manifest:
//
//	helm-ai-kernel evidence prove-entry --manifest <manifest.json> --entry <path> [--out <file>]
//
// The emitted artifact lets a holder prove that one entry (e.g. a receipt)
// belongs to the pack — binding to manifest_hash and entries_merkle_root —
// WITHOUT disclosing the other entries. Verify it offline with:
//
//	helm-ai-kernel verify --entry <path> --proof <file>
//
// Exit codes: 0 = ok · 2 = runtime error.
func runEvidenceProveEntry(args []string, stdout, stderr io.Writer) int {
	cmd := flag.NewFlagSet("evidence prove-entry", flag.ContinueOnError)
	cmd.SetOutput(stderr)

	var (
		manifestPath string
		entryPath    string
		outPath      string
	)
	cmd.StringVar(&manifestPath, "manifest", "", "Path to the pack manifest.json")
	cmd.StringVar(&entryPath, "entry", "", "Manifest entry path to prove (e.g. receipts/decision-001.json)")
	cmd.StringVar(&outPath, "out", "", "Write the proof to this file (default: stdout)")

	if err := cmd.Parse(args); err != nil {
		return 2
	}
	if manifestPath == "" || entryPath == "" {
		_, _ = fmt.Fprintln(stderr, "Error: --manifest and --entry are required")
		return 2
	}

	data, err := os.ReadFile(manifestPath)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: cannot read manifest: %v\n", err)
		return 2
	}
	var manifest evidencepack.Manifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: invalid manifest JSON: %v\n", err)
		return 2
	}
	if manifest.ManifestHash == "" {
		_, _ = fmt.Fprintln(stderr, "Error: manifest is missing manifest_hash")
		return 2
	}

	proof, err := evidencepack.BuildInclusionProof(&manifest, entryPath, nil)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: %v\n", err)
		return 2
	}

	out, err := json.MarshalIndent(proof, "", "  ")
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: cannot encode proof: %v\n", err)
		return 2
	}

	if outPath == "" {
		_, _ = fmt.Fprintln(stdout, string(out))
		return 0
	}
	if err := os.WriteFile(outPath, append(out, '\n'), 0o644); err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: cannot write proof: %v\n", err)
		return 2
	}
	_, _ = fmt.Fprintf(stdout, "Inclusion proof for %s written to %s\n", entryPath, outPath)
	return 0
}
