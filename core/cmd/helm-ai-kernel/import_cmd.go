package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/verifier/decisionreceipt"
)

func init() {
	Register(Subcommand{
		Name:  "import",
		Usage: "Import an external receipt into a HELM EvidencePack (receipt <file> --out <dir> [--format <id>] [--public-key <hex>] [--json])",
		RunFn: runImportCmd,
	})
}

func runImportCmd(args []string, stdout, stderr io.Writer) int {
	if len(args) > 0 && args[0] == "receipt" {
		return runImportReceiptCmd(args[1:], stdout, stderr)
	}
	fmt.Fprintln(stderr, "Usage: helm-ai-kernel import receipt <file> --out <dir> [--format <id>] [--public-key <hex>] [--json]")
	return 2
}

// runImportReceiptCmd verifies an external decision receipt and re-anchors it as
// a content-addressed HELM EvidencePack written to --out.
func runImportReceiptCmd(args []string, stdout, stderr io.Writer) int {
	cmd := flag.NewFlagSet("import receipt", flag.ContinueOnError)
	cmd.SetOutput(stderr)
	var (
		file       string
		out        string
		format     string
		publicKey  string
		jsonOutput bool
	)
	cmd.StringVar(&file, "file", "", "Path to the receipt/bundle JSON (or pass as a positional argument)")
	cmd.StringVar(&out, "out", "", "Output directory for the EvidencePack (required)")
	cmd.StringVar(&format, "format", "", "Format id (e.g. helm_external.v1); empty = auto-detect")
	cmd.StringVar(&publicKey, "public-key", "", "Trusted Ed25519 public key hex")
	cmd.BoolVar(&jsonOutput, "json", false, "Output the import result as JSON")
	if err := cmd.Parse(reorderFlagsFirst(args, map[string]bool{"file": true, "out": true, "format": true, "public-key": true})); err != nil {
		return 2
	}
	if file == "" && cmd.NArg() > 0 {
		file = cmd.Arg(0)
	}
	if file == "" || out == "" {
		fmt.Fprintln(stderr, "Error: a receipt file (positional or --file) and --out <dir> are required")
		return 2
	}
	raw, err := os.ReadFile(file)
	if err != nil {
		fmt.Fprintf(stderr, "Error: read %s: %v\n", file, err)
		return 2
	}

	result, err := decisionreceipt.ImportReceipt(raw, decisionreceipt.ImportOptions{
		FormatID:     format,
		PublicKeyHex: publicKey,
	})
	if err != nil {
		fmt.Fprintf(stderr, "Error: %v\n", err)
		return 2
	}
	if err := writeEvidencePack(out, result.ContentMap); err != nil {
		fmt.Fprintf(stderr, "Error: write evidence pack: %v\n", err)
		return 2
	}

	if jsonOutput {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(result); err != nil {
			fmt.Fprintf(stderr, "Error: encode result: %v\n", err)
			return 2
		}
	} else {
		fmt.Fprintf(stdout, "Imported %s  classification=%s\n", result.Report.FormatID, result.Report.Classification)
		fmt.Fprintf(stdout, "EvidencePack: %s\n", out)
		fmt.Fprintf(stdout, "  manifest_hash: %s\n", result.ManifestHash)
		fmt.Fprintf(stdout, "  entries (%d):\n", len(result.Entries))
		for _, e := range result.Entries {
			fmt.Fprintf(stdout, "    %s\n", e)
		}
		if !result.Report.Verified {
			fmt.Fprintln(stdout, "  note: receipt is UNVERIFIED — imported as honestly-labeled evidence only")
		}
	}

	if !result.Report.Verified {
		return 1
	}
	return 0
}

// writeEvidencePack writes a built EvidencePack content map to outDir, creating
// subdirectories as needed.
func writeEvidencePack(outDir string, contentMap map[string][]byte) error {
	paths := make([]string, 0, len(contentMap))
	for p := range contentMap {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	for _, p := range paths {
		full := filepath.Join(outDir, p)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(full, contentMap[p], 0o644); err != nil {
			return err
		}
	}
	return nil
}
