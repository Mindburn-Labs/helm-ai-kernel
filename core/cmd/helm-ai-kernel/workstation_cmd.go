// quantum_posture: workstation receipt verification references classical
// Ed25519 keys only; this command layer adds no post-quantum control.
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
		_, _ = fmt.Fprintln(stderr, "Usage: helm-ai-kernel workstation <import|view|decide|enforce|verify-decision|operator|list|denied|memory|loops|evidence|certify|capture> [flags]")
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
	case "verify-decision":
		return runWorkstationVerifyDecisionCmd(args[1:], stdout, stderr)
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
		_, _ = fmt.Fprintln(stderr, "Usage: helm-ai-kernel workstation <import|view|decide|enforce|verify-decision|operator|list|denied|memory|loops|evidence|certify|capture> [flags]")
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
		seedFile  string
		dataDir   string
	)
	cmd.StringVar(&artifacts, "artifacts", "", "Artifact directory containing run.manifest.json")
	cmd.StringVar(&out, "out", "", "Write canonical import result JSON to this path")
	cmd.BoolVar(&jsonOut, "json", false, "Print canonical import result JSON")
	cmd.StringVar(&seedHex, "signing-seed-hex", "", "Deprecated unsafe argv seed input; use --signing-seed-file")
	cmd.StringVar(&seedFile, "signing-seed-file", "", "Path to 0600 file containing a 32-byte Ed25519 seed as hex")
	cmd.StringVar(&dataDir, "data-dir", defaultSetupDataDir(), "Directory for HELM local signing state")

	if err := cmd.Parse(args); err != nil {
		return 2
	}
	if artifacts == "" {
		_, _ = fmt.Fprintln(stderr, "Error: --artifacts is required")
		return 2
	}
	seed, err := resolveWorkstationSigningSeed(dataDir, seedHex, seedFile)
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
		receiptPath          string
		jsonOut              bool
		dataDir              string
		trustedPublicKeyFile string
		trustedSignersFile   string
	)
	cmd.StringVar(&receiptPath, "receipt", "", "Agent Run Receipt or workstation import result JSON")
	cmd.BoolVar(&jsonOut, "json", false, "Print summary JSON")
	cmd.StringVar(&dataDir, "data-dir", defaultSetupDataDir(), "Directory for HELM local signing state")
	cmd.StringVar(&trustedPublicKeyFile, "trusted-public-key-file", "", "Path to caller-owned Ed25519 public key file")
	cmd.StringVar(&trustedSignersFile, "trusted-signers-file", "", "Path to caller-owned versioned trusted signer store JSON")

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
	integrityValid, err := workstation.VerifyReceiptSignature(result.Receipt)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: receipt integrity check failed: %v\n", err)
		return 1
	}
	trustedSigners, trustAnchor, trustAnchorAvailable, err := resolveTrustedWorkstationSigners(dataDir, trustedPublicKeyFile, trustedSignersFile)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: load trusted public key: %v\n", err)
		return 1
	}
	signerTrusted := false
	if trustAnchorAvailable {
		signerTrusted, err = workstation.VerifyReceiptWithTrustedSigners(result.Receipt, trustedSigners)
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "Error: trusted receipt verification failed: %v\n", err)
			return 1
		}
	}
	summary := workstation.Summary(result.Receipt)
	summary["integrity_valid"] = integrityValid
	summary["signer_trusted"] = signerTrusted
	summary["trust_anchor"] = trustAnchor
	if result.ReplayRootHash != "" {
		summary["replay_root_hash"] = result.ReplayRootHash
	}
	if jsonOut {
		data, _ := json.MarshalIndent(summary, "", "  ")
		_, _ = fmt.Fprintln(stdout, string(data))
	} else {
		printWorkstationSummary(stdout, summary)
	}
	if !integrityValid || !signerTrusted {
		return 1
	}
	return 0
}

func loadSigningSeed(seedHex, seedFile string) ([]byte, error) {
	if strings.TrimSpace(seedHex) != "" {
		return nil, fmt.Errorf("--signing-seed-hex is disabled because argv exposes secrets; use --signing-seed-file")
	}
	if strings.TrimSpace(seedFile) == "" {
		return nil, nil
	}
	info, err := os.Lstat(seedFile)
	if err != nil {
		return nil, fmt.Errorf("stat --signing-seed-file: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, fmt.Errorf("--signing-seed-file must be a regular file, not a symlink or special file")
	}
	if info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("--signing-seed-file must not be readable by group or others")
	}
	data, err := os.ReadFile(seedFile)
	if err != nil {
		return nil, fmt.Errorf("read --signing-seed-file: %w", err)
	}
	return parseSigningSeedHex(strings.TrimSpace(string(data)))
}

func parseSigningSeedHex(seedHex string) ([]byte, error) {
	seed, err := hex.DecodeString(seedHex)
	if err != nil {
		return nil, fmt.Errorf("signing seed must be hex: %w", err)
	}
	if len(seed) != 32 {
		return nil, fmt.Errorf("signing seed must decode to 32 bytes")
	}
	for _, value := range seed {
		if value != 0 {
			return seed, nil
		}
	}
	return nil, fmt.Errorf("signing seed must not be all zero")
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
	if integrityValid, ok := summary["integrity_valid"]; ok {
		_, _ = fmt.Fprintf(stdout, "  integrity:     %v\n", integrityValid)
	}
	if signerTrusted, ok := summary["signer_trusted"]; ok {
		_, _ = fmt.Fprintf(stdout, "  signer trusted: %v\n", signerTrusted)
	}
	if trustAnchor, ok := summary["trust_anchor"]; ok {
		_, _ = fmt.Fprintf(stdout, "  trust anchor:  %v\n", trustAnchor)
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
