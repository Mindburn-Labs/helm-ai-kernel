package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/conform"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/verifier"
)

// runVerifyCmd implements `helm verify` per §2.1.
//
// Validates a signed EvidencePack bundle: structure, hashes, and signature.
// Supports auditor mode via --json-out for structured verification reports.
//
// Exit codes:
//
//	0 = verification passed
//	1 = verification failed
//	2 = runtime error
func runVerifyCmd(args []string, stdout, stderr io.Writer) int {
	cmd := flag.NewFlagSet("verify", flag.ContinueOnError)
	cmd.SetOutput(stderr)

	var (
		bundle      string
		jsonOutput  bool
		jsonOutFile string
		online      bool
		ledgerURL   string
	)

	cmd.StringVar(&bundle, "bundle", "", "Path to EvidencePack directory or archive")
	cmd.BoolVar(&jsonOutput, "json", false, "Output results as JSON to stdout")
	cmd.StringVar(&jsonOutFile, "json-out", "", "Write structured audit report to file (auditor mode)")
	cmd.BoolVar(&online, "online", false, "Verify pack metadata against the public proof ledger after offline checks pass")
	cmd.StringVar(&ledgerURL, "ledger-url", "", "Public proof verification URL")

	normalizedArgs, normalizeErr := normalizeVerifyArgs(args)
	if normalizeErr != nil {
		_, _ = fmt.Fprintf(stderr, "Error: %v\n", normalizeErr)
		return 2
	}
	if err := cmd.Parse(normalizedArgs); err != nil {
		return 2
	}

	if bundle == "" && cmd.NArg() > 0 {
		bundle = cmd.Arg(0)
	}
	if cmd.NArg() > 1 {
		_, _ = fmt.Fprintf(stderr, "Error: unexpected argument: %s\n", cmd.Arg(1))
		return 2
	}
	if bundle == "" {
		_, _ = fmt.Fprintln(stderr, "Error: evidence pack path is required")
		return 2
	}

	verifyTarget := bundle
	info, err := os.Stat(bundle)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: verification failed: %v\n", err)
		return 2
	}
	if !info.IsDir() {
		tempDir, err := os.MkdirTemp("", "helm-verify-*")
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "Error: cannot create verification workspace: %v\n", err)
			return 2
		}
		defer os.RemoveAll(tempDir)

		if err := extractEvidenceArchive(bundle, tempDir); err != nil {
			_, _ = fmt.Fprintf(stderr, "Error: verification failed: %v\n", err)
			return 2
		}
		verifyTarget = tempDir
	}

	// Use the standalone verifier library (zero network deps)
	report, err := verifier.VerifyBundle(verifyTarget)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: verification failed: %v\n", err)
		return 2
	}

	// Also run legacy conform-based checks for backward compat
	if hasCanonicalEvidenceLayout(verifyTarget) {
		structIssues := conform.ValidateEvidencePackStructure(verifyTarget)
		if len(structIssues) > 0 {
			for _, issue := range structIssues {
				report.Checks = append(report.Checks, verifier.CheckResult{
					Name:   "conform:" + issue,
					Pass:   false,
					Reason: issue,
				})
			}
			report.Verified = false
		}
	}

	// Verify report signature when a conformance report signature is present.
	if hasConformanceSignature(verifyTarget) {
		sigErr := conform.VerifyReport(verifyTarget, func(data []byte, sig string) error {
			// Attempt to load public key for verification.
			pubKeyHex := os.Getenv("HELM_VERIFY_PUBLIC_KEY_HEX")
			if pubKeyHex == "" {
				keyPath := filepath.Join(verifyTarget, "public_key.hex")
				if keyData, readErr := os.ReadFile(keyPath); readErr == nil {
					pubKeyHex = strings.TrimSpace(string(keyData))
				}
			}
			if pubKeyHex == "" {
				if sig != "" && !strings.Contains(sig, "sha256-hmac") && !strings.Contains(sig, "sha256-digest-only") {
					return fmt.Errorf("signature present but no verification key available (set HELM_VERIFY_PUBLIC_KEY_HEX)")
				}
				return nil
			}

			pubKeyBytes, err := hex.DecodeString(pubKeyHex)
			if err != nil || len(pubKeyBytes) != 32 {
				return fmt.Errorf("invalid HELM_VERIFY_PUBLIC_KEY_HEX: must be 64 hex chars (32 bytes)")
			}

			sigBytes, err := hex.DecodeString(sig)
			if err != nil {
				return fmt.Errorf("invalid signature encoding: %w", err)
			}

			pubKey := ed25519.PublicKey(pubKeyBytes)
			if !ed25519.Verify(pubKey, data, sigBytes) {
				return fmt.Errorf("Ed25519 signature verification failed: signature does not match data")
			}
			return nil
		})
		if sigErr != nil {
			report.Checks = append(report.Checks, verifier.CheckResult{
				Name:   "signature_verification",
				Pass:   false,
				Reason: fmt.Sprintf("signature: %v", sigErr),
			})
			report.Verified = false
		}
	}

	if online && report.Verified {
		proof, proofErr := verifyOnlineProof(report, ledgerURL)
		if proofErr != nil {
			report.Checks = append(report.Checks, verifier.CheckResult{
				Name:   "online_proof",
				Pass:   false,
				Reason: proofErr.Error(),
			})
			report.Verified = false
		} else if !proof.Verified {
			reason := proof.Error
			if reason == "" {
				reason = "public proof API did not verify this pack"
			}
			report.Checks = append(report.Checks, verifier.CheckResult{
				Name:   "online_proof",
				Pass:   false,
				Reason: reason,
			})
			report.Verified = false
		} else {
			report.Checks = append(report.Checks, verifier.CheckResult{
				Name:   "online_proof",
				Pass:   true,
				Detail: "public proof API verified pack metadata",
			})
			mergeOnlineProof(report, proof)
		}
	}

	finalizeVerifyReport(report)

	// Write auditor JSON report to file if requested
	if jsonOutFile != "" {
		data, _ := json.MarshalIndent(report, "", "  ")
		if writeErr := os.WriteFile(jsonOutFile, data, 0644); writeErr != nil {
			_, _ = fmt.Fprintf(stderr, "Error: cannot write audit report: %v\n", writeErr)
			return 2
		}
		_, _ = fmt.Fprintf(stdout, "Audit report written to %s\n", jsonOutFile)
	}

	// Output
	if jsonOutput {
		data, _ := json.MarshalIndent(report, "", "  ")
		_, _ = fmt.Fprintln(stdout, string(data))
	} else {
		if report.Verified {
			printCompactVerifyReport(stdout, report)
		} else {
			_, _ = fmt.Fprintf(stdout, "FAILED · envelope %s\n", displayEnvelopeID(report))
			_, _ = fmt.Fprintf(stdout, "Bundle: %s\n", bundle)
			for _, c := range report.Checks {
				if !c.Pass {
					_, _ = fmt.Fprintf(stdout, "  - %s: %s\n", c.Name, c.Reason)
				}
			}
		}
	}

	if !report.Verified {
		return 1
	}
	return 0
}

func extractEvidenceArchive(bundlePath, dstDir string) error {
	file, err := os.Open(bundlePath)
	if err != nil {
		return err
	}
	defer file.Close()

	var reader io.Reader = file
	if strings.HasSuffix(bundlePath, ".gz") || strings.HasSuffix(bundlePath, ".tgz") {
		gzReader, err := gzip.NewReader(file)
		if err != nil {
			return fmt.Errorf("open gzip archive: %w", err)
		}
		defer gzReader.Close()
		reader = gzReader
	}

	tarReader := tar.NewReader(reader)
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return fmt.Errorf("read tar entry: %w", err)
		}

		targetPath := filepath.Join(dstDir, filepath.Clean(header.Name))
		cleanRoot := filepath.Clean(dstDir)
		if !strings.HasPrefix(targetPath, cleanRoot+string(os.PathSeparator)) && targetPath != cleanRoot {
			return fmt.Errorf("archive entry escapes destination: %s", header.Name)
		}

		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(targetPath, 0750); err != nil {
				return fmt.Errorf("create directory %s: %w", targetPath, err)
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(targetPath), 0750); err != nil {
				return fmt.Errorf("prepare file %s: %w", targetPath, err)
			}
			outFile, err := os.OpenFile(targetPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
			if err != nil {
				return fmt.Errorf("create file %s: %w", targetPath, err)
			}
			if _, err := io.Copy(outFile, tarReader); err != nil {
				outFile.Close()
				return fmt.Errorf("extract file %s: %w", targetPath, err)
			}
			if err := outFile.Close(); err != nil {
				return fmt.Errorf("close file %s: %w", targetPath, err)
			}
		default:
			return fmt.Errorf("unsupported archive entry %s", header.Name)
		}
	}
}

func hasCanonicalEvidenceLayout(root string) bool {
	if _, err := os.Stat(filepath.Join(root, "00_INDEX.json")); err == nil {
		return true
	}
	if _, err := os.Stat(filepath.Join(root, "02_PROOFGRAPH")); err == nil {
		return true
	}
	return false
}

func hasConformanceSignature(root string) bool {
	_, err := os.Stat(filepath.Join(root, "07_ATTESTATIONS", "conformance_report.sig"))
	return err == nil
}

func normalizeVerifyArgs(args []string) ([]string, error) {
	var flags []string
	var positional []string
	valueFlags := map[string]bool{
		"--bundle":     true,
		"-bundle":      true,
		"--json-out":   true,
		"-json-out":    true,
		"--ledger-url": true,
		"-ledger-url":  true,
	}
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if strings.HasPrefix(arg, "-") {
			flags = append(flags, arg)
			if strings.Contains(arg, "=") {
				continue
			}
			if valueFlags[arg] {
				if i+1 >= len(args) {
					return nil, fmt.Errorf("%s requires a value", arg)
				}
				i++
				flags = append(flags, args[i])
			}
			continue
		}
		positional = append(positional, arg)
	}
	return append(flags, positional...), nil
}

type onlineProofResponse struct {
	Verified            bool    `json:"verified"`
	EnvelopeID          string  `json:"envelope_id,omitempty"`
	SealedAt            string  `json:"sealed_at,omitempty"`
	SignatureValidCount int     `json:"signature_valid_count,omitempty"`
	SignatureTotalCount int     `json:"signature_total_count,omitempty"`
	AnchorIndex         *uint64 `json:"anchor_index,omitempty"`
	MerkleRoot          string  `json:"merkle_root,omitempty"`
	Error               string  `json:"error,omitempty"`
}

func verifyOnlineProof(report *verifier.VerifyReport, ledgerURL string) (*onlineProofResponse, error) {
	if ledgerURL == "" {
		ledgerURL = os.Getenv("HELM_LEDGER_URL")
	}
	if ledgerURL == "" {
		ledgerURL = "https://mindburn.org/api/proof/verify"
	}

	body, err := json.Marshal(map[string]any{
		"envelope_id": report.EnvelopeID,
		"sealed_at":   report.SealedAt,
		"merkle_root": report.MerkleRoot,
		"anchor_index": func() any {
			if report.AnchorIndex == nil {
				return nil
			}
			return *report.AnchorIndex
		}(),
		"offline_verified": report.Verified,
	})
	if err != nil {
		return nil, err
	}
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Post(ledgerURL, "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("public proof API unavailable: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return nil, fmt.Errorf("public proof API returned %d: %s", resp.StatusCode, strings.TrimSpace(string(data)))
	}
	var proof onlineProofResponse
	if err := json.NewDecoder(resp.Body).Decode(&proof); err != nil {
		return nil, fmt.Errorf("invalid public proof response: %w", err)
	}
	return &proof, nil
}

func mergeOnlineProof(report *verifier.VerifyReport, proof *onlineProofResponse) {
	if proof.EnvelopeID != "" {
		report.EnvelopeID = proof.EnvelopeID
	}
	if proof.SealedAt != "" {
		report.SealedAt = proof.SealedAt
	}
	if proof.MerkleRoot != "" {
		report.MerkleRoot = proof.MerkleRoot
	}
	if proof.SignatureTotalCount > 0 {
		report.SignatureTotalCount = proof.SignatureTotalCount
		report.SignatureValidCount = proof.SignatureValidCount
	}
	if proof.AnchorIndex != nil {
		report.AnchorIndex = proof.AnchorIndex
	}
}

func printCompactVerifyReport(stdout io.Writer, report *verifier.VerifyReport) {
	anchor := "offline"
	if report.AnchorIndex != nil {
		anchor = fmt.Sprintf("#%d", *report.AnchorIndex)
	}
	sealed := report.SealedAt
	if sealed == "" {
		sealed = "unknown"
	}
	_, _ = fmt.Fprintf(stdout, "envelope %s · sig %d/%d · anchor %s\n", displayEnvelopeID(report), report.SignatureValidCount, report.SignatureTotalCount, anchor)
	_, _ = fmt.Fprintf(stdout, "VERIFIED · sealed %s\n", sealed)
}

func displayEnvelopeID(report *verifier.VerifyReport) string {
	if report.EnvelopeID != "" {
		return report.EnvelopeID
	}
	return "unknown"
}

func finalizeVerifyReport(report *verifier.VerifyReport) {
	failed := 0
	for _, check := range report.Checks {
		if !check.Pass {
			failed++
		}
	}
	report.IssueCount = failed
	if failed > 0 {
		report.Verified = false
		report.Summary = fmt.Sprintf("FAIL: %d/%d checks failed", failed, len(report.Checks))
		return
	}
	report.Verified = true
	report.Summary = fmt.Sprintf("PASS: %d/%d checks passed", len(report.Checks), len(report.Checks))
}

func init() {
	Register(Subcommand{Name: "verify", Aliases: []string{}, Usage: "Verify EvidencePack bundle ([path] --bundle, --json, --online)", RunFn: runVerifyCmd})
}
