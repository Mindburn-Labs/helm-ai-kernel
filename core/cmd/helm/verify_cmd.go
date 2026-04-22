package main

import (
	"archive/tar"
	"compress/gzip"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

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
	)

	cmd.StringVar(&bundle, "bundle", "", "Path to EvidencePack directory (REQUIRED)")
	cmd.BoolVar(&jsonOutput, "json", false, "Output results as JSON to stdout")
	cmd.StringVar(&jsonOutFile, "json-out", "", "Write structured audit report to file (auditor mode)")

	if err := cmd.Parse(args); err != nil {
		return 2
	}

	if bundle == "" {
		_, _ = fmt.Fprintln(stderr, "Error: --bundle is required")
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
			_, _ = fmt.Fprintf(stdout, "✅ EvidencePack verification PASSED\n")
			_, _ = fmt.Fprintf(stdout, "Bundle: %s\n", bundle)
			_, _ = fmt.Fprintf(stdout, "Checks: %s\n", report.Summary)
		} else {
			_, _ = fmt.Fprintf(stdout, "❌ EvidencePack verification FAILED\n")
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

func init() {
	Register(Subcommand{Name: "verify", Aliases: []string{}, Usage: "Verify EvidencePack bundle (--bundle, --json)", RunFn: runVerifyCmd})
}
