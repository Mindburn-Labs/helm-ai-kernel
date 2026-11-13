package main

// quantum_posture: verify command trust checks use classical Ed25519
// conformance/report signatures in this release; no post-quantum assurance is
// claimed for this CLI verification path.

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/conform"
	evidencepkg "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/evidence"
	helmotel "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/otel"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/receiptverify"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/verifier"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/verifier/packfs"
)

// runVerifyCmd implements `helm-ai-kernel verify` per §2.1.
//
// Validates a signed EvidencePack bundle: structure, hashes, and signature.
// Supports auditor mode via --json-out for structured verification reports.
//
// Every check ends VERIFIED, FAILED, UNVERIFIABLE or NOT_RUN. A check with
// nothing to read is NOT_RUN and is never counted as passed.
//
// Exit codes:
//
//	0 = VERIFIED: no check failed and every check the pack, its declared gates,
//	    the trust profile and the --require-* flags require ran and held.
//	    Checks the pack gave no input to are listed as not run; name them with
//	    --require-check to make their absence a failure.
//	1 = FAILED or UNVERIFIABLE
//	2 = runtime or usage error; no verdict was reached
func runVerifyCmd(args []string, stdout, stderr io.Writer) int {
	if len(args) > 0 && args[0] == "external-receipt" {
		return runVerifyExternalReceiptCmd(args[1:], stdout, stderr)
	}
	if len(args) > 0 && args[0] == "receipt" {
		return runVerifyReceiptCmd(args[1:], stdout, stderr)
	}
	if len(args) > 0 && args[0] == "decision-receipt" {
		return runVerifyDecisionReceiptCmd(args[1:], stdout, stderr)
	}
	if hasFlag(args, "entry") || hasFlag(args, "proof") {
		return runVerifyEntryCmd(args, stdout, stderr)
	}
	if len(args) > 0 && (args[0] == "pack" || args[0] == "proofgraph") {
		args = args[1:]
	}

	cmd := flag.NewFlagSet("verify", flag.ContinueOnError)
	cmd.SetOutput(stderr)

	var (
		bundle            string
		jsonOutput        bool
		jsonOutFile       string
		online            bool
		ledgerURL         string
		profile           string
		allowSelfAttested bool
		allowLegacyV4     bool
		configPath        string
		storageReceipt    string
		externalHostKey   string
		trustedPublicKey  string
		managedAgentKey   string
		requireEIDAS      bool
		eidasMaxAgeHours  int
		requireTEE        string
		requireCheckFlags []string
	)

	cmd.StringVar(&bundle, "bundle", "", "Path to EvidencePack directory or archive")
	cmd.BoolVar(&jsonOutput, "json", false, "Output results as JSON to stdout")
	cmd.StringVar(&jsonOutFile, "json-out", "", "Write structured audit report to file (auditor mode)")
	cmd.BoolVar(&online, "online", false, "Verify pack metadata against the public proof ledger after offline checks pass")
	cmd.StringVar(&ledgerURL, "ledger-url", "", "Public proof verification URL")
	cmd.StringVar(&profile, "profile", "", "Evidence trust profile: dev-local, team, customer, high-assurance (default: active config or dev-local)")
	cmd.BoolVar(&allowSelfAttested, "allow-self-attested", false,
		"Accept a dev-local seal whose verification key is carried inside the pack. "+
			"Such a seal proves internal consistency only, never provenance — anyone can sign their own pack.")
	cmd.BoolVar(&allowLegacyV4, "allow-legacy-v4-receipts", false,
		"Check a dev-local MCP proof receipt that has no signature_version as a legacy V4 receipt instead of leaving it unverified. "+
			"A legacy signature covers eight colon-joined fields, not the verdict, and a receipt.v5 signature can be replayed as one: "+
			"use it only for a pack known to predate receipt.v5.")
	cmd.StringVar(&configPath, "config", "", "Evidence trust config path, for example helm/helm.yaml (never read implicitly from the working directory)")
	cmd.StringVar(&storageReceipt, "storage-receipt", "", "Path to S3 Object Lock storage receipt for customer/high-assurance verification")
	envKeys := packVerifyKeysFromEnv()
	cmd.StringVar(&externalHostKey, "external-host-public-key", envKeys.externalHost, "Trusted Ed25519 public key hex for external host evidence chains")
	cmd.StringVar(&trustedPublicKey, "trusted-public-key", envKeys.conformanceReport, "Trusted Ed25519 public key hex for conformance report signatures")
	cmd.StringVar(&managedAgentKey, "managed-agent-receipt-public-key", envKeys.managedAgentReceipt, "Trusted Ed25519 public key hex for embedded managed-agent receipt signatures")
	cmd.BoolVar(&requireEIDAS, "require-eidas", false, "Require eIDAS-labelled anchor metadata (backend=eidas-qtsp with a parseable integrated_time); metadata-only, not RFC 3161 or EU Trusted List cryptographic verification")
	cmd.IntVar(&eidasMaxAgeHours, "eidas-max-age-hours", 24, "Maximum age in hours of the declared integrated_time checked by --require-eidas; this does not verify the timestamp token")
	cmd.StringVar(&requireTEE, "require-tee", "", "Require every receipt to carry a TEE attestation; one of sevsnp|tdx|nitro|any (empty = no requirement)")
	// flag.Func, not StringVar: a string flag keeps only its last value, so
	// `--require-check a --require-check b` required b alone, and a pack on
	// which check a never ran still verified.
	cmd.Func("require-check", "Checks that must have run, for example chain_integrity,connector_evidence. Repeat the flag or separate names with commas; every named check is required. A named check the pack gives no input to is FAILED instead of not run. Checks: "+strings.Join(verifier.CheckNames(), ", "), func(value string) error {
		requireCheckFlags = append(requireCheckFlags, value)
		return nil
	})

	normalizedArgs, normalizeErr := normalizeVerifyArgs(args)
	if normalizeErr != nil {
		writeText(stderr, "Error: %v\n", normalizeErr)
		return 2
	}
	if err := cmd.Parse(normalizedArgs); err != nil {
		return 2
	}

	if bundle == "" && cmd.NArg() > 0 {
		bundle = cmd.Arg(0)
	}
	if cmd.NArg() > 1 {
		writeText(stderr, "Error: unexpected argument: %s\n", cmd.Arg(1))
		return 2
	}
	if bundle == "" {
		_, _ = fmt.Fprintln(stderr, "Error: evidence pack path is required")
		return 2
	}
	// Every occurrence of the flag adds to the required set.
	var requiredChecks []string
	for _, value := range requireCheckFlags {
		names, err := parseRequiredChecks(value)
		if err != nil {
			writeText(stderr, "Error: --require-check %s\n", err)
			return 2
		}
		requiredChecks = append(requiredChecks, names...)
	}

	verifyTarget := bundle
	storageObjectPath := ""
	info, err := os.Stat(bundle)
	if err != nil {
		writeText(stderr, "Error: verification failed: %s\n", err)
		return 2
	}
	if !info.IsDir() {
		storageObjectPath = bundle
		tempDir, err := os.MkdirTemp("", "helm-verify-*")
		if err != nil {
			writeText(stderr, "Error: cannot create verification workspace: %v\n", err)
			return 2
		}
		defer os.RemoveAll(tempDir)

		// The error can quote an entry name out of the archive.
		if err := extractEvidenceArchive(bundle, tempDir); err != nil {
			writeText(stderr, "Error: verification failed: %s\n", err)
			return 2
		}
		verifyTarget = tempDir
	}

	profileOpt := evidencepkg.EvidenceTrustProfile("")
	if strings.TrimSpace(profile) != "" {
		profileOpt = normalizeEvidenceTrustProfile(profile)
	}
	report, err := verifyPackDir(verifyTarget, verifier.VerifyOptions{
		Profile:                         profileOpt,
		ConfigPath:                      configPath,
		StorageReceiptPath:              storageReceipt,
		StorageObjectPath:               storageObjectPath,
		ExternalHostKeyHex:              externalHostKey,
		ManagedAgentReceiptPublicKeyHex: managedAgentKey,
		AllowSelfAttested:               allowSelfAttested,
		AllowLegacyV4Receipts:           allowLegacyV4,
		RequireChecks:                   requiredChecks,
	}, trustedPublicKey)
	if err != nil {
		writeText(stderr, "Error: verification failed: %s\n", err)
		return 2
	}

	if requireEIDAS {
		eidasResults := checkEIDASAnchorMetadata(verifyTarget, time.Duration(eidasMaxAgeHours)*time.Hour)
		report.Checks = append(report.Checks, eidasResults...)
		for _, r := range eidasResults {
			if !r.Pass {
				report.Verified = false
			}
		}
	}

	if requireTEE != "" {
		teeResults := checkTEEAttestations(verifyTarget, requireTEE)
		report.Checks = append(report.Checks, teeResults...)
		for _, r := range teeResults {
			if !r.Pass {
				report.Verified = false
			}
		}
	}

	// The flag checks above appended results; the verdict follows them.
	finalizeVerifyReport(report)

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

	recordVerification(context.Background(), helmotel.VerificationEvent{
		EnvelopeID: report.EnvelopeID,
		Verified:   report.Verified,
		// Checks that did not run are not part of what was verified.
		CheckCount:  report.CheckCounts.Ran(),
		EvidenceRef: bundle,
	})

	// Write auditor JSON report to file if requested
	if jsonOutFile != "" {
		data, _ := json.MarshalIndent(report, "", "  ")
		if writeErr := os.WriteFile(jsonOutFile, data, 0644); writeErr != nil {
			writeText(stderr, "Error: cannot write audit report: %s\n", writeErr)
			return 2
		}
		writeText(stdout, "Audit report written to %s\n", jsonOutFile)
	}

	// Output. JSON carries every value as the pack states it; text goes
	// through writeText, which makes pack-controlled strings safe to print.
	if jsonOutput {
		data, _ := json.MarshalIndent(report, "", "  ")
		_, _ = fmt.Fprintln(stdout, string(data))
	} else {
		if report.Verified {
			printCompactVerifyReport(stdout, report)
		} else {
			// UNVERIFIABLE: content intact, but no trust root names the signer.
			writeText(stdout, "%s · envelope %s\n", report.Outcome, displayEnvelopeID(report))
			writeText(stdout, "Bundle: %s\n", bundle)
			printVerifyIssues(stdout, report)
		}
		printVerifyCheckCounts(stdout, report)
	}

	if report.Outcome != receiptverify.VerdictVerified {
		return 1
	}
	return 0
}

// maxNotRunLines bounds the not-run listing in text output. A pack with many
// host receipts reports several not-run checks per receipt; --json has them all.
const maxNotRunLines = 20

// printVerifyCheckCounts prints how many checks passed, failed and did not
// run, and names each check that did not run with its reason, so a VERIFIED
// headline cannot be read as covering checks that had nothing to read.
func printVerifyCheckCounts(stdout io.Writer, report *verifier.VerifyReport) {
	counts := report.CheckCounts
	line := fmt.Sprintf("checks: %d passed, %d failed, ", counts.Passed, counts.Failed)
	if counts.Unverifiable > 0 {
		line += fmt.Sprintf("%d unverifiable, ", counts.Unverifiable)
	}
	line += fmt.Sprintf("%d not run", counts.NotRun)
	if counts.NotRun > 0 && report.Verified {
		line += "; this result covers only the checks that ran"
	}
	writeText(stdout, "%s\n", line)
	printed := 0
	for _, c := range report.Checks {
		if c.Status != verifier.CheckNotRun {
			continue
		}
		if printed == maxNotRunLines {
			writeText(stdout, "  ... and %d more not run (use --json for all of them)\n", counts.NotRun-printed)
			break
		}
		writeText(stdout, "  not run: %s: %s\n", c.Name, c.Reason)
		printed++
	}
}

// printVerifyIssues lists the checks that ran and did not pass. A check name
// can carry a file name and a reason can quote the pack, so both are printed
// through writeText.
func printVerifyIssues(stdout io.Writer, report *verifier.VerifyReport) {
	for _, c := range report.Checks {
		if c.Status == verifier.CheckFailed || c.Status == verifier.CheckUnverifiable {
			writeText(stdout, "  - %s: %s\n", c.Name, c.Reason)
		}
	}
}

// packVerifyKeys are the trusted keys `verify` and `evidence inspect` both
// read from the environment, so a pack is judged against the same roots
// whichever command is used.
type packVerifyKeys struct {
	externalHost        string
	conformanceReport   string
	managedAgentReceipt string
}

func packVerifyKeysFromEnv() packVerifyKeys {
	return packVerifyKeys{
		externalHost:        strings.TrimSpace(os.Getenv("HELM_EXTERNAL_HOST_PUBLIC_KEY_HEX")),
		conformanceReport:   strings.TrimSpace(os.Getenv("HELM_VERIFY_PUBLIC_KEY_HEX")),
		managedAgentReceipt: strings.TrimSpace(os.Getenv("HELM_MANAGED_AGENT_RECEIPT_PUBLIC_KEY_HEX")),
	}
}

// verifyPackDir is the verdict on an extracted pack directory. `verify` and
// `evidence inspect` both call it, so one pack cannot be FAILED by one command
// and VERIFIED by the other.
//
// It runs the verifier library's checks, the §3.1 layout check on a pack in
// the canonical layout, and the conformance report signature check when the
// pack carries one, and returns the finalized report. conformanceKeyHex is the
// trusted key for that signature.
func verifyPackDir(dir string, opts verifier.VerifyOptions, conformanceKeyHex string) (*verifier.VerifyReport, error) {
	conformanceSigPresent := hasConformanceSignature(dir)
	var conformanceSigErr error
	if conformanceSigPresent {
		conformanceSigErr = verifyConformanceReportSignature(dir, conformanceKeyHex)
		opts.AllowVerifiedConformanceSignature = conformanceSigErr == nil
	}

	// The standalone verifier library (zero network deps).
	report, err := verifier.VerifyBundleWithOptions(dir, opts)
	if err != nil {
		return nil, err
	}

	if hasCanonicalEvidenceLayout(dir) {
		for _, issue := range conform.ValidateEvidencePackStructure(dir) {
			report.Checks = append(report.Checks, verifier.CheckResult{
				Name:   "conform:" + issue,
				Pass:   false,
				Reason: issue,
			})
		}
	}

	if conformanceSigErr != nil {
		report.Checks = append(report.Checks, verifier.CheckResult{
			Name:   "signature_verification",
			Pass:   false,
			Reason: fmt.Sprintf("signature: %v", conformanceSigErr),
		})
	}

	report.Finalize()
	return report, nil
}

// parseRequiredChecks reads one --require-check value: check names separated
// by commas. A name that is not a registered check is an error, and so is a
// value that names none: either would otherwise require nothing and let a pack
// verify without the check the caller asked for.
func parseRequiredChecks(value string) ([]string, error) {
	var names []string
	for _, name := range strings.Split(value, ",") {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		if !slices.Contains(verifier.CheckNames(), name) {
			return nil, fmt.Errorf("names an unknown check %q (checks: %s)", name, strings.Join(verifier.CheckNames(), ", "))
		}
		names = append(names, name)
	}
	if len(names) == 0 {
		return nil, fmt.Errorf("value %q names no check (checks: %s)", value, strings.Join(verifier.CheckNames(), ", "))
	}
	return names, nil
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
	var extractedBytes int64
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return fmt.Errorf("read tar entry: %w", err)
		}

		targetPath, err := safeArchiveEntryPath(dstDir, header.Name)
		if err != nil {
			return err
		}

		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(targetPath, 0750); err != nil {
				return fmt.Errorf("create directory %s: %w", targetPath, err)
			}
		case tar.TypeReg:
			if header.Size < 0 {
				return fmt.Errorf("archive entry %s has invalid size", header.Name)
			}
			if header.Size > maxEvidenceBundleBytes {
				return fmt.Errorf("archive entry %s exceeds %d bytes", header.Name, maxEvidenceBundleBytes)
			}
			if extractedBytes+header.Size > maxEvidenceBundleBytes {
				return fmt.Errorf("archive exceeds %d extracted bytes", maxEvidenceBundleBytes)
			}
			if err := os.MkdirAll(filepath.Dir(targetPath), 0750); err != nil {
				return fmt.Errorf("prepare file %s: %w", targetPath, err)
			}
			outFile, err := os.OpenFile(targetPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
			if err != nil {
				return fmt.Errorf("create file %s: %w", targetPath, err)
			}
			written, err := io.Copy(outFile, tarReader)
			if err != nil {
				outFile.Close()
				return fmt.Errorf("extract file %s: %w", targetPath, err)
			}
			if written != header.Size {
				outFile.Close()
				return fmt.Errorf("archive entry %s size mismatch", header.Name)
			}
			extractedBytes += written
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

func verifyConformanceReportSignature(root string, trustedPublicKey string) error {
	return conform.VerifyReport(root, func(data []byte, sig string) error {
		pubKeyHex := strings.TrimSpace(trustedPublicKey)
		if pubKeyHex == "" {
			return fmt.Errorf("signature present but no trusted verification key available (set --trusted-public-key or HELM_VERIFY_PUBLIC_KEY_HEX)")
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
}

func normalizeVerifyArgs(args []string) ([]string, error) {
	var flags []string
	var positional []string
	valueFlags := map[string]bool{
		"--bundle":                           true,
		"-bundle":                            true,
		"--json-out":                         true,
		"-json-out":                          true,
		"--ledger-url":                       true,
		"-ledger-url":                        true,
		"--profile":                          true,
		"-profile":                           true,
		"--config":                           true,
		"-config":                            true,
		"--storage-receipt":                  true,
		"-storage-receipt":                   true,
		"--external-host-public-key":         true,
		"-external-host-public-key":          true,
		"--trusted-public-key":               true,
		"-trusted-public-key":                true,
		"--managed-agent-receipt-public-key": true,
		"-managed-agent-receipt-public-key":  true,
		"--eidas-max-age-hours":              true,
		"-eidas-max-age-hours":               true,
		"--require-check":                    true,
		"-require-check":                     true,
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
	sealState := report.SealState
	if sealState == "" {
		sealState = "unknown"
	}
	trust := report.TrustLevel
	if trust == "" {
		trust = string(evidencepkg.EvidenceTrustProfileDevLocal)
	}
	anchorStatus := report.AnchorStatus
	if anchorStatus == "" {
		anchorStatus = anchor
	} else if anchor != "offline" && anchorStatus != anchor {
		anchorStatus = anchor + " (" + anchorStatus + ")"
	}
	storageStatus := report.StorageStatus
	if storageStatus == "" {
		storageStatus = "unknown"
	}
	writeText(stdout, "envelope %s · seal %s · sig %d/%d · trust %s\n", displayEnvelopeID(report), sealState, report.SignatureValidCount, report.SignatureTotalCount, trust)
	writeText(stdout, "VERIFIED · sealed %s · anchor %s · storage %s\n", sealed, anchorStatus, storageStatus)
}

func displayEnvelopeID(report *verifier.VerifyReport) string {
	if report.EnvelopeID != "" {
		return report.EnvelopeID
	}
	return "unknown"
}

func finalizeVerifyReport(report *verifier.VerifyReport) {
	report.Finalize()
}

// checkEIDASAnchorMetadata inventories anchor records whose metadata declares
// backend == "eidas-qtsp" and checks that integrated_time is parseable and no
// older than maxAge. It does not parse or verify an RFC 3161 token, validate a
// message imprint or signature, consult an EU Trusted List, establish receipt
// coverage, or prove eIDAS/QTSP qualification.
//
// Anchor receipts are looked up under <bundle>/02_PROOFGRAPH/anchors/*.json
// and as embedded shapes inside <bundle>/00_INDEX.json (key "anchor"). The
// receipt JSON shape mirrors anchor.AnchorReceipt: {backend, log_id,
// log_index, integrated_time, signature, request:{...}}.
func checkEIDASAnchorMetadata(bundleRoot string, maxAge time.Duration) []verifier.CheckResult {
	const eidasBackend = "eidas-qtsp"

	results := make([]verifier.CheckResult, 0, 4)

	// Inventory candidate anchors from the pack, read through an os.Root on
	// its directory: a link out of the pack or a named pipe is refused.
	pack, packErr := packfs.Open(bundleRoot)
	if packErr != nil {
		return append(results, verifier.CheckResult{
			Name:   "eidas:read_anchor",
			Pass:   false,
			Reason: fmt.Sprintf("cannot open the pack: %v", packErr),
		})
	}
	defer func() { _ = pack.Close() }()
	const anchorsName = "02_PROOFGRAPH/anchors"
	anchorsDir := filepath.Join(bundleRoot, "02_PROOFGRAPH", "anchors")
	entries, err := pack.ReadDir(anchorsName)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		results = append(results, verifier.CheckResult{
			Name:   "eidas:read_anchor",
			Pass:   false,
			Reason: fmt.Sprintf("cannot read %s: %v", anchorsName, err),
		})
	}

	type anchorMeta struct {
		Path           string
		Backend        string
		IntegratedRaw  string
		IntegratedTime time.Time
	}
	var anchors []anchorMeta

	for _, ent := range entries {
		if ent.IsDir() || !strings.HasSuffix(ent.Name(), ".json") {
			continue
		}
		path := filepath.Join(anchorsDir, ent.Name())
		data, err := pack.ReadFile(anchorsName + "/" + ent.Name())
		if err != nil {
			results = append(results, verifier.CheckResult{
				Name:   "eidas:read_anchor",
				Pass:   false,
				Reason: fmt.Sprintf("cannot read %s: %v", path, err),
			})
			continue
		}
		var doc map[string]any
		if err := json.Unmarshal(data, &doc); err != nil {
			results = append(results, verifier.CheckResult{
				Name:   "eidas:parse_anchor",
				Pass:   false,
				Reason: fmt.Sprintf("cannot parse %s: %v", path, err),
			})
			continue
		}
		backend, _ := doc["backend"].(string)
		ts, _ := doc["integrated_time"].(string)
		parsed, _ := time.Parse(time.RFC3339, ts)
		anchors = append(anchors, anchorMeta{Path: path, Backend: backend, IntegratedRaw: ts, IntegratedTime: parsed})
	}

	// Also check 00_INDEX.json's embedded anchor field, when present.
	if data, err := pack.ReadFile("00_INDEX.json"); err != nil && !errors.Is(err, fs.ErrNotExist) {
		results = append(results, verifier.CheckResult{
			Name:   "eidas:read_anchor",
			Pass:   false,
			Reason: fmt.Sprintf("cannot read 00_INDEX.json: %v", err),
		})
	} else if err == nil {
		var doc map[string]any
		if json.Unmarshal(data, &doc) == nil {
			if a, ok := doc["anchor"].(map[string]any); ok {
				backend, _ := a["backend"].(string)
				ts, _ := a["integrated_time"].(string)
				parsed, _ := time.Parse(time.RFC3339, ts)
				anchors = append(anchors, anchorMeta{Path: "00_INDEX.json#anchor", Backend: backend, IntegratedRaw: ts, IntegratedTime: parsed})
			}
		}
	}

	if len(anchors) == 0 {
		results = append(results, verifier.CheckResult{
			Name:   "eidas:require",
			Pass:   false,
			Reason: "no anchor metadata found under 02_PROOFGRAPH/anchors/ or 00_INDEX.json#anchor; --require-eidas needs at least one record declaring backend=eidas-qtsp and does not establish eIDAS qualification",
		})
		return results
	}

	now := time.Now().UTC()
	hasEIDAS := false
	for _, a := range anchors {
		if a.Backend != eidasBackend {
			results = append(results, verifier.CheckResult{
				Name:   "eidas:anchor_backend",
				Pass:   false,
				Reason: fmt.Sprintf("anchor %s has backend %q, not %q", a.Path, a.Backend, eidasBackend),
			})
			continue
		}
		hasEIDAS = true
		if strings.TrimSpace(a.IntegratedRaw) == "" || a.IntegratedTime.IsZero() {
			results = append(results, verifier.CheckResult{
				Name:   "eidas:anchor_metadata",
				Pass:   false,
				Reason: fmt.Sprintf("anchor %s must declare integrated_time as RFC3339 metadata; no timestamp token or EU Trusted List verification was performed", a.Path),
			})
			continue
		}
		if maxAge > 0 && now.Sub(a.IntegratedTime) > maxAge {
			results = append(results, verifier.CheckResult{
				Name: "eidas:anchor_freshness",
				Pass: false,
				Reason: fmt.Sprintf("anchor %s integrated_time %s is older than --eidas-max-age-hours window of %s",
					a.Path, a.IntegratedTime.Format(time.RFC3339), maxAge),
			})
			continue
		}
		results = append(results, verifier.CheckResult{
			Name:   "eidas:anchor_metadata",
			Pass:   true,
			Detail: fmt.Sprintf("%s declares backend=%s and integrated_time=%s; metadata only, RFC 3161 token and EU Trusted List were not verified", a.Path, eidasBackend, a.IntegratedTime.Format(time.RFC3339)),
		})
	}

	if !hasEIDAS {
		results = append(results, verifier.CheckResult{
			Name:   "eidas:require",
			Pass:   false,
			Reason: "no anchor with backend=eidas-qtsp found",
		})
	}

	return results
}

// checkTEEAttestations enforces --require-tee on a verified bundle. The
// `platform` argument selects the strictness:
//
//   - sevsnp | tdx | nitro: every receipt must carry a tee_attestation
//     whose platform field matches.
//   - any: every receipt must carry some tee_attestation regardless of
//     platform; useful for multi-platform fleets.
//
// helm-ai-kernel receipts grow a `tee_attestation` field as the kernel-side
// receipt extension lands (Workstream A3). Until each receipt actually
// carries one, this check fails closed - which is the right default for a
// flag named `--require-`.
func checkTEEAttestations(bundleRoot string, platform string) []verifier.CheckResult {
	platform = strings.ToLower(strings.TrimSpace(platform))
	switch platform {
	case "sevsnp", "tdx", "nitro", "any":
	default:
		return []verifier.CheckResult{{
			Name:   "tee:platform",
			Pass:   false,
			Reason: fmt.Sprintf("unknown --require-tee value %q (want sevsnp|tdx|nitro|any)", platform),
		}}
	}

	// Receipts are read through an os.Root on the pack directory: a link out
	// of the pack or a named pipe is refused.
	pack, err := packfs.Open(bundleRoot)
	if err != nil {
		return []verifier.CheckResult{{
			Name:   "tee:read_receipt",
			Pass:   false,
			Reason: fmt.Sprintf("cannot open the pack: %v", err),
		}}
	}
	defer func() { _ = pack.Close() }()
	receiptsDir := filepath.Join(bundleRoot, "receipts")
	entries, err := pack.ReadDir("receipts")

	var results []verifier.CheckResult
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		results = append(results, verifier.CheckResult{
			Name:   "tee:read_receipt",
			Pass:   false,
			Reason: fmt.Sprintf("cannot read receipts: %v", err),
		})
	}
	receiptsSeen := 0
	receiptsWithTEE := 0
	receiptsWrongPlatform := 0

	for _, ent := range entries {
		if ent.IsDir() || !strings.HasSuffix(ent.Name(), ".json") {
			continue
		}
		path := filepath.Join(receiptsDir, ent.Name())
		data, err := pack.ReadFile("receipts/" + ent.Name())
		if err != nil {
			results = append(results, verifier.CheckResult{
				Name:   "tee:read_receipt",
				Pass:   false,
				Reason: fmt.Sprintf("cannot read %s: %v", path, err),
			})
			continue
		}
		var doc map[string]any
		if err := json.Unmarshal(data, &doc); err != nil {
			continue
		}
		receiptsSeen++

		att, ok := doc["tee_attestation"].(map[string]any)
		if !ok {
			results = append(results, verifier.CheckResult{
				Name:   "tee:receipt_attested",
				Pass:   false,
				Reason: fmt.Sprintf("%s missing tee_attestation field; --require-tee=%s demands it on every receipt", ent.Name(), platform),
			})
			continue
		}
		receiptsWithTEE++

		gotPlatform, _ := att["platform"].(string)
		if platform != "any" && !strings.EqualFold(gotPlatform, platform) {
			receiptsWrongPlatform++
			results = append(results, verifier.CheckResult{
				Name:   "tee:platform_match",
				Pass:   false,
				Reason: fmt.Sprintf("%s has tee_attestation.platform=%q; --require-tee=%s requires %s", ent.Name(), gotPlatform, platform, platform),
			})
			continue
		}

		results = append(results, verifier.CheckResult{
			Name:   "tee:receipt_attested",
			Pass:   true,
			Detail: fmt.Sprintf("%s carries tee_attestation platform=%s", ent.Name(), gotPlatform),
		})
	}

	if receiptsSeen == 0 {
		results = append(results, verifier.CheckResult{
			Name:   "tee:require",
			Pass:   false,
			Reason: fmt.Sprintf("no receipts found under %s; --require-tee=%s needs at least one TEE-attested receipt", receiptsDir, platform),
		})
	}

	return results
}

func init() {
	Register(Subcommand{Name: "verify", Aliases: []string{}, Usage: "Verify EvidencePack bundle ([path] --bundle, --json, --online, --require-check, --require-eidas, --require-tee), a Kernel receipt.v5 file (receipt --receipt --trusted-public-key-file), a single redacted entry (--entry <path> --proof <file>), or an external decision receipt (decision-receipt <file> --format --public-key --json)", RunFn: runVerifyCmd})
}
