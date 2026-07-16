package main

// quantum_posture: campaign trust delegates to the EvidencePack verifier's
// classical Ed25519 trust profiles; no post-quantum assurance is claimed.

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/conform"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/conform/adversarial"
	evidencepkg "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/evidence"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/verifier"
)

const (
	adversarialCampaignSchemaVersion = "helm.adversarial_campaign_report.v1"
	maxAdversarialSnapshotEntries    = 4096
)

type adversarialCampaignStatus string

const (
	adversarialCampaignStatusPassed                   adversarialCampaignStatus = "passed"
	adversarialCampaignStatusBundleVerificationFailed adversarialCampaignStatus = "bundle_verification_failed"
	adversarialCampaignStatusCoverageIncomplete       adversarialCampaignStatus = "coverage_incomplete"
	adversarialCampaignStatusAdversarialFailed        adversarialCampaignStatus = "adversarial_failed"
)

// adversarialCampaignReport intentionally omits wall-clock timestamps and
// machine-local paths. Repeated offline runs are byte-identical when the sealed
// pack, verifier version, explicit trust inputs, and time-sensitive trust
// verdicts are unchanged.
type adversarialCampaignReport struct {
	SchemaVersion          string                      `json:"schema_version"`
	Pass                   bool                        `json:"pass"`
	Status                 adversarialCampaignStatus   `json:"status"`
	TrustProfile           string                      `json:"trust_profile"`
	EvaluationTime         string                      `json:"evaluation_time"`
	CampaignTrustKeyID     string                      `json:"campaign_trust_key_id"`
	BundleVerified         bool                        `json:"bundle_verified"`
	VerifierVersion        string                      `json:"verifier_version"`
	VerificationSummary    string                      `json:"verification_summary"`
	VerificationIssueCount int                         `json:"verification_issue_count"`
	VerificationChecks     []verifier.CheckResult      `json:"verification_checks"`
	EvidenceRoot           string                      `json:"evidence_root,omitempty"`
	MerkleRoot             string                      `json:"merkle_root,omitempty"`
	IndexEntryCount        int                         `json:"index_entry_count"`
	MandatorySuites        int                         `json:"mandatory_suites"`
	CoverageVerified       bool                        `json:"coverage_verified"`
	CoveredSuites          int                         `json:"covered_suites"`
	MissingSuites          int                         `json:"missing_suites"`
	CoverageChecks         []adversarial.CoverageCheck `json:"coverage_checks"`
	ExecutedSuites         int                         `json:"executed_suites"`
	PassedSuites           int                         `json:"passed_suites"`
	FailedSuites           int                         `json:"failed_suites"`
	Suites                 []*adversarial.SuiteResult  `json:"suites,omitempty"`
	UntestedRegions        []string                    `json:"untested_regions"`
	KnownLimitations       []string                    `json:"known_limitations"`
	RunnerProvenance       adversarialRunnerProvenance `json:"runner_provenance"`
	Attestation            adversarialAttestation      `json:"attestation"`
}

type adversarialRunnerProvenance struct {
	KernelCommit             string `json:"kernel_commit"`
	ExecutableSHA256         string `json:"executable_sha256"`
	DetectorRevision         string `json:"detector_revision"`
	DetectorDefinitionSHA256 string `json:"detector_definition_sha256"`
}

type adversarialAttestation struct {
	Algorithm string `json:"algorithm"`
	KeyID     string `json:"key_id"`
	Signature string `json:"signature"`
}

// runConformAdversarial implements `helm-ai-kernel conform adversarial`.
//
// Exit codes:
//
//	0 = EvidencePack verification and all mandatory adversarial suites pass
//	1 = EvidencePack verification or any adversarial suite fails
//	2 = invalid configuration or runtime/report-writing error
func runConformAdversarial(args []string, stdout, stderr io.Writer) int {
	if len(args) > 0 && args[0] == "verify-report" {
		return runVerifyAdversarialCampaignReport(args[1:], stdout, stderr)
	}
	cmd := flag.NewFlagSet("conform adversarial", flag.ContinueOnError)
	cmd.SetOutput(stderr)

	var (
		bundle            string
		profile           string
		configPath        string
		storageReceipt    string
		externalHostKey   string
		trustedPublicKey  string
		managedAgentKey   string
		campaignPublicKey string
		evaluationTimeRaw string
		kernelCommit      string
		reportPath        string
		jsonOutput        bool
	)
	cmd.StringVar(&bundle, "bundle", "", "Path to a sealed EvidencePack directory or archive")
	cmd.StringVar(&profile, "profile", "", "Required EvidencePack trust profile: dev-local, team, customer, or high-assurance")
	cmd.StringVar(&configPath, "config", "", "Evidence trust config path")
	cmd.StringVar(&storageReceipt, "storage-receipt", "", "S3 Object Lock storage receipt for customer/high-assurance verification")
	cmd.StringVar(&externalHostKey, "external-host-public-key", strings.TrimSpace(os.Getenv("HELM_EXTERNAL_HOST_PUBLIC_KEY_HEX")), "Trusted Ed25519 key for external host evidence")
	cmd.StringVar(&trustedPublicKey, "trusted-public-key", strings.TrimSpace(os.Getenv("HELM_VERIFY_PUBLIC_KEY_HEX")), "Trusted Ed25519 key for conformance report signatures")
	cmd.StringVar(&managedAgentKey, "managed-agent-receipt-public-key", strings.TrimSpace(os.Getenv("HELM_MANAGED_AGENT_RECEIPT_PUBLIC_KEY_HEX")), "Trusted Ed25519 key for embedded managed-agent receipts")
	cmd.StringVar(&campaignPublicKey, "campaign-public-key", strings.TrimSpace(os.Getenv("HELM_BOUNTY_CAMPAIGN_PUBLIC_KEY_HEX")), "Required external Ed25519 trust root for campaign authorization and tool signatures")
	cmd.StringVar(&evaluationTimeRaw, "evaluation-time", strings.TrimSpace(os.Getenv("HELM_BOUNTY_EVALUATION_TIME_RFC3339")), "Required RFC3339 trust-evaluation time for deterministic replay")
	cmd.StringVar(&kernelCommit, "kernel-commit", strings.TrimSpace(os.Getenv("HELM_KERNEL_COMMIT")), "Required exact Kernel commit for runner provenance")
	cmd.StringVar(&reportPath, "report", "", "Required output path for the deterministic campaign report (must be outside the sealed pack)")
	cmd.BoolVar(&jsonOutput, "json", false, "Also emit the deterministic campaign report as JSON to stdout")
	if err := cmd.Parse(args); err != nil {
		return 2
	}
	if cmd.NArg() != 0 {
		_, _ = fmt.Fprintf(stderr, "Error: unexpected argument: %s\n", cmd.Arg(0))
		return 2
	}
	if strings.TrimSpace(bundle) == "" {
		_, _ = fmt.Fprintln(stderr, "Error: --bundle is required")
		return 2
	}
	if strings.TrimSpace(profile) == "" {
		_, _ = fmt.Fprintln(stderr, "Error: --profile is required; strict campaigns never default to dev-local")
		return 2
	}
	trustProfile, err := parseAdversarialTrustProfile(profile)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: %v\n", err)
		return 2
	}
	if strings.TrimSpace(reportPath) == "" {
		_, _ = fmt.Fprintln(stderr, "Error: --report is required so every campaign has a durable deterministic artifact")
		return 2
	}
	campaignTrustKeyID, err := adversarial.CampaignKeyID(campaignPublicKey)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: --campaign-public-key is required and invalid: %v\n", err)
		return 2
	}
	evaluationTime, err := time.Parse(time.RFC3339, strings.TrimSpace(evaluationTimeRaw))
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: --evaluation-time must be RFC3339: %v\n", err)
		return 2
	}
	if strings.TrimSpace(kernelCommit) == "" {
		_, _ = fmt.Fprintln(stderr, "Error: --kernel-commit is required for exact runner provenance")
		return 2
	}
	embeddedCommit := strings.TrimSpace(commit)
	if embeddedCommit == "" || embeddedCommit == "unknown" {
		_, _ = fmt.Fprintln(stderr, "Error: campaign runner binary has no embedded source commit")
		return 2
	}
	if strings.TrimSpace(kernelCommit) != embeddedCommit {
		_, _ = fmt.Fprintf(stderr, "Error: --kernel-commit %s does not match embedded runner commit %s\n", strings.TrimSpace(kernelCommit), embeddedCommit)
		return 2
	}
	executableDigest, err := currentExecutableSHA256()
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: cannot hash campaign executable: %v\n", err)
		return 2
	}
	detectorDigest, err := adversarial.DefinitionDigest()
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: cannot hash detector definition: %v\n", err)
		return 2
	}
	runner := adversarialRunnerProvenance{
		KernelCommit:             strings.TrimSpace(kernelCommit),
		ExecutableSHA256:         executableDigest,
		DetectorRevision:         adversarial.DetectorRevision,
		DetectorDefinitionSHA256: detectorDigest,
	}
	verificationOpts := adversarial.VerificationOptions{CampaignPublicKeyHex: campaignPublicKey}

	bundleInfo, err := os.Stat(bundle)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: cannot open EvidencePack: %v\n", err)
		return 2
	}
	if pathWithin(reportPath, bundle) {
		_, _ = fmt.Fprintln(stderr, "Error: --report must be outside the sealed EvidencePack")
		return 2
	}
	storageObjectPath := ""
	if !bundleInfo.IsDir() {
		storageObjectPath = bundle
	}

	var campaign adversarialCampaignReport
	err = withAdversarialEvidenceSnapshot(bundle, func(packDir string) error {
		verification, verifyErr := verifyAdversarialCampaignBundle(packDir, adversarialBundleVerifyOptions{
			Profile:               trustProfile,
			ConfigPath:            configPath,
			StorageReceiptPath:    storageReceipt,
			StorageObjectPath:     storageObjectPath,
			ExternalHostKeyHex:    externalHostKey,
			TrustedPublicKeyHex:   trustedPublicKey,
			ManagedAgentPublicKey: managedAgentKey,
			Now:                   evaluationTime.UTC(),
		})
		if verifyErr != nil {
			return verifyErr
		}
		campaign = newAdversarialCampaignReport(trustProfile, evaluationTime.UTC(), campaignTrustKeyID, runner, verification)
		if !verification.Verified {
			return nil
		}
		coverage := adversarial.EvaluateCoverageWithOptions(packDir, verificationOpts)
		campaign.CoverageVerified = coverage.Pass
		campaign.CoveredSuites = coverage.CoveredSuites
		campaign.MissingSuites = coverage.MissingSuites
		campaign.CoverageChecks = coverage.Checks
		if !coverage.Pass {
			campaign.Status = adversarialCampaignStatusCoverageIncomplete
			return nil
		}

		result := adversarial.RunAllWithOptions(packDir, verificationOpts)
		campaign.ExecutedSuites = len(result.Suites)
		campaign.PassedSuites = result.PassedSuites
		campaign.FailedSuites = result.FailedSuites
		campaign.Suites = result.Suites
		campaign.Pass = result.Pass && campaign.ExecutedSuites == campaign.MandatorySuites
		if campaign.Pass {
			campaign.Status = adversarialCampaignStatusPassed
		} else {
			campaign.Status = adversarialCampaignStatusAdversarialFailed
		}
		return nil
	})
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: adversarial campaign failed to run: %v\n", err)
		return 2
	}
	if err := signAdversarialCampaignReport(&campaign); err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: cannot attest campaign report: %v\n", err)
		return 2
	}

	reportData, err := marshalAdversarialCampaignReport(campaign)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: cannot encode campaign report: %v\n", err)
		return 2
	}
	if err := writeAdversarialCampaignReport(reportPath, reportData); err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: cannot write campaign report: %v\n", err)
		return 2
	}

	if jsonOutput {
		_, _ = stdout.Write(reportData)
	} else {
		_, _ = fmt.Fprintf(stdout, "Kernel adversarial campaign: %s\n", campaign.Status)
		_, _ = fmt.Fprintf(stdout, "  EvidencePack verified: %t (%s)\n", campaign.BundleVerified, campaign.TrustProfile)
		_, _ = fmt.Fprintf(stdout, "  Suites: %d/%d passed\n", campaign.PassedSuites, campaign.MandatorySuites)
		_, _ = fmt.Fprintf(stdout, "  Report: %s\n", reportPath)
	}
	if !campaign.Pass {
		return 1
	}
	return 0
}

func runVerifyAdversarialCampaignReport(args []string, stdout, stderr io.Writer) int {
	cmd := flag.NewFlagSet("conform adversarial verify-report", flag.ContinueOnError)
	cmd.SetOutput(stderr)
	var reportPath, trustedPublicKey, expectedKernelCommit, expectedExecutableSHA string
	var jsonOutput bool
	cmd.StringVar(&reportPath, "report", "", "Path to an attested adversarial campaign report")
	cmd.StringVar(&trustedPublicKey, "trusted-public-key", strings.TrimSpace(os.Getenv("HELM_VERIFY_PUBLIC_KEY_HEX")), "Externally trusted Ed25519 report-attestation public key")
	cmd.StringVar(&expectedKernelCommit, "expected-kernel-commit", "", "Optional exact Kernel commit required by downstream policy")
	cmd.StringVar(&expectedExecutableSHA, "expected-executable-sha256", "", "Optional exact runner executable digest required by downstream policy")
	cmd.BoolVar(&jsonOutput, "json", false, "Emit the authenticated campaign report as JSON")
	if err := cmd.Parse(args); err != nil {
		return 2
	}
	if cmd.NArg() != 0 || strings.TrimSpace(reportPath) == "" || strings.TrimSpace(trustedPublicKey) == "" {
		_, _ = fmt.Fprintln(stderr, "Error: --report and --trusted-public-key are required")
		return 2
	}
	data, err := os.ReadFile(reportPath)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: cannot read campaign report: %v\n", err)
		return 2
	}
	var report adversarialCampaignReport
	if err := json.Unmarshal(data, &report); err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: cannot decode campaign report: %v\n", err)
		return 2
	}
	if report.SchemaVersion != adversarialCampaignSchemaVersion || report.RunnerProvenance.KernelCommit == "" || report.RunnerProvenance.ExecutableSHA256 == "" || report.RunnerProvenance.DetectorDefinitionSHA256 == "" {
		_, _ = fmt.Fprintln(stderr, "Error: campaign report provenance is incomplete or unsupported")
		return 1
	}
	if err := verifyAdversarialCampaignReportAttestation(report, trustedPublicKey); err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: %v\n", err)
		return 1
	}
	if expected := strings.TrimSpace(expectedKernelCommit); expected != "" && report.RunnerProvenance.KernelCommit != expected {
		_, _ = fmt.Fprintf(stderr, "Error: kernel commit mismatch: got %s want %s\n", report.RunnerProvenance.KernelCommit, expected)
		return 1
	}
	if expected := strings.TrimSpace(expectedExecutableSHA); expected != "" && report.RunnerProvenance.ExecutableSHA256 != expected {
		_, _ = fmt.Fprintf(stderr, "Error: executable digest mismatch: got %s want %s\n", report.RunnerProvenance.ExecutableSHA256, expected)
		return 1
	}
	if report.Pass != (report.Status == adversarialCampaignStatusPassed) {
		_, _ = fmt.Fprintln(stderr, "Error: campaign report pass/status fields are inconsistent")
		return 1
	}
	if jsonOutput {
		verified, err := marshalAdversarialCampaignReport(report)
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "Error: cannot encode verified campaign report: %v\n", err)
			return 2
		}
		_, _ = stdout.Write(verified)
	} else {
		_, _ = fmt.Fprintf(stdout, "Kernel adversarial campaign attestation: verified\n  Status: %s\n  Kernel commit: %s\n  Executable: %s\n", report.Status, report.RunnerProvenance.KernelCommit, report.RunnerProvenance.ExecutableSHA256)
	}
	if !report.Pass {
		return 1
	}
	return 0
}

type adversarialBundleVerifyOptions struct {
	Profile               evidencepkg.EvidenceTrustProfile
	ConfigPath            string
	StorageReceiptPath    string
	StorageObjectPath     string
	ExternalHostKeyHex    string
	TrustedPublicKeyHex   string
	ManagedAgentPublicKey string
	Now                   time.Time
}

func verifyAdversarialCampaignBundle(packDir string, opts adversarialBundleVerifyOptions) (*verifier.VerifyReport, error) {
	conformanceSigPresent := hasConformanceSignature(packDir)
	var conformanceSigErr error
	allowVerifiedConformanceSignature := false
	if conformanceSigPresent {
		conformanceSigErr = verifyConformanceReportSignature(packDir, opts.TrustedPublicKeyHex)
		allowVerifiedConformanceSignature = conformanceSigErr == nil
	}
	report, err := verifier.VerifyBundleWithOptions(packDir, verifier.VerifyOptions{
		Profile:                           opts.Profile,
		ConfigPath:                        opts.ConfigPath,
		StorageReceiptPath:                opts.StorageReceiptPath,
		StorageObjectPath:                 opts.StorageObjectPath,
		ExternalHostKeyHex:                opts.ExternalHostKeyHex,
		ManagedAgentReceiptPublicKeyHex:   opts.ManagedAgentPublicKey,
		Now:                               opts.Now,
		AllowVerifiedConformanceSignature: allowVerifiedConformanceSignature,
	})
	if err != nil {
		return nil, err
	}
	if hasCanonicalEvidenceLayout(packDir) {
		for _, issue := range conform.ValidateEvidencePackStructure(packDir) {
			report.Checks = append(report.Checks, verifier.CheckResult{
				Name:   "conform:" + issue,
				Pass:   false,
				Reason: issue,
			})
		}
	}
	if conformanceSigPresent && conformanceSigErr != nil {
		report.Checks = append(report.Checks, verifier.CheckResult{
			Name:   "signature_verification",
			Pass:   false,
			Reason: fmt.Sprintf("signature: %v", conformanceSigErr),
		})
	}
	finalizeVerifyReport(report)
	report.Checks = sanitizeAdversarialVerificationChecks(report.Checks, []adversarialPathReplacement{
		{Source: opts.StorageReceiptPath, Replacement: "<storage-receipt>"},
		{Source: opts.StorageObjectPath, Replacement: "<storage-object>"},
		{Source: opts.ConfigPath, Replacement: "<trust-config>"},
		{Source: strings.TrimSpace(os.Getenv("HELM_EVIDENCE_TRUST_CONFIG")), Replacement: "<trust-config>"},
		{Source: evidencepkg.EvidencePackTrustConfigPath(""), Replacement: "<trust-config>"},
		{Source: packDir, Replacement: "<evidence-pack>"},
	})
	return report, nil
}

func newAdversarialCampaignReport(profile evidencepkg.EvidenceTrustProfile, evaluationTime time.Time, campaignTrustKeyID string, runner adversarialRunnerProvenance, verification *verifier.VerifyReport) adversarialCampaignReport {
	return adversarialCampaignReport{
		SchemaVersion:          adversarialCampaignSchemaVersion,
		Pass:                   false,
		Status:                 adversarialCampaignStatusBundleVerificationFailed,
		TrustProfile:           string(profile),
		EvaluationTime:         evaluationTime.Format(time.RFC3339),
		CampaignTrustKeyID:     campaignTrustKeyID,
		BundleVerified:         verification.Verified,
		VerifierVersion:        verification.VerifierVer,
		VerificationSummary:    verification.Summary,
		VerificationIssueCount: verification.IssueCount,
		VerificationChecks:     verification.Checks,
		EvidenceRoot:           verification.Roots.ManifestRootHash,
		MerkleRoot:             verification.MerkleRoot,
		IndexEntryCount:        verification.Roots.EntryCount,
		MandatorySuites:        len(adversarial.AllSuites()),
		UntestedRegions: []string{
			"model/provider clean-room execution",
			"independent SecurityFinding verification lifecycle",
			"patch generation and regression validation",
			"staging, production smoke, and soak",
		},
		KnownLimitations: []string{
			"the campaign evaluates only artifacts present in the supplied sealed EvidencePack",
			"a passing report is conformance evidence, not a bug-free or production-ready claim",
			"producer, verifier, and patcher identity separation is enforced by the HELM control plane, not this offline command",
		},
		RunnerProvenance: runner,
	}
}

func parseAdversarialTrustProfile(raw string) (evidencepkg.EvidenceTrustProfile, error) {
	profile := normalizeEvidenceTrustProfile(raw)
	switch profile {
	case evidencepkg.EvidenceTrustProfileDevLocal,
		evidencepkg.EvidenceTrustProfileTeam,
		evidencepkg.EvidenceTrustProfileCustomer,
		evidencepkg.EvidenceTrustProfileHighAssurance:
		return profile, nil
	default:
		return "", fmt.Errorf("unsupported --profile %q (valid: dev-local, team, customer, high-assurance)", raw)
	}
}

func marshalAdversarialCampaignReport(report adversarialCampaignReport) ([]byte, error) {
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

func writeAdversarialCampaignReport(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".helm-adversarial-campaign-*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath) //nolint:errcheck
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close() //nolint:errcheck
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close() //nolint:errcheck
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close() //nolint:errcheck
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpPath, path)
}

func pathWithin(path, root string) bool {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return false
	}
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return false
	}
	absPath = resolveExistingSymlinks(absPath)
	absRoot = resolveExistingSymlinks(absRoot)
	rel, err := filepath.Rel(absRoot, absPath)
	if err != nil {
		return false
	}
	return rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)))
}

func resolveExistingSymlinks(path string) string {
	current := filepath.Clean(path)
	missing := []string{}
	for {
		if resolved, err := filepath.EvalSymlinks(current); err == nil {
			for i := len(missing) - 1; i >= 0; i-- {
				resolved = filepath.Join(resolved, missing[i])
			}
			return resolved
		}
		parent := filepath.Dir(current)
		if parent == current {
			return filepath.Clean(path)
		}
		missing = append(missing, filepath.Base(current))
		current = parent
	}
}

func withAdversarialEvidenceSnapshot(bundle string, fn func(string) error) error {
	info, err := os.Stat(bundle)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return withEvidenceBundleDir(bundle, fn)
	}
	tempDir, err := os.MkdirTemp("", "helm-adversarial-snapshot-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tempDir)
	snapshot := filepath.Join(tempDir, "evidence-pack")
	if err := copyAdversarialEvidenceDirectory(bundle, snapshot, maxAdversarialSnapshotEntries); err != nil {
		return err
	}
	return fn(snapshot)
}

func copyAdversarialEvidenceDirectory(source, destination string, maxEntries int) error {
	var copiedBytes int64
	entries := 0
	return filepath.WalkDir(source, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("EvidencePack snapshot rejects symlink: %s", entry.Name())
		}
		entries++
		if entries > maxEntries {
			return fmt.Errorf("EvidencePack snapshot exceeds %d entries", maxEntries)
		}
		rel, err := filepath.Rel(source, path)
		if err != nil {
			return err
		}
		target := filepath.Join(destination, rel)
		if entry.IsDir() {
			return os.MkdirAll(target, 0o750)
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("EvidencePack snapshot rejects non-regular file: %s", entry.Name())
		}
		copiedBytes += info.Size()
		if info.Size() > maxEvidenceBundleBytes || copiedBytes > maxEvidenceBundleBytes {
			return fmt.Errorf("EvidencePack snapshot exceeds %d bytes", maxEvidenceBundleBytes)
		}
		input, err := os.Open(path)
		if err != nil {
			return err
		}
		openedInfo, statErr := input.Stat()
		if statErr != nil || !os.SameFile(info, openedInfo) || !openedInfo.Mode().IsRegular() {
			input.Close() //nolint:errcheck
			return fmt.Errorf("EvidencePack changed while snapshotting: %s", entry.Name())
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o750); err != nil {
			input.Close() //nolint:errcheck
			return err
		}
		output, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			input.Close() //nolint:errcheck
			return err
		}
		_, copyErr := io.Copy(output, io.LimitReader(input, info.Size()+1))
		closeOutputErr := output.Close()
		closeInputErr := input.Close()
		if copyErr != nil {
			return copyErr
		}
		if closeOutputErr != nil {
			return closeOutputErr
		}
		if closeInputErr != nil {
			return closeInputErr
		}
		finalInfo, err := os.Stat(target)
		if err != nil || finalInfo.Size() != info.Size() {
			return fmt.Errorf("EvidencePack changed while snapshotting: %s", entry.Name())
		}
		return nil
	})
}

func currentExecutableSHA256() (string, error) {
	path, err := os.Executable()
	if err != nil {
		return "", err
	}
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}
	return "sha256:" + hex.EncodeToString(hash.Sum(nil)), nil
}

func signAdversarialCampaignReport(report *adversarialCampaignReport) error {
	privateKey, publicKeyHex, err := externalFailureSigningKey()
	if err != nil {
		return fmt.Errorf("HELM_SIGNING_KEY_HEX is required for campaign attestation: %w", err)
	}
	publicKey, err := hex.DecodeString(publicKeyHex)
	if err != nil || len(publicKey) != ed25519.PublicKeySize {
		return fmt.Errorf("derive campaign attestation public key")
	}
	keyHash := sha256.Sum256(publicKey)
	report.Attestation = adversarialAttestation{
		Algorithm: "ed25519",
		KeyID:     "sha256:" + hex.EncodeToString(keyHash[:]),
	}
	payload, err := canonicalAdversarialCampaignReport(*report)
	if err != nil {
		return err
	}
	report.Attestation.Signature = hex.EncodeToString(ed25519.Sign(privateKey, payload))
	return nil
}

func canonicalAdversarialCampaignReport(report adversarialCampaignReport) ([]byte, error) {
	report.Attestation.Signature = ""
	return canonicalJSON(report)
}

func verifyAdversarialCampaignReportAttestation(report adversarialCampaignReport, trustedPublicKeyHex string) error {
	if report.Attestation.Algorithm != "ed25519" {
		return fmt.Errorf("unsupported campaign attestation algorithm %q", report.Attestation.Algorithm)
	}
	publicKey, err := hex.DecodeString(strings.TrimSpace(trustedPublicKeyHex))
	if err != nil || len(publicKey) != ed25519.PublicKeySize {
		return fmt.Errorf("trusted campaign attestation key must be Ed25519 hex")
	}
	keyHash := sha256.Sum256(publicKey)
	if report.Attestation.KeyID != "sha256:"+hex.EncodeToString(keyHash[:]) {
		return fmt.Errorf("campaign attestation key id mismatch")
	}
	signature, err := hex.DecodeString(strings.TrimSpace(report.Attestation.Signature))
	if err != nil || len(signature) != ed25519.SignatureSize {
		return fmt.Errorf("invalid campaign attestation signature encoding")
	}
	payload, err := canonicalAdversarialCampaignReport(report)
	if err != nil {
		return err
	}
	if !ed25519.Verify(ed25519.PublicKey(publicKey), payload, signature) {
		return fmt.Errorf("campaign attestation signature verification failed")
	}
	return nil
}

type adversarialPathReplacement struct {
	Source      string
	Replacement string
}

func sanitizeAdversarialVerificationChecks(checks []verifier.CheckResult, replacements []adversarialPathReplacement) []verifier.CheckResult {
	sanitized := append([]verifier.CheckResult(nil), checks...)
	for i := range sanitized {
		for _, replacement := range replacements {
			source := strings.TrimSpace(replacement.Source)
			if source == "" {
				continue
			}
			sanitized[i].Detail = strings.ReplaceAll(sanitized[i].Detail, source, replacement.Replacement)
			sanitized[i].Reason = strings.ReplaceAll(sanitized[i].Reason, source, replacement.Replacement)
		}
	}
	return sanitized
}
