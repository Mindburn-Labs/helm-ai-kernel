package main

// quantum_posture: campaign trust delegates to the EvidencePack verifier's
// classical Ed25519 trust profiles; no post-quantum assurance is claimed.

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/conform"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/conform/adversarial"
	evidencepkg "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/evidence"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/verifier"
)

const adversarialCampaignSchemaVersion = "helm.adversarial_campaign_report.v1"

type adversarialCampaignStatus string

const (
	adversarialCampaignStatusPassed                   adversarialCampaignStatus = "passed"
	adversarialCampaignStatusBundleVerificationFailed adversarialCampaignStatus = "bundle_verification_failed"
	adversarialCampaignStatusCoverageIncomplete       adversarialCampaignStatus = "coverage_incomplete"
	adversarialCampaignStatusAdversarialFailed        adversarialCampaignStatus = "adversarial_failed"
)

// adversarialCampaignReport intentionally omits wall-clock timestamps and
// machine-local paths. The same sealed EvidencePack must produce byte-identical
// campaign reports on repeated offline runs with the same verifier version.
type adversarialCampaignReport struct {
	SchemaVersion          string                      `json:"schema_version"`
	Pass                   bool                        `json:"pass"`
	Status                 adversarialCampaignStatus   `json:"status"`
	TrustProfile           string                      `json:"trust_profile"`
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
}

// runConformAdversarial implements `helm-ai-kernel conform adversarial`.
//
// Exit codes:
//
//	0 = EvidencePack verification and all mandatory adversarial suites pass
//	1 = EvidencePack verification or any adversarial suite fails
//	2 = invalid configuration or runtime/report-writing error
func runConformAdversarial(args []string, stdout, stderr io.Writer) int {
	cmd := flag.NewFlagSet("conform adversarial", flag.ContinueOnError)
	cmd.SetOutput(stderr)

	var (
		bundle           string
		profile          string
		configPath       string
		storageReceipt   string
		externalHostKey  string
		trustedPublicKey string
		managedAgentKey  string
		reportPath       string
		jsonOutput       bool
	)
	cmd.StringVar(&bundle, "bundle", "", "Path to a sealed EvidencePack directory or archive")
	cmd.StringVar(&profile, "profile", "", "Required EvidencePack trust profile: dev-local, team, customer, or high-assurance")
	cmd.StringVar(&configPath, "config", "", "Evidence trust config path")
	cmd.StringVar(&storageReceipt, "storage-receipt", "", "S3 Object Lock storage receipt for customer/high-assurance verification")
	cmd.StringVar(&externalHostKey, "external-host-public-key", strings.TrimSpace(os.Getenv("HELM_EXTERNAL_HOST_PUBLIC_KEY_HEX")), "Trusted Ed25519 key for external host evidence")
	cmd.StringVar(&trustedPublicKey, "trusted-public-key", strings.TrimSpace(os.Getenv("HELM_VERIFY_PUBLIC_KEY_HEX")), "Trusted Ed25519 key for conformance report signatures")
	cmd.StringVar(&managedAgentKey, "managed-agent-receipt-public-key", strings.TrimSpace(os.Getenv("HELM_MANAGED_AGENT_RECEIPT_PUBLIC_KEY_HEX")), "Trusted Ed25519 key for embedded managed-agent receipts")
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

	bundleInfo, err := os.Stat(bundle)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: cannot open EvidencePack: %v\n", err)
		return 2
	}
	if bundleInfo.IsDir() && pathWithin(reportPath, bundle) {
		_, _ = fmt.Fprintln(stderr, "Error: --report must be outside the sealed EvidencePack")
		return 2
	}
	storageObjectPath := ""
	if !bundleInfo.IsDir() {
		storageObjectPath = bundle
	}

	var campaign adversarialCampaignReport
	err = withEvidenceBundleDir(bundle, func(packDir string) error {
		verification, verifyErr := verifyAdversarialCampaignBundle(packDir, adversarialBundleVerifyOptions{
			Profile:               trustProfile,
			ConfigPath:            configPath,
			StorageReceiptPath:    storageReceipt,
			StorageObjectPath:     storageObjectPath,
			ExternalHostKeyHex:    externalHostKey,
			TrustedPublicKeyHex:   trustedPublicKey,
			ManagedAgentPublicKey: managedAgentKey,
		})
		if verifyErr != nil {
			return verifyErr
		}
		campaign = newAdversarialCampaignReport(trustProfile, verification)
		if !verification.Verified {
			return nil
		}
		coverage := adversarial.EvaluateCoverage(packDir)
		campaign.CoverageVerified = coverage.Pass
		campaign.CoveredSuites = coverage.CoveredSuites
		campaign.MissingSuites = coverage.MissingSuites
		campaign.CoverageChecks = coverage.Checks
		if !coverage.Pass {
			campaign.Status = adversarialCampaignStatusCoverageIncomplete
			return nil
		}

		result := adversarial.RunAll(packDir)
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

type adversarialBundleVerifyOptions struct {
	Profile               evidencepkg.EvidenceTrustProfile
	ConfigPath            string
	StorageReceiptPath    string
	StorageObjectPath     string
	ExternalHostKeyHex    string
	TrustedPublicKeyHex   string
	ManagedAgentPublicKey string
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
		{Source: packDir, Replacement: "<evidence-pack>"},
	})
	return report, nil
}

func newAdversarialCampaignReport(profile evidencepkg.EvidenceTrustProfile, verification *verifier.VerifyReport) adversarialCampaignReport {
	return adversarialCampaignReport{
		SchemaVersion:          adversarialCampaignSchemaVersion,
		Pass:                   false,
		Status:                 adversarialCampaignStatusBundleVerificationFailed,
		TrustProfile:           string(profile),
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
