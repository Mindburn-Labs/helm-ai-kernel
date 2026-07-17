package main

// quantum_posture: campaign trust delegates to the EvidencePack verifier's
// classical Ed25519 trust profiles; no post-quantum assurance is claimed.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/conform"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/conform/adversarial"
	evidencepkg "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/evidence"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/verifier"
)

const (
	adversarialCampaignSchemaVersion = "helm.adversarial_campaign_report.v2"
	adversarialReportSignatureDomain = "helm.bounty.campaign-report-signature/v1"
	adversarialReportSigningKeyEnv   = "HELM_BOUNTY_REPORT_SIGNING_KEY_HEX"
	adversarialReportPublicKeyEnv    = "HELM_BOUNTY_REPORT_PUBLIC_KEY_HEX"
	maxAdversarialIdentifierBytes    = 128
	maxAdversarialSnapshotEntries    = maxEvidenceArchiveEntries
	maxAdversarialReportBytes        = 8 << 20
	maxAdversarialJSONDepth          = 128
)

// Keep an open handle for the process lifetime so executable provenance is
// bound to the image that was present at process initialization, not to a
// pathname that can be replaced later. Linux's /proc/self/exe resolves the
// running image even after the original pathname is renamed or deleted.
var (
	runningExecutableImage, runningExecutableImageErr = openRunningExecutableImage()
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
	CampaignID             string                      `json:"campaign_id"`
	RunID                  string                      `json:"run_id"`
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
	if len(args) > 0 && args[0] == "definition" {
		return runAdversarialDetectorDefinition(args[1:], stdout, stderr)
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
		campaignID        string
		runID             string
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
	cmd.StringVar(&campaignPublicKey, "campaign-public-key", strings.TrimSpace(os.Getenv(adversarial.CampaignPublicKeyEnv)), "Required external Ed25519 trust root for campaign authorization and tool signatures")
	cmd.StringVar(&campaignID, "campaign-id", strings.TrimSpace(os.Getenv(adversarial.CampaignIDEnv)), "Required stable campaign identifier")
	cmd.StringVar(&runID, "run-id", strings.TrimSpace(os.Getenv(adversarial.CampaignRunIDEnv)), "Required unique campaign-run identifier")
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
	campaignID, err = validateAdversarialIdentifier("campaign id", campaignID)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: --campaign-id is required and invalid: %v\n", err)
		return 2
	}
	runID, err = validateAdversarialIdentifier("run id", runID)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: --run-id is required and invalid: %v\n", err)
		return 2
	}
	evaluationTime, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(evaluationTimeRaw))
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: --evaluation-time must be RFC3339: %v\n", err)
		return 2
	}
	evaluationTime = evaluationTime.UTC()
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
	reportPrivateKey, reportPublicKeyHex, err := adversarialReportSigningKey()
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: campaign report attestation key is invalid: %v\n", err)
		return 2
	}
	verificationOpts := adversarial.VerificationOptions{
		CampaignPublicKeyHex: campaignPublicKey,
		CampaignID:           campaignID,
		RunID:                runID,
	}

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
		campaign = newAdversarialCampaignReport(campaignID, runID, trustProfile, evaluationTime.UTC(), campaignTrustKeyID, runner, verification.Report)
		if !verification.Report.Verified {
			return nil
		}
		verificationOpts.VerifiedEvidenceIndexHash = verification.Report.Roots.ManifestRootHash
		verificationOpts.VerifiedEvidenceMerkleRoot = verification.Report.Roots.MerkleRoot
		verificationOpts.VerifiedEvidenceEntryCount = verification.Report.Roots.EntryCount
		verificationOpts.AllowVerifiedConformanceSignature = verification.AllowVerifiedConformanceSignature
		result := adversarial.RunAllWithOptions(packDir, verificationOpts)
		campaign.CoverageVerified = result.Coverage.Pass
		campaign.CoveredSuites = result.Coverage.CoveredSuites
		campaign.MissingSuites = result.Coverage.MissingSuites
		campaign.CoverageChecks = result.Coverage.Checks
		if !result.Coverage.Pass {
			campaign.Status = adversarialCampaignStatusCoverageIncomplete
			return nil
		}
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
	if err := validateAdversarialCampaignReportSemantics(campaign); err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: refusing to attest an inconsistent campaign report: %v\n", err)
		return 2
	}
	if err := signAdversarialCampaignReportWithKey(&campaign, reportPrivateKey, reportPublicKeyHex); err != nil {
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
		_, _ = fmt.Fprintf(stdout, "  Campaign/run: %s/%s\n", campaign.CampaignID, campaign.RunID)
		_, _ = fmt.Fprintf(stdout, "  EvidencePack verified: %t (%s)\n", campaign.BundleVerified, campaign.TrustProfile)
		_, _ = fmt.Fprintf(stdout, "  Suites: %d/%d passed\n", campaign.PassedSuites, campaign.MandatorySuites)
		_, _ = fmt.Fprintf(stdout, "  Report: %s\n", reportPath)
	}
	if !campaign.Pass {
		return 1
	}
	return 0
}

func runAdversarialDetectorDefinition(args []string, stdout, stderr io.Writer) int {
	if len(args) != 0 {
		_, _ = fmt.Fprintf(stderr, "Error: unexpected argument: %s\n", args[0])
		return 2
	}
	digest, err := adversarial.DefinitionDigest()
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: cannot hash detector definition: %v\n", err)
		return 2
	}
	detectors, err := adversarial.Definition()
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: cannot load detector definition: %v\n", err)
		return 2
	}
	definition := struct {
		Revision         string                                `json:"revision"`
		DefinitionSHA256 string                                `json:"definition_sha256"`
		MandatorySuites  int                                   `json:"mandatory_suites"`
		Suites           []adversarial.DetectorSuiteDefinition `json:"suites"`
	}{
		Revision:         detectors.Revision,
		DefinitionSHA256: digest,
		MandatorySuites:  len(detectors.Suites),
		Suites:           detectors.Suites,
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(definition); err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: encode detector definition: %v\n", err)
		return 2
	}
	return 0
}

func runVerifyAdversarialCampaignReport(args []string, stdout, stderr io.Writer) int {
	cmd := flag.NewFlagSet("conform adversarial verify-report", flag.ContinueOnError)
	cmd.SetOutput(stderr)
	var (
		reportPath                       string
		trustedPublicKey                 string
		expectedKernelCommit             string
		expectedExecutableSHA            string
		expectedTrustProfile             string
		expectedCampaignPublicKey        string
		expectedCampaignID               string
		expectedRunID                    string
		expectedEvidenceRoot             string
		expectedMerkleRoot               string
		expectedEvaluationTime           string
		expectedDetectorRevision         string
		expectedDetectorDefinitionSHA256 string
		jsonOutput                       bool
	)
	cmd.StringVar(&reportPath, "report", "", "Path to an attested adversarial campaign report")
	cmd.StringVar(&trustedPublicKey, "trusted-public-key", strings.TrimSpace(os.Getenv(adversarialReportPublicKeyEnv)), "Externally trusted Ed25519 report-attestation public key")
	cmd.StringVar(&expectedKernelCommit, "expected-kernel-commit", "", "Optional exact Kernel commit required by downstream policy")
	cmd.StringVar(&expectedExecutableSHA, "expected-executable-sha256", "", "Optional exact runner executable digest required by downstream policy")
	cmd.StringVar(&expectedTrustProfile, "expected-trust-profile", "", "Optional exact EvidencePack trust profile required by downstream policy")
	cmd.StringVar(&expectedCampaignPublicKey, "expected-campaign-public-key", strings.TrimSpace(os.Getenv(adversarial.CampaignPublicKeyEnv)), "Required external Ed25519 campaign trust root")
	cmd.StringVar(&expectedCampaignID, "expected-campaign-id", "", "Required exact campaign identifier for replay-safe verification")
	cmd.StringVar(&expectedRunID, "expected-run-id", "", "Required exact campaign-run identifier for replay-safe verification")
	cmd.StringVar(&expectedEvidenceRoot, "expected-evidence-root", "", "Optional exact EvidencePack manifest root required by downstream policy")
	cmd.StringVar(&expectedMerkleRoot, "expected-merkle-root", "", "Optional exact EvidencePack Merkle root required by downstream policy")
	cmd.StringVar(&expectedEvaluationTime, "expected-evaluation-time", "", "Optional exact RFC3339 trust-evaluation time required by downstream policy")
	cmd.StringVar(&expectedDetectorRevision, "expected-detector-revision", "", "Optional exact adversarial detector revision required by downstream policy")
	cmd.StringVar(&expectedDetectorDefinitionSHA256, "expected-detector-definition-sha256", "", "Optional exact adversarial detector-definition digest required by downstream policy")
	cmd.BoolVar(&jsonOutput, "json", false, "Emit the authenticated campaign report as JSON")
	if err := cmd.Parse(args); err != nil {
		return 2
	}
	if cmd.NArg() != 0 || strings.TrimSpace(reportPath) == "" || strings.TrimSpace(trustedPublicKey) == "" || strings.TrimSpace(expectedCampaignPublicKey) == "" || strings.TrimSpace(expectedCampaignID) == "" || strings.TrimSpace(expectedRunID) == "" {
		_, _ = fmt.Fprintln(stderr, "Error: --report, --trusted-public-key, --expected-campaign-public-key, --expected-campaign-id, and --expected-run-id are required")
		return 2
	}
	var err error
	expectedCampaignID, err = validateAdversarialIdentifier("expected campaign id", expectedCampaignID)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: %v\n", err)
		return 2
	}
	expectedRunID, err = validateAdversarialIdentifier("expected run id", expectedRunID)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: %v\n", err)
		return 2
	}
	expectedCampaignKeyID, err := adversarial.CampaignKeyID(expectedCampaignPublicKey)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: --expected-campaign-public-key is invalid: %v\n", err)
		return 2
	}
	data, err := readBoundedAdversarialReport(reportPath)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: cannot read campaign report: %v\n", err)
		return 2
	}
	report, err := decodeAdversarialCampaignReport(data)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: cannot decode campaign report: %v\n", err)
		return 2
	}
	if report.SchemaVersion != adversarialCampaignSchemaVersion || report.CampaignID == "" || report.RunID == "" || report.RunnerProvenance.KernelCommit == "" || report.RunnerProvenance.ExecutableSHA256 == "" || report.RunnerProvenance.DetectorRevision == "" || report.RunnerProvenance.DetectorDefinitionSHA256 == "" {
		_, _ = fmt.Fprintln(stderr, "Error: campaign report provenance is incomplete or unsupported")
		return 1
	}
	if err := verifyAdversarialCampaignReportAttestation(report, trustedPublicKey); err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: %v\n", err)
		return 1
	}
	contextChecks := []struct {
		name     string
		got      string
		expected string
	}{
		{name: "kernel commit", got: report.RunnerProvenance.KernelCommit, expected: expectedKernelCommit},
		{name: "executable digest", got: report.RunnerProvenance.ExecutableSHA256, expected: expectedExecutableSHA},
		{name: "trust profile", got: report.TrustProfile, expected: expectedTrustProfile},
		{name: "campaign key id", got: report.CampaignTrustKeyID, expected: expectedCampaignKeyID},
		{name: "campaign id", got: report.CampaignID, expected: expectedCampaignID},
		{name: "run id", got: report.RunID, expected: expectedRunID},
		{name: "evidence root", got: report.EvidenceRoot, expected: expectedEvidenceRoot},
		{name: "merkle root", got: report.MerkleRoot, expected: expectedMerkleRoot},
		{name: "evaluation time", got: report.EvaluationTime, expected: expectedEvaluationTime},
		{name: "detector revision", got: report.RunnerProvenance.DetectorRevision, expected: expectedDetectorRevision},
		{name: "detector definition digest", got: report.RunnerProvenance.DetectorDefinitionSHA256, expected: expectedDetectorDefinitionSHA256},
	}
	for _, check := range contextChecks {
		if expected := strings.TrimSpace(check.expected); expected != "" && check.got != expected {
			_, _ = fmt.Fprintf(stderr, "Error: %s mismatch: got %s want %s\n", check.name, check.got, expected)
			return 1
		}
	}
	if err := validateAdversarialCampaignReportSemantics(report); err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: campaign report semantics are invalid: %v\n", err)
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

func readBoundedAdversarialReport(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	data, err := io.ReadAll(io.LimitReader(file, maxAdversarialReportBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxAdversarialReportBytes {
		return nil, fmt.Errorf("report exceeds %d-byte limit", maxAdversarialReportBytes)
	}
	return data, nil
}

func decodeAdversarialCampaignReport(data []byte) (adversarialCampaignReport, error) {
	if err := rejectDuplicateJSONKeys(data); err != nil {
		return adversarialCampaignReport{}, err
	}

	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var report adversarialCampaignReport
	if err := decoder.Decode(&report); err != nil {
		return adversarialCampaignReport{}, err
	}
	if err := requireJSONEOF(decoder); err != nil {
		return adversarialCampaignReport{}, err
	}
	return report, nil
}

func rejectDuplicateJSONKeys(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := consumeUniqueJSONValue(decoder, 0); err != nil {
		return err
	}
	return requireJSONEOF(decoder)
}

func consumeUniqueJSONValue(decoder *json.Decoder, depth int) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	if depth >= maxAdversarialJSONDepth {
		return fmt.Errorf("JSON nesting exceeds %d-container limit", maxAdversarialJSONDepth)
	}

	switch delim {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return fmt.Errorf("object key is not a string")
			}
			if _, exists := seen[key]; exists {
				return fmt.Errorf("duplicate JSON object key %q", key)
			}
			seen[key] = struct{}{}
			if err := consumeUniqueJSONValue(decoder, depth+1); err != nil {
				return err
			}
		}
		return consumeJSONClosingDelimiter(decoder, '}')
	case '[':
		for decoder.More() {
			if err := consumeUniqueJSONValue(decoder, depth+1); err != nil {
				return err
			}
		}
		return consumeJSONClosingDelimiter(decoder, ']')
	default:
		return fmt.Errorf("unexpected JSON delimiter %q", delim)
	}
}

func validateAdversarialCampaignReportSemantics(report adversarialCampaignReport) error {
	if _, err := validateAdversarialIdentifier("campaign id", report.CampaignID); err != nil {
		return err
	}
	if _, err := validateAdversarialIdentifier("run id", report.RunID); err != nil {
		return err
	}
	if _, err := parseAdversarialTrustProfile(report.TrustProfile); err != nil {
		return err
	}
	evaluationTime, err := time.Parse(time.RFC3339Nano, report.EvaluationTime)
	if err != nil || evaluationTime.UTC().Format(time.RFC3339Nano) != report.EvaluationTime {
		return fmt.Errorf("evaluation_time must be canonical UTC RFC3339")
	}
	if err := validatePrefixedSHA256("campaign_trust_key_id", report.CampaignTrustKeyID); err != nil {
		return err
	}
	if err := validateKernelCommit(report.RunnerProvenance.KernelCommit); err != nil {
		return err
	}
	if err := validatePrefixedSHA256("runner executable digest", report.RunnerProvenance.ExecutableSHA256); err != nil {
		return err
	}
	if report.VerifierVersion != verifier.VerifierVersion {
		return fmt.Errorf("verifier_version=%q; want source-owned %q", report.VerifierVersion, verifier.VerifierVersion)
	}
	if strings.TrimSpace(report.VerificationSummary) == "" || len(report.VerificationChecks) == 0 {
		return fmt.Errorf("verification evidence is incomplete")
	}
	if !equalAdversarialStrings(report.UntestedRegions, adversarialUntestedRegions()) {
		return fmt.Errorf("untested_regions does not match the source-owned limitation contract")
	}
	if !equalAdversarialStrings(report.KnownLimitations, adversarialKnownLimitations()) {
		return fmt.Errorf("known_limitations does not match the source-owned limitation contract")
	}
	definition, err := adversarial.Definition()
	if err != nil {
		return fmt.Errorf("load source-owned detector definition: %w", err)
	}
	detectorDigest, err := adversarial.DefinitionDigest()
	if err != nil {
		return fmt.Errorf("hash source-owned detector definition: %w", err)
	}
	if report.RunnerProvenance.DetectorRevision != definition.Revision {
		return fmt.Errorf("detector_revision=%q; want source-owned %q", report.RunnerProvenance.DetectorRevision, definition.Revision)
	}
	if report.RunnerProvenance.DetectorDefinitionSHA256 != detectorDigest {
		return fmt.Errorf("detector_definition_sha256=%q; want source-owned %q", report.RunnerProvenance.DetectorDefinitionSHA256, detectorDigest)
	}
	mandatoryByID := make(map[string]adversarial.DetectorSuiteDefinition, len(definition.Suites))
	for _, suite := range definition.Suites {
		mandatoryByID[suite.SuiteID] = suite
	}
	if report.MandatorySuites != len(definition.Suites) {
		return fmt.Errorf("mandatory_suites=%d; want %d", report.MandatorySuites, len(definition.Suites))
	}
	if report.IndexEntryCount < 0 {
		return fmt.Errorf("index_entry_count must not be negative")
	}
	if report.BundleVerified {
		if report.IndexEntryCount == 0 {
			return fmt.Errorf("verified bundle has no indexed entries")
		}
		if err := validateRawSHA256("evidence_root", report.EvidenceRoot); err != nil {
			return err
		}
		if err := validateRawSHA256("merkle_root", report.MerkleRoot); err != nil {
			return err
		}
	}

	failedVerificationChecks := 0
	for _, check := range report.VerificationChecks {
		if !check.Pass {
			failedVerificationChecks++
		}
	}
	if report.VerificationIssueCount != failedVerificationChecks {
		return fmt.Errorf("verification_issue_count=%d; derived %d", report.VerificationIssueCount, failedVerificationChecks)
	}
	if report.BundleVerified != (failedVerificationChecks == 0) {
		return fmt.Errorf("bundle_verified is inconsistent with verification checks")
	}

	coveredSuites := 0
	seenCoverage := make(map[string]struct{}, len(report.CoverageChecks))
	for index, check := range report.CoverageChecks {
		suiteDefinition, ok := mandatoryByID[check.SuiteID]
		if !ok {
			return fmt.Errorf("coverage check names unknown suite %q", check.SuiteID)
		}
		if _, duplicate := seenCoverage[check.SuiteID]; duplicate {
			return fmt.Errorf("coverage check duplicates suite %q", check.SuiteID)
		}
		if index >= len(definition.Suites) || check.SuiteID != definition.Suites[index].SuiteID {
			return fmt.Errorf("coverage checks are not in source-owned detector order")
		}
		seenCoverage[check.SuiteID] = struct{}{}
		if check.EvidenceCount < 0 {
			return fmt.Errorf("coverage check %q has negative evidence_count", check.SuiteID)
		}
		if check.MutationID != suiteDefinition.MutationID {
			return fmt.Errorf("coverage check %q mutation_id=%q; want %q", check.SuiteID, check.MutationID, suiteDefinition.MutationID)
		}
		if strings.TrimSpace(check.Reason) == "" {
			return fmt.Errorf("coverage check %q has no reason", check.SuiteID)
		}
		mutationProofComplete := check.PositiveControlPassed && check.MutationApplied && check.MutationRejected && check.MutationRestored
		if check.Covered && (!mutationProofComplete || check.EvidenceCount == 0) {
			return fmt.Errorf("covered suite %q lacks complete positive-control and mutation evidence", check.SuiteID)
		}
		if !check.Covered && mutationProofComplete {
			return fmt.Errorf("uncovered suite %q contradicts complete mutation evidence", check.SuiteID)
		}
		if check.Covered {
			coveredSuites++
		}
	}
	if report.CoveredSuites != coveredSuites || report.MissingSuites != len(report.CoverageChecks)-coveredSuites {
		return fmt.Errorf("coverage counters do not match coverage_checks")
	}
	coverageComplete := len(report.CoverageChecks) == len(definition.Suites) && coveredSuites == len(definition.Suites)
	if report.CoverageVerified != coverageComplete {
		return fmt.Errorf("coverage_verified is inconsistent with mandatory coverage checks")
	}

	passedSuites := 0
	seenSuites := make(map[string]struct{}, len(report.Suites))
	for index, suite := range report.Suites {
		if suite == nil {
			return fmt.Errorf("suites contains a null result")
		}
		suiteDefinition, ok := mandatoryByID[suite.SuiteID]
		if !ok {
			return fmt.Errorf("suite result names unknown suite %q", suite.SuiteID)
		}
		if _, duplicate := seenSuites[suite.SuiteID]; duplicate {
			return fmt.Errorf("suite result duplicates suite %q", suite.SuiteID)
		}
		if index >= len(definition.Suites) || suite.SuiteID != definition.Suites[index].SuiteID {
			return fmt.Errorf("suite results are not in source-owned detector order")
		}
		seenSuites[suite.SuiteID] = struct{}{}
		if suite.Name != suiteDefinition.Name {
			return fmt.Errorf("suite %q name mismatch", suite.SuiteID)
		}
		if len(suite.TestResults) == 0 {
			return fmt.Errorf("suite %q has no test results", suite.SuiteID)
		}
		testsPass := true
		expectedTestSeen := false
		seenTests := make(map[string]struct{}, len(suite.TestResults))
		for _, test := range suite.TestResults {
			if strings.TrimSpace(test.TestID) == "" {
				return fmt.Errorf("suite %q has an empty test id", suite.SuiteID)
			}
			if strings.TrimSpace(test.Name) == "" {
				return fmt.Errorf("suite %q test %q has no name", suite.SuiteID, test.TestID)
			}
			if _, duplicate := seenTests[test.TestID]; duplicate {
				return fmt.Errorf("suite %q duplicates test %q", suite.SuiteID, test.TestID)
			}
			seenTests[test.TestID] = struct{}{}
			if test.TestID == suiteDefinition.ExpectedTestID {
				expectedTestSeen = true
			}
			testsPass = testsPass && test.Pass
		}
		if !expectedTestSeen {
			return fmt.Errorf("suite %q lacks expected detector test %q", suite.SuiteID, suiteDefinition.ExpectedTestID)
		}
		if suite.Pass != testsPass {
			return fmt.Errorf("suite %q pass does not match its test results", suite.SuiteID)
		}
		if suite.Pass {
			passedSuites++
		}
	}
	if report.ExecutedSuites != len(report.Suites) || report.PassedSuites != passedSuites || report.FailedSuites != len(report.Suites)-passedSuites {
		return fmt.Errorf("suite counters do not match suite results")
	}

	if report.Pass != (report.Status == adversarialCampaignStatusPassed) {
		return fmt.Errorf("pass/status fields are inconsistent")
	}
	switch report.Status {
	case adversarialCampaignStatusBundleVerificationFailed:
		if report.BundleVerified || report.CoverageVerified || len(report.CoverageChecks) != 0 || len(report.Suites) != 0 {
			return fmt.Errorf("bundle_verification_failed contains downstream coverage or suite success")
		}
	case adversarialCampaignStatusCoverageIncomplete:
		if !report.BundleVerified || report.CoverageVerified || len(report.CoverageChecks) != len(definition.Suites) || report.MissingSuites == 0 || len(report.Suites) != 0 {
			return fmt.Errorf("coverage_incomplete fields are inconsistent")
		}
	case adversarialCampaignStatusAdversarialFailed:
		if !report.BundleVerified || !report.CoverageVerified || len(report.Suites) != len(definition.Suites) || report.FailedSuites == 0 {
			return fmt.Errorf("adversarial_failed fields are inconsistent")
		}
	case adversarialCampaignStatusPassed:
		if !report.BundleVerified || !report.CoverageVerified || len(report.Suites) != len(definition.Suites) || report.PassedSuites != len(definition.Suites) || report.FailedSuites != 0 {
			return fmt.Errorf("passed fields are inconsistent")
		}
	default:
		return fmt.Errorf("unsupported status %q", report.Status)
	}
	return nil
}

func consumeJSONClosingDelimiter(decoder *json.Decoder, want json.Delim) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	if token != want {
		return fmt.Errorf("unexpected JSON delimiter %q; want %q", token, want)
	}
	return nil
}

func requireJSONEOF(decoder *json.Decoder) error {
	if _, err := decoder.Token(); err != io.EOF {
		if err == nil {
			return fmt.Errorf("multiple JSON values are not allowed")
		}
		return err
	}
	return nil
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

type adversarialBundleVerification struct {
	Report                            *verifier.VerifyReport
	AllowVerifiedConformanceSignature bool
}

func verifyAdversarialCampaignBundle(packDir string, opts adversarialBundleVerifyOptions) (adversarialBundleVerification, error) {
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
		return adversarialBundleVerification{}, err
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
	return adversarialBundleVerification{
		Report:                            report,
		AllowVerifiedConformanceSignature: allowVerifiedConformanceSignature,
	}, nil
}

func newAdversarialCampaignReport(campaignID, runID string, profile evidencepkg.EvidenceTrustProfile, evaluationTime time.Time, campaignTrustKeyID string, runner adversarialRunnerProvenance, verification *verifier.VerifyReport) adversarialCampaignReport {
	return adversarialCampaignReport{
		SchemaVersion:          adversarialCampaignSchemaVersion,
		CampaignID:             campaignID,
		RunID:                  runID,
		Pass:                   false,
		Status:                 adversarialCampaignStatusBundleVerificationFailed,
		TrustProfile:           string(profile),
		EvaluationTime:         evaluationTime.UTC().Format(time.RFC3339Nano),
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
		CoverageChecks:         []adversarial.CoverageCheck{},
		UntestedRegions:        adversarialUntestedRegions(),
		KnownLimitations:       adversarialKnownLimitations(),
		RunnerProvenance:       runner,
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

func validateAdversarialIdentifier(name, raw string) (string, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return "", fmt.Errorf("%s must not be empty", name)
	}
	if len(value) > maxAdversarialIdentifierBytes {
		return "", fmt.Errorf("%s exceeds %d bytes", name, maxAdversarialIdentifierBytes)
	}
	for _, character := range []byte(value) {
		allowed := character >= 'a' && character <= 'z' ||
			character >= 'A' && character <= 'Z' ||
			character >= '0' && character <= '9'
		switch character {
		case '-', '_', '.', ':', '/':
			allowed = true
		}
		if !allowed {
			return "", fmt.Errorf("%s contains unsupported byte %q", name, character)
		}
	}
	return value, nil
}

func validateKernelCommit(value string) error {
	value = strings.TrimSpace(value)
	if len(value) != 40 && len(value) != 64 {
		return fmt.Errorf("kernel_commit must be a 40- or 64-character lowercase hex commit")
	}
	decoded, err := hex.DecodeString(value)
	if err != nil || hex.EncodeToString(decoded) != value {
		return fmt.Errorf("kernel_commit must be a 40- or 64-character lowercase hex commit")
	}
	return nil
}

func validatePrefixedSHA256(name, value string) error {
	const prefix = "sha256:"
	if !strings.HasPrefix(value, prefix) {
		return fmt.Errorf("%s must be a canonical sha256: digest", name)
	}
	return validateRawSHA256(name, strings.TrimPrefix(value, prefix))
}

func validateRawSHA256(name, value string) error {
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != sha256.Size || hex.EncodeToString(decoded) != value {
		return fmt.Errorf("%s must be a canonical lowercase SHA-256 digest", name)
	}
	return nil
}

func adversarialUntestedRegions() []string {
	return []string{
		"model/provider clean-room execution",
		"independent SecurityFinding verification lifecycle",
		"patch generation and regression validation",
		"staging, production smoke, and soak",
	}
}

func adversarialKnownLimitations() []string {
	return []string{
		"the campaign evaluates only artifacts present in the supplied sealed EvidencePack",
		"a passing report is conformance evidence, not a bug-free or production-ready claim",
		"producer, verifier, and patcher identity separation is enforced by the HELM control plane, not this offline command",
	}
}

func equalAdversarialStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
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
		copiedHasher := sha256.New()
		copied, copyErr := io.Copy(io.MultiWriter(output, copiedHasher), io.LimitReader(input, info.Size()+1))
		closeOutputErr := output.Close()
		closeInputErr := input.Close()
		switch {
		case copyErr != nil:
			return copyErr
		case closeOutputErr != nil:
			return closeOutputErr
		case closeInputErr != nil:
			return closeInputErr
		case copied != info.Size():
			return fmt.Errorf("EvidencePack changed while snapshotting: %s", entry.Name())
		}

		verificationInput, err := os.Open(path)
		if err != nil {
			return err
		}
		verificationInfo, statErr := verificationInput.Stat()
		if statErr != nil || !os.SameFile(info, verificationInfo) || !verificationInfo.Mode().IsRegular() || verificationInfo.Size() != info.Size() || !verificationInfo.ModTime().Equal(info.ModTime()) {
			_ = verificationInput.Close()
			return fmt.Errorf("EvidencePack changed while snapshotting: %s", entry.Name())
		}
		verificationHasher := sha256.New()
		verified, verificationErr := io.Copy(verificationHasher, io.LimitReader(verificationInput, info.Size()+1))
		closeVerificationErr := verificationInput.Close()
		switch {
		case verificationErr != nil:
			return verificationErr
		case closeVerificationErr != nil:
			return closeVerificationErr
		case verified != info.Size():
			return fmt.Errorf("EvidencePack changed while snapshotting: %s", entry.Name())
		case !bytes.Equal(copiedHasher.Sum(nil), verificationHasher.Sum(nil)):
			return fmt.Errorf("EvidencePack changed while snapshotting: %s", entry.Name())
		}
		return nil
	})
}

func currentExecutableSHA256() (string, error) {
	if runningExecutableImageErr != nil {
		return "", runningExecutableImageErr
	}
	return hashOpenExecutableImage(runningExecutableImage)
}

func openRunningExecutableImage() (*os.File, error) {
	path := "/proc/self/exe"
	if runtime.GOOS != "linux" {
		var err error
		path, err = os.Executable()
		if err != nil {
			return nil, fmt.Errorf("resolve running executable: %w", err)
		}
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("pin running executable image: %w", err)
	}
	return file, nil
}

func hashOpenExecutableImage(file *os.File) (string, error) {
	if file == nil {
		return "", fmt.Errorf("running executable image is not pinned")
	}
	info, err := file.Stat()
	if err != nil {
		return "", fmt.Errorf("stat pinned executable image: %w", err)
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 {
		return "", fmt.Errorf("pinned executable image is not a non-empty regular file")
	}
	hash := sha256.New()
	written, err := io.Copy(hash, io.NewSectionReader(file, 0, info.Size()))
	if err != nil {
		return "", fmt.Errorf("hash pinned executable image: %w", err)
	}
	if written != info.Size() {
		return "", fmt.Errorf("pinned executable image changed while hashing")
	}
	return "sha256:" + hex.EncodeToString(hash.Sum(nil)), nil
}

func signAdversarialCampaignReport(report *adversarialCampaignReport) error {
	privateKey, publicKeyHex, err := adversarialReportSigningKey()
	if err != nil {
		return err
	}
	return signAdversarialCampaignReportWithKey(report, privateKey, publicKeyHex)
}

func adversarialReportSigningKey() (ed25519.PrivateKey, string, error) {
	keyHex := strings.TrimSpace(os.Getenv(adversarialReportSigningKeyEnv))
	if keyHex == "" {
		return nil, "", fmt.Errorf("%s is required", adversarialReportSigningKeyEnv)
	}
	keyBytes, err := hex.DecodeString(keyHex)
	if err != nil {
		return nil, "", fmt.Errorf("invalid %s: %w", adversarialReportSigningKeyEnv, err)
	}
	var privateKey ed25519.PrivateKey
	switch len(keyBytes) {
	case ed25519.SeedSize:
		privateKey = ed25519.NewKeyFromSeed(keyBytes)
	case ed25519.PrivateKeySize:
		derivedKey := ed25519.NewKeyFromSeed(keyBytes[:ed25519.SeedSize])
		if subtle.ConstantTimeCompare(derivedKey, keyBytes) != 1 {
			return nil, "", fmt.Errorf("%s public key does not match its seed", adversarialReportSigningKeyEnv)
		}
		privateKey = derivedKey
	default:
		return nil, "", fmt.Errorf("%s must be a 32-byte seed or 64-byte private key", adversarialReportSigningKeyEnv)
	}
	publicKey := privateKey.Public().(ed25519.PublicKey)
	return privateKey, hex.EncodeToString(publicKey), nil
}

func signAdversarialCampaignReportWithKey(report *adversarialCampaignReport, privateKey ed25519.PrivateKey, publicKeyHex string) error {
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
	payload, err := canonicalJSON(report)
	if err != nil {
		return nil, err
	}
	domain := append([]byte(adversarialReportSignatureDomain), 0)
	return append(domain, payload...), nil
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
	signatureHex := report.Attestation.Signature
	signature, err := hex.DecodeString(signatureHex)
	if err != nil || len(signature) != ed25519.SignatureSize || hex.EncodeToString(signature) != signatureHex {
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
