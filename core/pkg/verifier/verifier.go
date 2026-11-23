// Package verifier provides offline EvidencePack verification.
//
// This package is intentionally minimal with ZERO server, proxy, or network
// dependencies. It is designed to be buildable and auditable as a standalone
// verification tool that an adversarial third party can trust.
//
// Trust model: the verifier trusts only the cryptographic primitives
// (Ed25519, SHA-256, JCS) and the EvidencePack format specification.
// It does NOT trust the HELM server, proxy, or any network service.
package verifier

// quantum_posture: standalone verifier trust roots use classical Ed25519
// signatures for EvidencePack and embedded receipt checks in this release; no
// post-quantum assurance is claimed by this verifier path.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"time"

	evidencepkg "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/evidence"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/receiptverify"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/verifier/externalreceipt"
)

// VerifyReport is the structured output of offline verification.
// Designed for auditor consumption — every field is evidence-grade.
type VerifyReport struct {
	Bundle string `json:"bundle"`
	// Verified is true exactly when Outcome is VERIFIED: no check failed and
	// every check the pack is required to give input to ran and held. Checks
	// that did not run are counted in CheckCounts.NotRun, never as passed.
	Verified bool `json:"verified"`
	// Outcome is VERIFIED, FAILED or UNVERIFIABLE (AGENTS.md R2).
	Outcome   receiptverify.Verdict `json:"outcome"`
	Timestamp time.Time             `json:"timestamp"`
	Roots     VerifyRoots           `json:"roots,omitempty"`
	Checks    []CheckResult         `json:"checks"`
	// CheckCounts counts Checks by the state each ended in.
	CheckCounts CheckCounts `json:"check_counts"`
	Summary     string      `json:"summary"`
	// IssueCount counts the checks that ran and did not pass (FAILED or
	// UNVERIFIABLE). A check that did not run is not an issue.
	IssueCount          int                                       `json:"issue_count"`
	VerifierVer         string                                    `json:"verifier_version"`
	EnvelopeID          string                                    `json:"envelope_id,omitempty"`
	SealedAt            string                                    `json:"sealed_at,omitempty"`
	SignatureValidCount int                                       `json:"signature_valid_count,omitempty"`
	SignatureTotalCount int                                       `json:"signature_total_count,omitempty"`
	AnchorIndex         *uint64                                   `json:"anchor_index,omitempty"`
	MerkleRoot          string                                    `json:"merkle_root,omitempty"`
	Seal                *evidencepkg.EvidencePackSealVerification `json:"seal,omitempty"`
	TrustLevel          string                                    `json:"trust_level,omitempty"`
	SealState           string                                    `json:"seal_state,omitempty"`
	SealSignatureValid  bool                                      `json:"seal_signature_valid,omitempty"`
	AnchorStatus        string                                    `json:"anchor_status,omitempty"`
	StorageStatus       string                                    `json:"storage_status,omitempty"`
	SealSubjectRoot     string                                    `json:"seal_subject_root,omitempty"`
	SealID              string                                    `json:"seal_id,omitempty"`
}

// VerifyRoots contains deterministic roots derived from 00_INDEX.json.
type VerifyRoots struct {
	ManifestRootHash string `json:"manifest_root_hash,omitempty"`
	MerkleRoot       string `json:"merkle_root,omitempty"`
	EntryCount       int    `json:"entry_count,omitempty"`
}

// CheckResult represents a single verification check.
type CheckResult struct {
	Name string `json:"name"`
	// Pass is true only for a check that ran and held (Status VERIFIED).
	Pass   bool        `json:"pass"`
	Status CheckStatus `json:"status"`
	// Detail says what a passed check established.
	Detail string `json:"detail,omitempty"`
	// Reason says why a check failed, was unverifiable or did not run.
	Reason string `json:"reason,omitempty"`
}

// VerifierVersion identifies the report format. 0.3.0 added the per-check
// status, outcome and check_counts, and stopped counting checks without input
// as passed.
const VerifierVersion = "0.3.0"

type VerifyOptions struct {
	Profile            evidencepkg.EvidenceTrustProfile
	TrustConfig        *evidencepkg.EvidencePackTrustConfig
	DataDir            string
	ConfigPath         string
	StorageReceiptPath string
	StorageObjectPath  string
	ExternalHostKeyHex string
	// ManagedAgentReceiptPublicKeyHex is the trusted Ed25519 public key used
	// to verify embedded managed-agent execution receipts. The verifier never
	// trusts public keys declared inside the bundle unless they match this root.
	ManagedAgentReceiptPublicKeyHex string
	// WitnessPublicKeysHex maps witness IDs to trusted Ed25519 public keys
	// for verifying receipt witness_signatures (the k-of-n witness overlay).
	// Witness signatures whose witness_id has no configured key are skipped —
	// they anchor to the witness registry, not to embedded presence, so an
	// unconfigured verifier neither trusts nor fails them. A configured key
	// demands a valid signature over the receipt hash (fail-closed).
	WitnessPublicKeysHex map[string]string
	Now                  time.Time
	// AllowVerifiedConformanceSignature permits 07_ATTESTATIONS/conformance_report.sig
	// to remain outside 00_INDEX.json only for callers that have already
	// verified it against an external trusted key. Standalone library callers
	// should leave this false so the seal verifier remains fail-closed.
	AllowVerifiedConformanceSignature bool
	// RequireChecks names registered checks (see CheckNames) the caller needs
	// to have run. A named check that would report NOT_RUN is FAILED instead,
	// so a pack that omits the evidence cannot verify.
	RequireChecks []string
	// AllowSelfAttested accepts a dev-local seal whose verification key comes
	// from inside the pack. Only set this when verifying a pack this process
	// just produced; never when verifying one that arrived from elsewhere.
	AllowSelfAttested bool
	// AllowLegacyV4Receipts checks a dev-local MCP proof receipt that has no
	// signature_version against the legacy V4 preimage instead of leaving it
	// unverified. The preimage is eight colon-joined fields with no escaping,
	// so the signature of a receipt.v5 receipt can be read back as one
	// (helm-tracker#305); set this only for a pack known to predate
	// receipt.v5. See legacyV4ReceiptRefused.
	AllowLegacyV4Receipts bool
}

// VerifyBundle performs offline verification of an EvidencePack directory.
// No network access. No server dependency. Pure filesystem + crypto.
//
// Provenance is NOT assumed: a dev-local seal that carries its own verification
// key is rejected. Use VerifyLocallyProducedBundle when the caller created the
// pack itself and only wants the structural and chain checks.
func VerifyBundle(bundlePath string) (*VerifyReport, error) {
	return VerifyBundleWithOptions(bundlePath, VerifyOptions{Profile: evidencepkg.EvidenceTrustProfileDevLocal})
}

// VerifyLocallyProducedBundle verifies a pack that this process just created.
//
// It accepts the self-attested dev-local seal, because the caller already knows
// which key signed it — there is no provenance question to answer. Never use it
// on a pack received from elsewhere: that is exactly the case where the seal's
// embedded key proves nothing (F-02).
func VerifyLocallyProducedBundle(bundlePath string) (*VerifyReport, error) {
	return VerifyBundleWithOptions(bundlePath, VerifyOptions{
		Profile:           evidencepkg.EvidenceTrustProfileDevLocal,
		AllowSelfAttested: true,
	})
}

// checkRun is what a registered check reads: the pack, the caller's options
// and the report so far. The seal check resolves the trust profile the later
// checks are judged under, so opts changes as the registry runs.
type checkRun struct {
	bundlePath string
	opts       VerifyOptions
	report     *VerifyReport
}

type registeredCheck struct {
	name string
	run  func(*checkRun) []CheckResult
}

// checkRegistry is every check VerifyBundleWithOptions runs, in report order.
//
// Each entry reports at least one result on every pack. A check with nothing
// to read reports NOT_RUN with the reason; it neither stays silent nor passes.
// A check whose input the pack is required to carry (by the pack format, by
// the gates 00_INDEX.json declares, or by VerifyOptions.RequireChecks) reports
// FAILED when that input is missing.
// TestCheckRegistry_NoCheckPassesWithoutInput holds every entry to this.
var checkRegistry = []registeredCheck{
	{"structure", func(run *checkRun) []CheckResult { return []CheckResult{checkStructure(run.bundlePath)} }},
	{"index_integrity", func(run *checkRun) []CheckResult { return []CheckResult{checkIndex(run.bundlePath)} }},
	{"roots", func(run *checkRun) []CheckResult { return []CheckResult{checkRoots(run.bundlePath, run.report)} }},
	{"evidence_pack_seal", func(run *checkRun) []CheckResult {
		result := checkEvidencePackSeal(run.bundlePath, run.report, run.opts)
		// Embedded receipts are judged under the profile the seal resolved (the
		// flag, else the trust config's active_profile, else dev-local). Using
		// the raw flag here let an empty --profile trust pack-carried receipt
		// keys inside a team or customer pack.
		if run.report.Seal != nil && run.report.Seal.TrustLevel != "" {
			run.opts.Profile = run.report.Seal.TrustLevel
		}
		return []CheckResult{result}
	}},
	{"file_hashes", func(run *checkRun) []CheckResult { return checkFileHashes(run.bundlePath) }},
	{"eu_ai_act_profile", func(run *checkRun) []CheckResult {
		return []CheckResult{checkEUAIActEvidenceProfile(run.bundlePath)}
	}},
	{"connector_evidence", func(run *checkRun) []CheckResult { return []CheckResult{checkConnectorEvidence(run.bundlePath)} }},
	{"chain_integrity", func(run *checkRun) []CheckResult { return []CheckResult{checkChainIntegrity(run.bundlePath)} }},
	{"lamport_monotonicity", func(run *checkRun) []CheckResult {
		return []CheckResult{checkLamportMonotonicity(run.bundlePath)}
	}},
	{"policy_decision_hashes", func(run *checkRun) []CheckResult {
		return []CheckResult{checkPolicyDecisionHashes(run.bundlePath)}
	}},
	{"replay_determinism", func(run *checkRun) []CheckResult { return []CheckResult{checkReplayDeterminism(run.bundlePath)} }},
	{"host_evidence", func(run *checkRun) []CheckResult { return checkHostEvidence(run.bundlePath, run.opts) }},
	{"embedded_signature_trust", func(run *checkRun) []CheckResult {
		result := checkEmbeddedSignatureTrust(run.bundlePath, run.opts).normalized()
		// With no trust root for the seal, nothing vouches for the keys these
		// signatures would be checked against either. That is unproven, not
		// tampered, so it must not turn an UNVERIFIABLE pack into a FAILED one.
		if result.Status == CheckFailed && run.report.SealState == evidencepkg.EvidencePackSealStateUnverifiable {
			result.Status = CheckUnverifiable
		}
		return []CheckResult{result}
	}},
}

// results runs the check and normalizes what it returns, so every result
// carries a status that agrees with Pass.
func (check registeredCheck) results(run *checkRun) []CheckResult {
	results := check.run(run)
	for i := range results {
		results[i] = results[i].normalized()
	}
	return results
}

// CheckNames lists the registered checks in report order. These are the names
// VerifyOptions.RequireChecks accepts.
func CheckNames() []string {
	names := make([]string, len(checkRegistry))
	for i, check := range checkRegistry {
		names[i] = check.name
	}
	return names
}

// packChecksRequiredForVerified are the checks every EvidencePack must give
// input to. Each of them fails, rather than reports NOT_RUN, when its input is
// missing; Conclude withholds VERIFIED if one is ever absent from a report.
var packChecksRequiredForVerified = []string{"structure", "evidence_pack_seal", "policy_decision_hashes"}

// VerifyBundleWithOptions performs offline verification with an explicit trust profile.
func VerifyBundleWithOptions(bundlePath string, opts VerifyOptions) (*VerifyReport, error) {
	callerRequired := make(map[string]bool, len(opts.RequireChecks))
	for _, name := range opts.RequireChecks {
		if !slices.Contains(CheckNames(), name) {
			return nil, fmt.Errorf("unknown check %q in RequireChecks (known checks: %s)", name, strings.Join(CheckNames(), ", "))
		}
		callerRequired[name] = true
	}

	report := &VerifyReport{
		Bundle:      bundlePath,
		Outcome:     receiptverify.VerdictFailed,
		Timestamp:   time.Now().UTC(),
		Checks:      make([]CheckResult, 0),
		VerifierVer: VerifierVersion,
	}
	run := &checkRun{bundlePath: bundlePath, opts: opts, report: report}
	for _, check := range checkRegistry {
		results := check.results(run)
		if callerRequired[check.name] {
			results = failIfNothingRan(results)
		}
		report.addChecks(results)
	}

	enrichReportMetadata(bundlePath, report, run.opts)
	report.Finalize()
	return report, nil
}

// failIfNothingRan turns the results of a check the caller requires into
// failures when none of them ran. A check that did run keeps its results as
// they are: requiring host_evidence asks for a host receipt chain, not for
// every receipt in it to make a hardware root claim.
func failIfNothingRan(results []CheckResult) []CheckResult {
	for _, result := range results {
		if result.Status != CheckNotRun {
			return results
		}
	}
	for i, result := range results {
		results[i] = failed(result.Name, "required by the caller, but it did not run: "+result.Reason).normalized()
	}
	return results
}

// Finalize normalizes the checks and sets Outcome, Verified, CheckCounts,
// IssueCount and Summary from them. It is safe to call again after appending
// checks.
//
// A report whose only non-passing checks lack a trust root is UNVERIFIABLE:
// the content is intact but nothing configured vouches for the signer. It is
// never a pass.
func (report *VerifyReport) Finalize() {
	outcomes := make([]CheckOutcome, len(report.Checks))
	for i := range report.Checks {
		report.Checks[i] = report.Checks[i].normalized()
		outcomes[i] = CheckOutcome{Name: report.Checks[i].Name, Status: report.Checks[i].Status}
	}
	conclusion := Conclude(outcomes, packChecksRequiredForVerified)
	report.Outcome = conclusion.Outcome
	report.Verified = conclusion.Outcome == receiptverify.VerdictVerified
	report.CheckCounts = conclusion.Counts
	report.IssueCount = conclusion.Counts.Failed + conclusion.Counts.Unverifiable
	report.Summary = summarize(conclusion)
}

// summarize states the verdict with the passed, failed and not-run counts
// apart, and says when a VERIFIED result covers only part of the registry.
func summarize(conclusion Conclusion) string {
	counts := conclusion.Counts
	tally := fmt.Sprintf("%d passed, %d failed, ", counts.Passed, counts.Failed)
	if counts.Unverifiable > 0 {
		tally += fmt.Sprintf("%d unverifiable, ", counts.Unverifiable)
	}
	tally += fmt.Sprintf("%d not run", counts.NotRun)

	switch conclusion.Outcome {
	case receiptverify.VerdictVerified:
		if counts.NotRun > 0 {
			return fmt.Sprintf("VERIFIED: %s; this result covers only the %d checks that ran", tally, counts.Ran())
		}
		return "VERIFIED: " + tally
	case receiptverify.VerdictUnverifiable:
		if counts.Unverifiable == 0 {
			return fmt.Sprintf("UNVERIFIABLE: required checks did not run (%s); %s", strings.Join(conclusion.RequiredNotRun, ", "), tally)
		}
		return fmt.Sprintf("UNVERIFIABLE: no trust root for the seal signer; %s (pass --config, set HELM_EVIDENCE_TRUST_CONFIG or HELM_EVIDENCE_TRUSTED_PUBLIC_KEY_HEX)", tally)
	default:
		return "FAILED: " + tally
	}
}

func checkEvidencePackSeal(bundlePath string, report *VerifyReport, opts VerifyOptions) CheckResult {
	seal := evidencepkg.VerifyEvidencePackSeal(bundlePath, evidencepkg.VerifyEvidencePackSealOptions{
		Profile:                           opts.Profile,
		TrustConfig:                       opts.TrustConfig,
		DataDir:                           opts.DataDir,
		ConfigPath:                        opts.ConfigPath,
		StorageReceiptPath:                opts.StorageReceiptPath,
		StorageObjectPath:                 opts.StorageObjectPath,
		Now:                               opts.Now,
		AllowVerifiedConformanceSignature: opts.AllowVerifiedConformanceSignature,
		AllowSelfAttested:                 opts.AllowSelfAttested,
	})
	report.Seal = &seal
	report.SealState = seal.State
	report.SealSignatureValid = seal.SignatureValid
	report.AnchorStatus = seal.AnchorStatus
	report.StorageStatus = seal.StorageStatus
	report.TrustLevel = string(seal.TrustLevel)
	report.SealSubjectRoot = seal.MerkleRoot
	report.SealID = seal.PackID
	if seal.MerkleRoot != "" {
		report.MerkleRoot = seal.MerkleRoot
	}
	if !seal.SignedAt.IsZero() {
		report.SealedAt = seal.SignedAt.Format(time.RFC3339)
	}
	if seal.SignatureValid {
		report.SignatureValidCount++
		report.SignatureTotalCount++
	}
	if seal.State == "valid" {
		return verified("evidence_pack_seal", fmt.Sprintf("seal valid; trust=%s; anchor=%s; storage=%s", seal.TrustLevel, seal.AnchorStatus, seal.StorageStatus))
	}
	reason := strings.Join(seal.Errors, "; ")
	if reason == "" {
		reason = "native EvidencePack seal is invalid"
	}
	if seal.State == evidencepkg.EvidencePackSealStateUnverifiable {
		return CheckResult{Name: "evidence_pack_seal", Status: CheckUnverifiable, Reason: "UNVERIFIABLE (no trust root): " + reason}
	}
	return failed("evidence_pack_seal", reason)
}

func enrichReportMetadata(bundlePath string, report *VerifyReport, opts VerifyOptions) {
	pack := openPack(bundlePath)
	defer pack.close()
	for _, name := range []string{"00_INDEX.json", "manifest.json"} {
		data, err := pack.readFile(name)
		if err != nil {
			continue
		}
		var document map[string]any
		if err := json.Unmarshal(data, &document); err != nil {
			continue
		}
		if report.EnvelopeID == "" {
			report.EnvelopeID = firstString(document, "envelope_id", "pack_id", "run_id", "session_id", "id")
		}
		if report.SealedAt == "" {
			report.SealedAt = firstString(document, "sealed_at", "exported_at", "created_at", "timestamp")
		}
		if report.MerkleRoot == "" {
			report.MerkleRoot = firstString(document, "merkle_root", "root_hash")
		}
		if report.AnchorIndex == nil {
			report.AnchorIndex = firstUint(document, "anchor_index", "ledger_index")
		}
		if report.AnchorIndex == nil {
			if anchor, ok := document["anchor"].(map[string]any); ok {
				report.AnchorIndex = firstUint(anchor, "index", "anchor_index", "ledger_index")
			}
		}
	}

	valid, total := countEmbeddedSignatures(bundlePath, opts)
	if report.SealState != "" {
		total++
		if report.SealSignatureValid {
			valid++
		}
	}
	report.SignatureValidCount = valid
	report.SignatureTotalCount = total
	if report.EnvelopeID == "" {
		report.EnvelopeID = "ep_" + shortHash(report.MerkleRoot+report.Bundle)
	}
}

func firstString(document map[string]any, keys ...string) string {
	for _, key := range keys {
		if value, ok := document[key].(string); ok && value != "" {
			return value
		}
	}
	return ""
}

func firstUint(document map[string]any, keys ...string) *uint64 {
	for _, key := range keys {
		switch value := document[key].(type) {
		case float64:
			if value >= 0 {
				v := uint64(value)
				return &v
			}
		case json.Number:
			if parsed, err := value.Int64(); err == nil && parsed >= 0 {
				v := uint64(parsed)
				return &v
			}
		case string:
			var parsed uint64
			if _, err := fmt.Sscanf(value, "%d", &parsed); err == nil {
				return &parsed
			}
		}
	}
	return nil
}

func shortHash(value string) string {
	if value == "" {
		value = time.Now().UTC().Format(time.RFC3339Nano)
	}
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])[:12]
}

func (r *VerifyReport) addChecks(cs []CheckResult) {
	r.Checks = append(r.Checks, cs...)
}

// checkHostEvidence verifies external host receipt chains when the pack
// carries any. Each chain reports its own checks under the chain file's path.
func checkHostEvidence(bundlePath string, opts VerifyOptions) []CheckResult {
	hostEvidence := externalreceipt.VerifyBundleWithOptions(bundlePath, externalreceipt.VerifyOptions{PublicKeyHex: opts.ExternalHostKeyHex})
	if !hostEvidence.Found {
		reason := "pack has no receipt chain files under host_evidence/ or 11_HOST_EVIDENCE/"
		if len(hostEvidence.ReportFiles) > 0 {
			// Named like a correlation or verification report and parsing as
			// one: present, but not a chain to verify.
			reason += fmt.Sprintf("; %d report file(s) there are not receipt chains and were not verified: %s",
				len(hostEvidence.ReportFiles), strings.Join(hostEvidence.ReportFiles, ", "))
		}
		return []CheckResult{notRun("host_evidence", reason)}
	}
	results := make([]CheckResult, 0, len(hostEvidence.Checks))
	for _, check := range hostEvidence.Checks {
		results = append(results, CheckResult{
			Name:   check.Name,
			Pass:   check.Pass,
			Status: CheckStatus(check.Status),
			Detail: check.Detail,
			Reason: check.Reason,
		})
	}
	if len(results) == 0 {
		return []CheckResult{failed("host_evidence", "host evidence chain files produced no checks")}
	}
	return results
}

// --- Helpers ---

// receiptDir is where the pack keeps its receipts: receipts/ when that
// directory exists, else 02_PROOFGRAPH/receipts/. A receipts name that leaves
// the pack is an error, not a missing directory.
func receiptDir(pack *packFiles) (string, error) {
	legacy, err := pack.hasDir("receipts")
	if err != nil {
		return "", fmt.Errorf("receipts is not read: %v", err)
	}
	if legacy {
		return "receipts", nil
	}
	return "02_PROOFGRAPH/receipts", nil
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
