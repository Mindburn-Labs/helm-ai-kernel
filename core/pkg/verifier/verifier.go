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
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
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
	for _, name := range []string{"00_INDEX.json", "manifest.json"} {
		data, err := os.ReadFile(filepath.Join(bundlePath, name))
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

func checkEmbeddedSignatureTrust(bundlePath string, opts VerifyOptions) CheckResult {
	valid, selfAttested, total := countEmbeddedSignatureTrust(bundlePath, opts)
	if total == 0 {
		return notRun("embedded_signature_trust", "no receipt or attestation in the pack declares a signature, and no configured witness key matches a witness signature")
	}
	if valid == total {
		detail := fmt.Sprintf("%d embedded receipt or witness signatures verified against configured trust roots", valid)
		if selfAttested > 0 {
			// Audit 23-07: dev-local MCP receipts are checked against the key
			// they carry, which the seal covers. Say so instead of calling it
			// a configured trust root.
			detail = fmt.Sprintf("%d embedded receipt or witness signatures verified: %d against configured trust roots, %d self-attested against keys carried in the dev-local pack (integrity under the seal, not independent provenance)", valid, valid-selfAttested, selfAttested)
		}
		return CheckResult{
			Name:   "embedded_signature_trust",
			Pass:   true,
			Detail: detail,
		}
	}
	return CheckResult{
		Name:   "embedded_signature_trust",
		Pass:   false,
		Reason: fmt.Sprintf("%d/%d embedded receipt or witness signatures require a configured verifier; none are trusted by presence alone", total-valid, total),
	}
}

func countEmbeddedSignatures(bundlePath string, opts VerifyOptions) (int, int) {
	valid, _, total := countEmbeddedSignatureTrust(bundlePath, opts)
	return valid, total
}

// countEmbeddedSignatureTrust returns how many embedded signatures verified,
// how many of those verified only against a key carried in the pack, and the
// total that required verification.
func countEmbeddedSignatureTrust(bundlePath string, opts VerifyOptions) (int, int, int) {
	valid := 0
	selfAttested := 0
	total := 0
	for _, dir := range []string{receiptPath(bundlePath), filepath.Join(bundlePath, "07_ATTESTATIONS")} {
		if !dirExists(dir) {
			continue
		}
		_ = filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() || filepath.Ext(path) != ".json" {
				return nil
			}
			data, readErr := os.ReadFile(path)
			if readErr != nil {
				return nil
			}
			document, parseErr := receiptverify.ParseReceiptDocument(data)
			if document == nil {
				return nil
			}
			signatureValue, signatureDeclared := document["signature"]
			_, signatureVersionDeclared := document["signature_version"]
			witnessValue, witnessDeclared := document["witness_signatures"]
			if parseErr != nil {
				if signatureDeclared || signatureVersionDeclared || witnessDeclared {
					total++
				}
				return nil
			}
			if signatureDeclared || signatureVersionDeclared {
				total++
				sig, sigOK := signatureValue.(string)
				if sigOK && sig != "" {
					if ok, packKey := verifyEmbeddedDocumentSignature(document, sig, opts); ok {
						valid++
						if packKey {
							selfAttested++
						}
					}
				}
			}
			if witnesses, ok := witnessValue.([]any); ok {
				for _, witness := range witnesses {
					item, ok := witness.(map[string]any)
					if !ok {
						continue
					}
					signatureValue, signatureDeclared := item["signature"]
					if !signatureDeclared {
						continue
					}
					keyHex := strings.TrimSpace(opts.WitnessPublicKeysHex[firstString(item, "witness_id")])
					if keyHex == "" {
						// Witness quorum signatures anchor to the witness
						// registry; without a configured key they are
						// skipped, never presence-trusted or auto-failed.
						continue
					}
					total++
					sig, ok := signatureValue.(string)
					if ok && sig != "" && verifyWitnessReceiptSignature(document, sig, keyHex) {
						valid++
					}
				}
			}
			return nil
		})
	}
	return valid, selfAttested, total
}

// verifyEmbeddedDocumentSignature reports whether the signature verified and
// whether it verified only against a key carried inside the pack.
func verifyEmbeddedDocumentSignature(document map[string]any, sig string, opts VerifyOptions) (bool, bool) {
	switch firstString(document, "receipt_version") {
	case "managed_agent_live_scenario_receipt.v1":
		if firstString(document, "signature_payload") != "decision_hash" {
			return false, false
		}
		return verifyManagedAgentEd25519Signature(document, sig, opts.ManagedAgentReceiptPublicKeyHex, firstString(document, "decision_hash")), false
	case "managed_agent_execution_receipt.v1":
		return verifyManagedAgentEd25519Signature(document, sig, opts.ManagedAgentReceiptPublicKeyHex, firstString(document, "receipt_hash")), false
	default:
		// MCP proof receipts bind their class to the signed EffectID prefix
		// (covered by the receipt signature). The unsigned Type field survives
		// only as a fallback for already-published dev-local packs that
		// predate signed class binding; a Type that contradicts the signed
		// class is a crafted receipt and fails closed.
		const (
			mcpPolicyDecisionClass = "mcp_policy_decision"
			mcpGovernedEffectClass = "mcp_governed_effect_execution"
		)
		effectID := firstString(document, "effect_id")
		class := ""
		switch {
		case strings.HasPrefix(effectID, mcpPolicyDecisionClass+"/"):
			class = mcpPolicyDecisionClass
		case strings.HasPrefix(effectID, mcpGovernedEffectClass+"/"):
			class = mcpGovernedEffectClass
		}
		if receiptType := firstString(document, "type"); receiptType != "" {
			if class == "" {
				class = receiptType
			} else if receiptType != class {
				return false, false
			}
		}
		switch class {
		case mcpPolicyDecisionClass:
			ok := verifyMCPPolicyDecisionReceiptSignature(document, sig, opts)
			return ok, ok
		case mcpGovernedEffectClass:
			ok := verifyMCPGovernedEffectReceiptSignature(document, sig, opts)
			return ok, ok
		default:
			return verifyEvaluateReceiptV5AgainstCallerKey(document, sig), false
		}
	}
}

// verifyEvaluateReceiptV5AgainstCallerKey checks a Kernel evaluate receipt.v5
// against HELM_EVIDENCE_TRUSTED_PUBLIC_KEY_HEX (or HELM_EVIDENCE_SIGNER_PUBLIC_KEY_HEX).
// A public_key_set carried inside the receipt is compared for mismatch only;
// it is never a trust root. This is the brew 0.8.4 stranger path for
// `helm-ai-kernel verify <evidence-pack.tar>`, not --allow-self-attested.
func verifyEvaluateReceiptV5AgainstCallerKey(document map[string]any, sig string) bool {
	if firstString(document, "signature_version") != contracts.ReceiptSignatureV5 {
		return false
	}
	trusted := strings.TrimSpace(firstNonEmptyEnv("HELM_EVIDENCE_TRUSTED_PUBLIC_KEY_HEX", "HELM_EVIDENCE_SIGNER_PUBLIC_KEY_HEX"))
	if trusted == "" {
		return false
	}
	if keySet, ok := document["public_key_set"].(map[string]any); ok {
		if embedded := strings.TrimSpace(firstString(keySet, "ed25519")); embedded != "" && !strings.EqualFold(embedded, trusted) {
			return false
		}
	}
	return verifyEd25519CanonicalReceipt(document, sig, trusted)
}

func firstNonEmptyEnv(keys ...string) string {
	for _, key := range keys {
		if value := strings.TrimSpace(os.Getenv(key)); value != "" {
			return value
		}
	}
	return ""
}

// verifyMCPGovernedEffectReceiptSignature verifies the SafeExecutor receipt
// emitted by the local positive MCP proof. Like the policy-decision receipt,
// its disclosed key is trusted only inside a dev-local pack whose seal has
// already passed. Production profiles require out-of-band trust roots.
func verifyMCPGovernedEffectReceiptSignature(document map[string]any, sig string, opts VerifyOptions) bool {
	profile := opts.Profile
	if profile == "" {
		profile = evidencepkg.EvidenceTrustProfileDevLocal
	}
	if profile != evidencepkg.EvidenceTrustProfileDevLocal || firstString(document, "signature_algorithm") != "ed25519" {
		return false
	}
	keySet, _ := document["public_key_set"].(map[string]any)
	if keySet == nil {
		return false
	}
	return verifyEd25519CanonicalReceipt(document, sig, firstString(keySet, "ed25519"))
}

// verifyMCPPolicyDecisionReceiptSignature verifies kernel-issued MCP proof
// receipts (`mcp proof` quarantine scenarios). New receipts use the signer-
// populated public_key_set; metadata disclosure remains as a legacy fallback.
// Both disclosure forms are integrity-anchored by the pack seal and trusted
// only under dev-local. Every other profile requires an out-of-band root.
func verifyMCPPolicyDecisionReceiptSignature(document map[string]any, sig string, opts VerifyOptions) bool {
	profile := opts.Profile
	if profile == "" {
		profile = evidencepkg.EvidenceTrustProfileDevLocal
	}
	if profile != evidencepkg.EvidenceTrustProfileDevLocal {
		return false
	}
	if firstString(document, "signature_algorithm") == "ed25519" {
		if keySet, ok := document["public_key_set"].(map[string]any); ok {
			if keyHex := strings.TrimSpace(firstString(keySet, "ed25519")); keyHex != "" {
				return verifyEd25519CanonicalReceipt(document, sig, keyHex)
			}
		}
	}
	meta, _ := document["metadata"].(map[string]any)
	if meta == nil {
		return false
	}
	if firstString(meta, "signature_key_type") != "ed25519" {
		return false
	}
	keyHex := strings.TrimSpace(firstString(meta, "signing_public_key_hex"))
	if keyHex == "" {
		return false
	}
	if ref := strings.TrimSpace(firstString(meta, "signature_key_ref")); ref != "" {
		const refPrefix = "ed25519:"
		if !strings.HasPrefix(ref, refPrefix) || !strings.HasPrefix(strings.ToLower(keyHex), strings.ToLower(strings.TrimPrefix(ref, refPrefix))) {
			return false
		}
	}
	return verifyEd25519CanonicalReceipt(document, sig, keyHex)
}

func verifyEd25519CanonicalReceipt(document map[string]any, sig, keyHex string) bool {
	if !receiptverify.ClassicalEd25519MetadataCompatible(
		firstString(document, "signature_profile"),
		firstString(document, "signature_algorithm"),
	) {
		return false
	}
	pubBytes, err := hex.DecodeString(strings.TrimSpace(keyHex))
	if err != nil || len(pubBytes) != ed25519.PublicKeySize {
		return false
	}
	sigBytes, err := hex.DecodeString(strings.TrimSpace(sig))
	if err != nil || len(sigBytes) != ed25519.SignatureSize {
		return false
	}
	var lamport uint64
	if v := firstUint(document, "lamport_clock"); v != nil {
		lamport = *v
	}
	// Mirrors crypto.CanonicalizeReceipt for legacy V4. The active receipt.v5
	// payload below is a narrow JCS envelope so its field boundaries cannot
	// collide when a signed value contains a colon.
	payload := []byte(fmt.Sprintf("%s:%s:%s:%s:%s:%s:%d:%s",
		firstString(document, "receipt_id"),
		firstString(document, "decision_id"),
		firstString(document, "effect_id"),
		firstString(document, "status"),
		firstString(document, "output_hash"),
		firstString(document, "prev_hash"),
		lamport,
		firstString(document, "args_hash"),
	))
	switch sigVersion := firstString(document, "signature_version"); sigVersion {
	case "":
		// legacy V4 — payload as built
	case "receipt.v5":
		// V5 has a fixed signed schema. firstString deliberately treats a
		// missing legacy alias and an explicit empty value alike, but doing so
		// here would let an attacker remove an explicitly empty genesis
		// prev_hash without changing the reconstructed payload.
		for _, field := range []string{
			"signature_version", "receipt_id", "decision_id", "effect_id", "status", "output_hash", "prev_hash",
			"args_hash", "verdict", "reason_code", "policy_hash", "session_id",
		} {
			if _, ok := document[field].(string); !ok {
				return false
			}
		}
		rawLamport, ok := document["lamport_clock"].(json.Number)
		if !ok || canonicalize.CheckInteroperableNumbers(rawLamport) != nil {
			return false
		}
		lamportValue := firstUint(document, "lamport_clock")
		if lamportValue == nil {
			return false
		}
		var err error
		payload, err = canonicalize.InteroperableJCS(receiptV5DocumentEnvelope{
			SignatureVersion: sigVersion,
			ReceiptID:        firstString(document, "receipt_id"),
			DecisionID:       firstString(document, "decision_id"),
			EffectID:         firstString(document, "effect_id"),
			Status:           firstString(document, "status"),
			OutputHash:       firstString(document, "output_hash"),
			PrevHash:         firstString(document, "prev_hash"),
			LamportClock:     *lamportValue,
			ArgsHash:         firstString(document, "args_hash"),
			Verdict:          firstString(document, "verdict"),
			ReasonCode:       firstString(document, "reason_code"),
			PolicyHash:       firstString(document, "policy_hash"),
			SessionID:        firstString(document, "session_id"),
		})
		if err != nil {
			return false
		}
	default:
		return false
	}
	return ed25519.Verify(ed25519.PublicKey(pubBytes), payload, sigBytes)
}

// receiptV5DocumentEnvelope must stay structurally identical to
// crypto.receiptV5SigningEnvelope. The offline verifier intentionally does
// not import the signer package, so it reconstructs the public signing
// contract from the exported receipt document instead.
type receiptV5DocumentEnvelope struct {
	SignatureVersion string `json:"signature_version"`
	ReceiptID        string `json:"receipt_id"`
	DecisionID       string `json:"decision_id"`
	EffectID         string `json:"effect_id"`
	Status           string `json:"status"`
	OutputHash       string `json:"output_hash"`
	PrevHash         string `json:"prev_hash"`
	LamportClock     uint64 `json:"lamport_clock"`
	ArgsHash         string `json:"args_hash"`
	Verdict          string `json:"verdict"`
	ReasonCode       string `json:"reason_code"`
	PolicyHash       string `json:"policy_hash"`
	SessionID        string `json:"session_id"`
}

// verifyWitnessReceiptSignature verifies a witness attestation: an Ed25519
// signature by the configured witness key over the receipt's hex-decoded
// receipt_hash (mirrors witness.VerifyAttestation). Missing or malformed
// hash material fails closed — a configured witness demands verification.
func verifyWitnessReceiptSignature(document map[string]any, sig, trustedPublicKeyHex string) bool {
	receiptHashHex := strings.TrimSpace(firstString(document, "receipt_hash"))
	if receiptHashHex == "" {
		return false
	}
	receiptHashBytes, err := hex.DecodeString(strings.TrimPrefix(receiptHashHex, "sha256:"))
	if err != nil || len(receiptHashBytes) == 0 {
		return false
	}
	pubBytes, err := hex.DecodeString(strings.TrimSpace(trustedPublicKeyHex))
	if err != nil || len(pubBytes) != ed25519.PublicKeySize {
		return false
	}
	sigBytes, err := hex.DecodeString(strings.TrimSpace(sig))
	if err != nil || len(sigBytes) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(ed25519.PublicKey(pubBytes), receiptHashBytes, sigBytes)
}

func verifyManagedAgentEd25519Signature(document map[string]any, sig, trustedPublicKeyHex, payload string) bool {
	if payload == "" || firstString(document, "signature_algorithm") != "ed25519" {
		return false
	}
	trustedPublicKeyHex = strings.TrimSpace(trustedPublicKeyHex)
	if trustedPublicKeyHex == "" {
		return false
	}
	declaredPublicKeyHex := strings.TrimSpace(firstString(document, "signing_public_key_hex", "public_key_hex"))
	if declaredPublicKeyHex != "" && !strings.EqualFold(declaredPublicKeyHex, trustedPublicKeyHex) {
		return false
	}
	pubBytes, err := hex.DecodeString(trustedPublicKeyHex)
	if err != nil || len(pubBytes) != ed25519.PublicKeySize {
		return false
	}
	sigBytes, err := hex.DecodeString(strings.TrimSpace(sig))
	if err != nil || len(sigBytes) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(ed25519.PublicKey(pubBytes), []byte(payload), sigBytes)
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

// --- Check implementations ---

func checkStructure(bundlePath string) CheckResult {
	info, err := os.Stat(bundlePath)
	if err != nil {
		return CheckResult{Name: "structure", Pass: false, Reason: fmt.Sprintf("path not found: %v", err)}
	}
	if !info.IsDir() {
		return CheckResult{Name: "structure", Pass: false, Reason: "bundle must be a directory (tar.gz extraction not yet supported in library)"}
	}

	// Check for manifest.json or 00_INDEX.json
	hasManifest := fileExists(filepath.Join(bundlePath, "manifest.json"))
	hasIndex := fileExists(filepath.Join(bundlePath, "00_INDEX.json"))

	if !hasManifest && !hasIndex {
		return CheckResult{Name: "structure", Pass: false, Reason: "missing manifest.json or 00_INDEX.json"}
	}

	// Only the presence of an index or manifest file is established here; what
	// they list is checked by index_integrity, file_hashes and the seal.
	present := "00_INDEX.json"
	switch {
	case hasManifest && hasIndex:
		present = "00_INDEX.json and manifest.json"
	case hasManifest:
		present = "manifest.json"
	}
	return verified("structure", "pack is a directory that holds "+present)
}

func checkIndex(bundlePath string) CheckResult {
	const name = "index_integrity"
	indexPath := filepath.Join(bundlePath, "00_INDEX.json")
	if !fileExists(indexPath) {
		// A manifest.json pack lists its hashes in the manifest; file_hashes
		// reads those. Parsing the manifest here used to count as index
		// integrity although no index was compared.
		return notRun(name, "pack has no 00_INDEX.json, so there are no indexed hashes to compare")
	}

	data, err := os.ReadFile(indexPath)
	if err != nil {
		return failed(name, fmt.Sprintf("cannot read index: %v", err))
	}
	var index indexFile
	if err := json.Unmarshal(data, &index); err != nil {
		return failed(name, fmt.Sprintf("invalid index JSON: %v", err))
	}
	if len(index.Entries) == 0 {
		return notRun(name, "00_INDEX.json lists no entries, so there are no indexed hashes to compare")
	}
	for _, entry := range index.Entries {
		if entry.Path == "" {
			return failed(name, "index entry path is required")
		}
		data, err := readPackFile(bundlePath, entry.Path)
		if errors.Is(err, errOutsidePack) {
			return failed(name, fmt.Sprintf("index entry escapes bundle: %v", err))
		}
		if err != nil {
			return failed(name, fmt.Sprintf("indexed file missing %s: %v", entry.Path, err))
		}
		if actual := sha256Hex(data); actual != entry.SHA256 {
			return failed(name, fmt.Sprintf("indexed hash mismatch for %s: expected %s, got %s", entry.Path, entry.SHA256, actual))
		}
	}
	return verified(name, fmt.Sprintf("%d files listed in 00_INDEX.json are present and match their SHA-256", len(index.Entries)))
}

// checkRoots derives the manifest root hash and Merkle root from the hashes
// 00_INDEX.json lists. It compares them with nothing: the seal check does that.
// An index that lists no entries leaves it NOT_RUN, as it leaves
// index_integrity.
func checkRoots(bundlePath string, report *VerifyReport) CheckResult {
	const name = "roots"
	if !fileExists(filepath.Join(bundlePath, "00_INDEX.json")) {
		return notRun(name, "pack has no 00_INDEX.json to derive roots from")
	}
	roots, err := computeIndexRoots(bundlePath)
	if err != nil {
		return failed(name, err.Error())
	}
	if roots.EntryCount == 0 {
		// The same state index_integrity reports for this index: roots over
		// no entries are derived from nothing, and say nothing about a file.
		return notRun(name, "00_INDEX.json lists no entries, so there are no indexed hashes to derive roots from")
	}
	if roots.ManifestRootHash == "" {
		return failed(name, "00_INDEX.json yielded no manifest root hash")
	}
	report.Roots = roots
	report.MerkleRoot = roots.MerkleRoot
	return verified(name, fmt.Sprintf("derived from 00_INDEX.json: %d indexed entries; manifest_root_hash=%s; merkle_root=%s", roots.EntryCount, roots.ManifestRootHash, roots.MerkleRoot))
}

type indexEntry struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

type indexFile struct {
	Entries []indexEntry `json:"entries"`
}

func computeIndexRoots(bundlePath string) (VerifyRoots, error) {
	if !fileExists(filepath.Join(bundlePath, "00_INDEX.json")) {
		return VerifyRoots{}, nil
	}
	roots, err := evidencepkg.ComputeEvidencePackIndexRoots(bundlePath)
	if err != nil {
		return VerifyRoots{}, err
	}
	return VerifyRoots{
		ManifestRootHash: roots.IndexHash,
		MerkleRoot:       roots.MerkleRoot,
		EntryCount:       roots.EntryCount,
	}, nil
}

// errOutsidePack marks a path a pack file names that does not stay inside the
// pack directory.
var errOutsidePack = errors.New("path is outside the pack")

// packFilePath resolves a path that a pack file names (an 00_INDEX.json entry
// or a manifest.json file_hashes key) to the file to read. It is the one
// containment rule for both: the path must be relative, must not contain a
// ".." segment, and must still be inside the pack directory once symbolic
// links are resolved. A path that breaks the rule returns an error wrapping
// errOutsidePack; any other error means the file could not be found.
//
// Without it a manifest naming "../../outside.txt" had that file hashed and
// reported as a verified pack file.
func packFilePath(bundlePath, name string) (string, error) {
	if filepath.IsAbs(name) || filepath.VolumeName(name) != "" || strings.HasPrefix(name, "/") || strings.HasPrefix(name, `\`) {
		return "", fmt.Errorf("%w: %q is absolute, and a pack names its files relative to its own directory", errOutsidePack, name)
	}
	for _, segment := range strings.FieldsFunc(name, func(r rune) bool { return r == '/' || r == '\\' }) {
		if segment == ".." {
			return "", fmt.Errorf("%w: %q contains a \"..\" segment", errOutsidePack, name)
		}
	}
	root, err := filepath.EvalSymlinks(bundlePath)
	if err != nil {
		return "", fmt.Errorf("cannot resolve the pack directory: %v", err)
	}
	resolved, err := filepath.EvalSymlinks(filepath.Join(bundlePath, filepath.FromSlash(name)))
	if err != nil {
		return "", err
	}
	rel, err := filepath.Rel(root, resolved)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return "", fmt.Errorf("%w: %q resolves through a symbolic link to a file that is not in the pack directory", errOutsidePack, name)
	}
	return resolved, nil
}

// readPackFile reads a file the pack names, after packFilePath has held the
// name inside the pack directory. index_integrity and file_hashes both read
// through it, so neither can be pointed at a file the pack does not hold.
func readPackFile(bundlePath, name string) ([]byte, error) {
	resolved, err := packFilePath(bundlePath, name)
	if err != nil {
		return nil, err
	}
	return os.ReadFile(resolved) // #nosec G304 -- packFilePath resolved the path and refused any that leaves the pack directory
}

func checkFileHashes(bundlePath string) []CheckResult {
	var results []CheckResult

	// Try manifest.json with file_hashes
	manifestPath := filepath.Join(bundlePath, "manifest.json")
	if fileExists(manifestPath) {
		data, err := os.ReadFile(manifestPath)
		if err != nil {
			return []CheckResult{{Name: "file_hashes", Pass: false, Reason: fmt.Sprintf("cannot read manifest: %v", err)}}
		}

		var manifest struct {
			FileHashes map[string]string `json:"file_hashes"`
		}
		if err := json.Unmarshal(data, &manifest); err != nil {
			// A manifest that does not parse is input this check could not
			// read, not a manifest without hashes.
			return []CheckResult{failed("file_hashes", fmt.Sprintf("invalid manifest JSON: %v", err))}
		}
		if len(manifest.FileHashes) == 0 {
			return []CheckResult{notRun("file_hashes", "manifest.json declares no file_hashes")}
		}

		// Sort keys for deterministic output
		keys := make([]string, 0, len(manifest.FileHashes))
		for k := range manifest.FileHashes {
			keys = append(keys, k)
		}
		sort.Strings(keys)

		for _, name := range keys {
			expectedHash := manifest.FileHashes[name]
			content, err := readPackFile(bundlePath, name)
			if errors.Is(err, errOutsidePack) {
				results = append(results, failed(fmt.Sprintf("hash:%s", name), fmt.Sprintf("manifest path is outside the pack, so it was not read: %v", err)))
				continue
			}
			if err != nil {
				results = append(results, CheckResult{
					Name: fmt.Sprintf("hash:%s", name), Pass: false,
					Reason: fmt.Sprintf("file missing: %v", err),
				})
				continue
			}
			actualHash := sha256Hex(content)
			if actualHash != expectedHash {
				results = append(results, CheckResult{
					Name: fmt.Sprintf("hash:%s", name), Pass: false,
					Reason: fmt.Sprintf("hash mismatch: expected %s, got %s", expectedHash, actualHash),
				})
			} else {
				results = append(results, CheckResult{
					Name:   fmt.Sprintf("hash:%s", name),
					Pass:   true,
					Detail: "SHA-256 matches manifest.json",
				})
			}
		}
	}

	if len(results) == 0 {
		results = append(results, notRun("file_hashes", "pack has no manifest.json, so there are no manifest hashes to compare"))
	}

	return results
}

func checkConnectorEvidence(bundlePath string) CheckResult {
	path := ""
	for _, candidate := range []string{
		filepath.Join(bundlePath, "connector_evidence.json"),
		filepath.Join(bundlePath, "09_SCHEMAS", "connector_evidence.json"),
		filepath.Join(bundlePath, "07_ATTESTATIONS", "connector_evidence.json"),
	} {
		if fileExists(candidate) {
			path = candidate
			break
		}
	}
	if path == "" {
		return notRun("connector_evidence", "pack has no connector_evidence.json")
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return CheckResult{Name: "connector_evidence", Pass: false, Reason: fmt.Sprintf("cannot read connector evidence: %v", err)}
	}
	records, err := parseConnectorEvidenceRecords(data)
	if err != nil {
		return CheckResult{Name: "connector_evidence", Pass: false, Reason: err.Error()}
	}
	if len(records) == 0 {
		return CheckResult{Name: "connector_evidence", Pass: false, Reason: "connector evidence must contain at least one record"}
	}

	var failures []string
	for i, record := range records {
		for _, issue := range evidencepkg.ValidateConnectorEvidenceRecord(record) {
			failures = append(failures, fmt.Sprintf("records[%d].%s", i, issue))
		}
	}
	if len(failures) > 0 {
		return CheckResult{Name: "connector_evidence", Pass: false, Reason: strings.Join(failures, "; ")}
	}
	// ValidateConnectorEvidenceRecord checks that the fields are present and
	// well-formed. It has nothing to recompute the hashes from.
	return verified("connector_evidence", fmt.Sprintf("%d connector evidence records declare the required sha256 hashes and references; the hashes are not recomputed", len(records)))
}

func parseConnectorEvidenceRecords(data []byte) ([]evidencepkg.ConnectorEvidenceRecord, error) {
	trimmed := strings.TrimSpace(string(data))
	if trimmed == "" {
		return nil, fmt.Errorf("connector evidence is empty")
	}
	if strings.HasPrefix(trimmed, "[") {
		var records []evidencepkg.ConnectorEvidenceRecord
		if err := json.Unmarshal(data, &records); err != nil {
			return nil, fmt.Errorf("invalid connector evidence array: %v", err)
		}
		return records, nil
	}

	var envelope struct {
		Records           []evidencepkg.ConnectorEvidenceRecord `json:"records"`
		ConnectorEvidence []evidencepkg.ConnectorEvidenceRecord `json:"connector_evidence"`
	}
	if err := json.Unmarshal(data, &envelope); err == nil {
		if len(envelope.Records) > 0 {
			return envelope.Records, nil
		}
		if len(envelope.ConnectorEvidence) > 0 {
			return envelope.ConnectorEvidence, nil
		}
	}

	var record evidencepkg.ConnectorEvidenceRecord
	if err := json.Unmarshal(data, &record); err != nil {
		return nil, fmt.Errorf("invalid connector evidence object: %v", err)
	}
	return []evidencepkg.ConnectorEvidenceRecord{record}, nil
}

func checkChainIntegrity(bundlePath string) CheckResult {
	// Look for proofgraph.json or 02_PROOFGRAPH/
	pgPath := filepath.Join(bundlePath, "proofgraph.json")
	pgDir := filepath.Join(bundlePath, "02_PROOFGRAPH")

	if !fileExists(pgPath) && !dirExists(pgDir) {
		return CheckResult{
			Name:   "chain_integrity",
			Pass:   false,
			Reason: "missing proof graph: neither proofgraph.json nor 02_PROOFGRAPH/ found — chain integrity cannot be verified",
		}
	}

	if fileExists(pgPath) {
		data, err := os.ReadFile(pgPath)
		if err != nil {
			return CheckResult{Name: "chain_integrity", Pass: false, Reason: fmt.Sprintf("cannot read proofgraph: %v", err)}
		}
		var pg map[string]any
		if err := json.Unmarshal(data, &pg); err != nil {
			return CheckResult{Name: "chain_integrity", Pass: false, Reason: fmt.Sprintf("invalid proofgraph JSON: %v", err)}
		}
	}

	// The proof graph being present and parseable was, until now, the entire
	// check — it never read prev_hash and never walked a parent, so a chain with
	// its middle removed, its order changed, or a fork grafted on reported
	// "chain integrity: PASS" (F-03). Actually link the receipts.
	if !packClaimsAChain(receiptPath(bundlePath)) {
		return unchainedPackResult("chain_integrity", receiptPath(bundlePath))
	}
	chains, res := loadReceiptChains(bundlePath, "chain_integrity")
	if res != nil {
		return *res
	}

	linked := 0
	for _, chain := range chains {
		// linkChain already proved each node's prev_hash resolves to the chain
		// hash of its predecessor, that there is exactly one genesis, no forks,
		// no cycles and no orphans. Re-assert the linkage explicitly so the
		// invariant is stated where a reader looks for it.
		for i := 1; i < len(chain.ordered); i++ {
			prev := chain.ordered[i-1]
			cur := chain.ordered[i]
			if !prev.matches(cur.receipt.PrevHash) {
				return CheckResult{
					Name: "chain_integrity", Pass: false,
					Reason: fmt.Sprintf("session %q: receipt %s prev_hash=%s does not match the chain hash of %s (%s)",
						chain.sessionID, cur.receipt.ReceiptID, cur.receipt.PrevHash, prev.receipt.ReceiptID, prev.primary()),
				}
			}
		}
		linked += len(chain.ordered)
	}

	return CheckResult{
		Name: "chain_integrity", Pass: true,
		Detail: fmt.Sprintf("%d receipts across %d session chain(s) link genesis-to-head with no fork, gap, or cycle", linked, len(chains)),
	}
}

// checkLamportMonotonicity verifies that each receipt chain carries strictly
// increasing Lamport clocks, and that the genesis receipt starts at 1.
//
// This previously returned Pass with "%d receipt files present" straight from
// os.ReadDir — no clock was ever parsed, so any ordering claim passed (F-03).
func checkLamportMonotonicity(bundlePath string) CheckResult {
	if !packClaimsAChain(receiptPath(bundlePath)) {
		return unchainedPackResult("lamport_monotonicity", receiptPath(bundlePath))
	}
	chains, res := loadReceiptChains(bundlePath, "lamport_monotonicity")
	if res != nil {
		return *res
	}

	checked := 0
	for _, chain := range chains {
		for i, r := range chain.ordered {
			if i == 0 {
				if r.receipt.LamportClock != 1 {
					return CheckResult{
						Name: "lamport_monotonicity", Pass: false,
						Reason: fmt.Sprintf("session %q genesis receipt %s has lamport_clock=%d, want 1 — the chain head is missing",
							chain.sessionID, r.receipt.ReceiptID, r.receipt.LamportClock),
					}
				}
				checked++
				continue
			}
			prev := chain.ordered[i-1].receipt
			if r.receipt.LamportClock != prev.LamportClock+1 {
				return CheckResult{
					Name: "lamport_monotonicity", Pass: false,
					Reason: fmt.Sprintf("session %q: receipt %s has lamport_clock=%d after %d — chain is truncated, reordered, or has a gap",
						chain.sessionID, r.receipt.ReceiptID, r.receipt.LamportClock, prev.LamportClock),
				}
			}
			checked++
		}
	}

	return CheckResult{
		Name: "lamport_monotonicity", Pass: true,
		Detail: fmt.Sprintf("%d receipts across %d session chain(s) are strictly monotonic from genesis", checked, len(chains)),
	}
}

// receiptNode pairs a parsed receipt with the chain hash other receipts use to
// reference it.
type receiptNode struct {
	receipt *contracts.Receipt
	// hashes are the identities a successor's prev_hash may legitimately carry.
	// EvidencePack producers do not agree on one derivation:
	//   - store     chains on contracts.ReceiptChainHash (JCS over the receipt)
	//   - mcp-proof chains on "sha256:"+sha256 of the receipt file as written
	//   - demo      chains on a "hash" field the receipt declares about itself
	// The first two are recomputed here, so tampering breaks linkage. The third
	// has no specified preimage and cannot be recomputed — recorded in the
	// security ledger as a schema gap.
	hashes []string
	file   string
}

// normalizeHash strips the optional "sha256:" prefix so identities produced by
// different producers compare equal.
func normalizeHash(h string) string {
	return strings.TrimPrefix(strings.TrimSpace(h), "sha256:")
}

// matches reports whether prevHash refers to this node under any derivation.
func (n receiptNode) matches(prevHash string) bool {
	want := normalizeHash(prevHash)
	if want == "" {
		return false
	}
	for _, h := range n.hashes {
		if normalizeHash(h) == want {
			return true
		}
	}
	return false
}

// primary is the identity quoted in diagnostics.
func (n receiptNode) primary() string {
	if len(n.hashes) == 0 {
		return ""
	}
	return normalizeHash(n.hashes[0])
}

// receiptChain is one session's receipts ordered from genesis to head.
type receiptChain struct {
	sessionID string
	ordered   []receiptNode
}

// loadReceiptChains parses every receipt in the pack, groups them by session,
// and links each group into a single chain by walking prev_hash from genesis.
//
// It returns a non-nil CheckResult when the receipts cannot be loaded or the
// chain does not link, so callers surface the failure under their own name.
func loadReceiptChains(bundlePath, checkName string) ([]receiptChain, *CheckResult) {
	fail := func(format string, args ...any) (
		[]receiptChain, *CheckResult) {
		return nil, &CheckResult{Name: checkName, Pass: false, Reason: fmt.Sprintf(format, args...)}
	}

	receiptsDir := receiptPath(bundlePath)
	if !dirExists(receiptsDir) {
		return fail("missing receipts directory (checked receipts/ and 02_PROOFGRAPH/receipts/) — chain of custody cannot be verified")
	}
	entries, err := os.ReadDir(receiptsDir)
	if err != nil {
		return fail("cannot read receipts: %v", err)
	}

	bySession := map[string][]receiptNode{}
	total := 0
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		filePath := filepath.Join(receiptsDir, entry.Name())
		data, err := os.ReadFile(filePath)
		if err != nil {
			return fail("cannot read receipt %s: %v", entry.Name(), err)
		}
		var receipt contracts.Receipt
		if err := json.Unmarshal(data, &receipt); err != nil {
			return fail("receipt %s is not valid JSON: %v", entry.Name(), err)
		}

		// EvidencePacks carry more than one receipt schema, and they do not
		// agree on how a node is identified:
		//
		//   - store.buildNextCausalReceipt chains contracts.Receipt on
		//     contracts.ReceiptChainHash (JCS over the receipt minus its
		//     transparency fields).
		//   - demo/mcp-proof/financedemo receipts carry their own "hash" field
		//     and chain children on that value directly.
		//
		// Use the declared hash when the producer supplies one, otherwise derive
		// it. Either way the linkage below is real: truncation, reordering and
		// forks are detected for both shapes.
		//
		// Caveat recorded in the security ledger: a self-declared "hash" cannot
		// be recomputed by the verifier, because its preimage is not specified
		// anywhere. For those receipts this proves the chain is well-formed, not
		// that each node's contents are bound to its identity.
		var raw map[string]any
		if err := json.Unmarshal(data, &raw); err != nil {
			return fail("receipt %s is not a JSON object: %v", entry.Name(), err)
		}

		var hashes []string
		// Recomputed identities first, so diagnostics quote a verifiable value.
		if h, hErr := contracts.ReceiptChainHash(&receipt); hErr == nil {
			hashes = append(hashes, h)
		}
		hashes = append(hashes, "sha256:"+sha256Hex(data))
		if declared, _ := raw["hash"].(string); strings.TrimSpace(declared) != "" {
			hashes = append(hashes, declared)
		}

		// Lamport lives under different keys across the schemas.
		if receipt.LamportClock == 0 {
			// Reject a non-integral or negative clock rather than truncating it:
			// uint64(1.9) is 1, which would let a tampered receipt slot into an
			// ordering it does not actually occupy.
			if v, ok := raw["lamport"].(float64); ok {
				if v != math.Trunc(v) || v < 0 {
					return fail("receipt %s has a non-integral lamport clock %v", entry.Name(), v)
				}
				receipt.LamportClock = uint64(v)
			}
		}
		if receipt.ReceiptID == "" {
			receipt.ReceiptID, _ = raw["receipt_id"].(string)
		}

		// Only receipt.v5 binds SessionID in its signing envelope. Legacy
		// receipts retain their historical ExecutorID chain scope even when a
		// later storage migration has populated session_id for lookup purposes.
		session := receipt.ExecutorID
		if receipt.SignatureVersion == contracts.ReceiptSignatureV5 {
			session = receipt.SessionID
		}
		bySession[session] = append(bySession[session], receiptNode{
			receipt: &receipt, hashes: hashes, file: entry.Name(),
		})
		total++
	}

	if total == 0 {
		return fail("receipts directory contains no receipts — no chain of custody to verify")
	}

	chains := make([]receiptChain, 0, len(bySession))
	for session, nodes := range bySession {
		ordered, err := linkChain(nodes)
		if err != nil {
			return fail("session %q: %v", session, err)
		}
		chains = append(chains, receiptChain{sessionID: session, ordered: ordered})
	}
	sort.Slice(chains, func(i, j int) bool { return chains[i].sessionID < chains[j].sessionID })
	return chains, nil
}

// linkChain orders one session's receipts by following prev_hash from the
// genesis receipt, and rejects forks, cycles, orphans and truncation.
func linkChain(nodes []receiptNode) ([]receiptNode, error) {
	// Genesis is the receipt with an empty prev_hash. Exactly one is required:
	// zero means the head of the chain was removed, more than one means the
	// chain was forked at the root.
	var roots []receiptNode
	for _, n := range nodes {
		if normalizeHash(n.receipt.PrevHash) == "" {
			roots = append(roots, n)
		}
	}
	switch {
	case len(roots) == 0:
		return nil, fmt.Errorf("no genesis receipt (none has an empty prev_hash) — the start of the chain is missing")
	case len(roots) > 1:
		return nil, fmt.Errorf("%d receipts claim to be genesis — the chain is forked at the root", len(roots))
	}

	ordered := make([]receiptNode, 0, len(nodes))
	used := map[string]bool{}
	current := roots[0]
	for {
		ordered = append(ordered, current)
		used[current.file] = true

		var children []receiptNode
		for _, n := range nodes {
			if used[n.file] {
				continue
			}
			if current.matches(n.receipt.PrevHash) {
				children = append(children, n)
			}
		}
		if len(children) == 0 {
			break
		}
		if len(children) > 1 {
			return nil, fmt.Errorf("receipt %s has %d successors — the chain is forked",
				current.receipt.ReceiptID, len(children))
		}
		current = children[0]
		if len(ordered) > len(nodes) {
			return nil, fmt.Errorf("receipt chain contains a cycle")
		}
	}

	if len(ordered) != len(nodes) {
		// Unreached receipts point at a predecessor that is not in the pack —
		// exactly what deleting a middle receipt produces.
		var orphans []string
		for _, n := range nodes {
			if !used[n.file] {
				orphans = append(orphans, fmt.Sprintf("%s (prev_hash=%s)", n.receipt.ReceiptID, n.receipt.PrevHash))
			}
		}
		sort.Strings(orphans)
		return nil, fmt.Errorf("%d of %d receipts are unreachable from genesis — the chain is broken or truncated: %s",
			len(orphans), len(nodes), strings.Join(orphans, ", "))
	}

	return ordered, nil
}

// packClaimsAChain reports whether the pack should be held to the full
// genesis-to-head walk.
//
// That is true when any receipt carries a non-empty prev_hash, and also — fail
// closed — when the receipts directory is missing or empty, or when any receipt
// cannot be read or parsed. Only a directory of well-formed receipts that all
// lack prev_hash counts as "no chain claimed".
//
// Several producers (launchpad, conform) emit receipts with lamport clocks that
// imply an order but no prev_hash linking them — those packs assert no chain of
// custody at all. Verifying such a pack must neither invent a chain nor claim to
// have checked one. Packs that DO carry prev_hash values get the full
// genesis-to-head walk.
//
// This cannot be abused to bypass the check: stripping every prev_hash changes
// what the pack claims, and the report says so in plain text instead of
// reporting a verified chain. A missing or empty receipts directory is not "no
// chain claimed" — it is a pack with no evidence, so it falls through and fails.
func packClaimsAChain(receiptsDir string) bool {
	if !dirExists(receiptsDir) {
		return true
	}
	entries, err := os.ReadDir(receiptsDir)
	if err != nil {
		return true
	}
	receipts := 0
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		receipts++
		data, err := os.ReadFile(filepath.Join(receiptsDir, entry.Name()))
		if err != nil {
			// An unreadable receipt must not be read as "no chain claimed" —
			// that would let a corrupt or deliberately unreadable file skip the
			// walk entirely. Claim a chain so the caller falls through to
			// loadReceiptChains and fails there with the real reason.
			return true
		}
		var raw map[string]any
		if json.Unmarshal(data, &raw) != nil {
			return true
		}
		if s, _ := raw["prev_hash"].(string); strings.TrimSpace(s) != "" {
			return true
		}
	}
	return receipts == 0
}

// unchainedPackResult describes a pack that makes no chaining claim. There is
// no chain to walk, so the check did not run; it used to be counted as passed.
func unchainedPackResult(checkName, receiptsDir string) CheckResult {
	entries, _ := os.ReadDir(receiptsDir)
	n := 0
	for _, e := range entries {
		if !e.IsDir() && filepath.Ext(e.Name()) == ".json" {
			n++
		}
	}
	return notRun(checkName, fmt.Sprintf("%d receipts carry no prev_hash: this pack asserts no chain of custody, "+
		"so there is no chain to check", n))
}

func checkPolicyDecisionHashes(bundlePath string) CheckResult {
	// Verify that decision records expose a signed policy binding. Legacy
	// receipts use decision_hash. Current MCP proof receipts use the signed
	// EffectID, OutputHash (complete authorization evaluation), and ArgsHash
	// (raw authorization inputs), avoiding an unsigned compatibility field.
	receiptsDir := receiptPath(bundlePath)
	if !dirExists(receiptsDir) {
		// Already caught by lamport check, but note here too
		return CheckResult{Name: "policy_decision_hashes", Pass: false, Reason: "no receipts directory (checked receipts/ and 02_PROOFGRAPH/receipts/) — no policy decision binding to look for"}
	}

	entries, err := os.ReadDir(receiptsDir)
	if err != nil || len(entries) == 0 {
		return CheckResult{Name: "policy_decision_hashes", Pass: false, Reason: "no receipt files to look for a policy decision binding in"}
	}

	// Structural check: parse each receipt and verify either the legacy field or
	// the current signed MCP policy-receipt binding exists.
	legacyVerified := 0
	legacyTotal := 0
	mcpPolicyTotal := 0
	mcpPolicyVerified := 0
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		filePath := filepath.Join(receiptsDir, entry.Name())
		data, err := os.ReadFile(filePath)
		if err != nil {
			continue
		}
		var receipt map[string]any
		if err := json.Unmarshal(data, &receipt); err != nil {
			continue
		}
		if strings.HasPrefix(firstString(receipt, "effect_id"), "mcp_policy_decision/") {
			mcpPolicyTotal++
			if firstString(receipt, "output_hash") != "" &&
				firstString(receipt, "args_hash") != "" &&
				firstString(receipt, "signature") != "" {
				mcpPolicyVerified++
			}
			continue
		}
		legacyTotal++
		if firstString(receipt, "decision_hash") != "" {
			legacyVerified++
		}
	}

	if mcpPolicyTotal > 0 {
		if mcpPolicyTotal != mcpPolicyVerified {
			return CheckResult{Name: "policy_decision_hashes", Pass: false, Reason: fmt.Sprintf("%d/%d MCP policy receipts lack an output_hash, args_hash or signature", mcpPolicyTotal-mcpPolicyVerified, mcpPolicyTotal)}
		}
		// Presence only. The signature over these fields is checked by
		// embedded_signature_trust; neither hash is recomputed here.
		return verified("policy_decision_hashes", fmt.Sprintf("%d MCP policy receipts carry output_hash, args_hash and signature fields; presence only, the hashes are not recomputed", mcpPolicyVerified))
	}

	if legacyVerified == 0 {
		return CheckResult{Name: "policy_decision_hashes", Pass: false, Reason: "no receipts contain a policy decision binding"}
	}

	return verified("policy_decision_hashes", fmt.Sprintf("%d of %d receipts carry a decision_hash field; presence only, the hash is not recomputed", legacyVerified, legacyTotal))
}

// checkReplayDeterminism checks the replay evidence a pack declares or
// carries. The rule:
//
//   - A pack that declares gate G2 in 00_INDEX.json claims replay evidence, so
//     all of it is required: 08_TAPES/tape_manifest.json and
//     02_PROOFGRAPH/determinism_manifest.json must be present and valid, and
//     05_DIFFS must hold no files. Anything missing is FAILED.
//   - A pack that does not declare G2 is still checked on the replay material
//     it carries. A determinism manifest is the replay result: when present it
//     must parse and state equal live_hash and replay_hash, so diverging
//     hashes fail whether or not G2 is listed. A tape manifest must parse.
//     05_DIFFS is not read here: producers keep placeholders and other
//     artifacts in it, and only G2 makes its files replay differences.
//   - NOT_RUN only when G2 is not declared and the pack carries no
//     determinism manifest. A tape manifest alone states no replay result, so
//     it does not make the check run; it is still parsed, fails if it does not
//     parse, and is named in the reason.
//   - A gates value that is not a list of gate names is malformed input and
//     FAILED: it cannot be read as "G2 is not declared".
//
// It replays nothing: live_hash and replay_hash are the pack's own
// statements, and the tape is not served back.
func checkReplayDeterminism(bundlePath string) CheckResult {
	const name = "replay_determinism"
	declared, undeclared, err := replayGateDeclared(bundlePath)
	if err != nil {
		return failed(name, err.Error())
	}

	tapesDir := filepath.Join(bundlePath, "08_TAPES")
	manifestPath := filepath.Join(tapesDir, "tape_manifest.json")
	detManifestPath := filepath.Join(bundlePath, "02_PROOFGRAPH", "determinism_manifest.json")
	hasTapeManifest := fileExists(manifestPath)
	hasDetManifest := fileExists(detManifestPath)

	// established lists what was read and held.
	var established []string

	switch {
	case hasTapeManifest:
		manifestData, err := os.ReadFile(manifestPath)
		if err != nil {
			return failed(name, fmt.Sprintf("cannot read tape manifest: %v", err))
		}
		var tapeManifest map[string]any
		if err := json.Unmarshal(manifestData, &tapeManifest); err != nil {
			return failed(name, fmt.Sprintf("invalid tape manifest JSON: %v", err))
		}
		entryCount := 0
		if entries, ok := tapeManifest["entries"].([]any); ok {
			entryCount = len(entries)
		}
		established = append(established, fmt.Sprintf("tape_manifest.json parses and lists %d entries (not replayed)", entryCount))
	case !declared:
	case !dirExists(tapesDir):
		return failed(name, "missing 08_TAPES directory — replay evidence required")
	default:
		return failed(name, "missing 08_TAPES/tape_manifest.json — replay evidence required")
	}

	switch {
	case hasDetManifest:
		detManifestData, err := os.ReadFile(detManifestPath)
		if err != nil {
			return failed(name, fmt.Sprintf("cannot read determinism manifest: %v", err))
		}
		var detManifest map[string]any
		if err := json.Unmarshal(detManifestData, &detManifest); err != nil {
			return failed(name, fmt.Sprintf("invalid determinism manifest JSON: %v", err))
		}
		liveHash, liveOK := detManifest["live_hash"].(string)
		replayHash, replayOK := detManifest["replay_hash"].(string)
		if !liveOK || liveHash == "" || !replayOK || replayHash == "" {
			return failed(name, "determinism manifest must declare live_hash and replay_hash")
		}
		if liveHash != replayHash {
			return failed(name, fmt.Sprintf("replay hash divergence: live=%s replay=%s", liveHash, replayHash))
		}
		established = append(established, "determinism_manifest.json states equal live_hash and replay_hash (declared by the pack, not recomputed)")
	case !declared:
		// No replay result to compare. Say what is and is not there, so the
		// reason is true of a pack that carries a tape manifest.
		if !hasTapeManifest {
			return notRun(name, undeclared+", and the pack carries no replay material (no 08_TAPES/tape_manifest.json and no 02_PROOFGRAPH/determinism_manifest.json)")
		}
		return notRun(name, fmt.Sprintf("%s, and the pack carries no 02_PROOFGRAPH/determinism_manifest.json, so it states no replay result to compare; 08_TAPES/%s",
			undeclared, established[0]))
	default:
		return failed(name, "missing 02_PROOFGRAPH/determinism_manifest.json — replay hash proof required")
	}

	if !declared {
		notRead := "05_DIFFS is read as replay differences only under gate G2"
		if !hasTapeManifest {
			notRead = "the pack carries no 08_TAPES/tape_manifest.json; " + notRead
		}
		return verified(name, fmt.Sprintf("gate G2 is not declared; the replay material the pack carries is consistent with itself: %s. Not read: %s",
			strings.Join(established, "; "), notRead))
	}

	diffsDir := filepath.Join(bundlePath, "05_DIFFS")
	if entries, err := os.ReadDir(diffsDir); err == nil && len(entries) > 0 {
		return failed(name, "05_DIFFS contains replay differences")
	}
	established = append(established, "05_DIFFS holds no files")
	return verified(name, "gate G2 evidence is present: "+strings.Join(established, "; "))
}

// replayGateDeclared reports whether 00_INDEX.json declares gate G2, which is
// how a pack states that it carries replay evidence. When it does not, the
// returned text says what the index declares instead. An index that cannot be
// read or parsed declares nothing either way, and neither does a gates value
// that is not a list of gate names: both are errors, not "G2 is not declared".
func replayGateDeclared(bundlePath string) (bool, string, error) {
	indexPath := filepath.Join(bundlePath, "00_INDEX.json")
	if !fileExists(indexPath) {
		return false, "pack has no 00_INDEX.json, so it declares no gates", nil
	}

	data, err := os.ReadFile(indexPath)
	if err != nil {
		return false, "", fmt.Errorf("cannot read the gates 00_INDEX.json declares: %v", err)
	}

	var document map[string]json.RawMessage
	if err := json.Unmarshal(data, &document); err != nil {
		return false, "", fmt.Errorf("cannot parse the gates 00_INDEX.json declares: %v", err)
	}

	raw, present := document["gates"]
	// Producers that hold the gates in a nil list write null.
	if !present || string(bytes.TrimSpace(raw)) == "null" {
		return false, "00_INDEX.json declares no gates", nil
	}
	var gates []string
	if err := json.Unmarshal(raw, &gates); err != nil {
		return false, "", fmt.Errorf("00_INDEX.json gates must be a list of gate names such as [\"G0\",\"G2\"]; it is malformed, so the gates the pack declares cannot be read: %v", err)
	}
	if slices.Contains(gates, "G2") {
		return true, "", nil
	}
	return false, "00_INDEX.json gates do not declare G2", nil
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

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

func dirExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

func receiptPath(bundlePath string) string {
	legacy := filepath.Join(bundlePath, "receipts")
	if dirExists(legacy) {
		return legacy
	}
	return filepath.Join(bundlePath, "02_PROOFGRAPH", "receipts")
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
