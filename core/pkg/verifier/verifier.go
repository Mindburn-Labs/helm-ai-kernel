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
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	evidencepkg "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/evidence"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/verifier/externalreceipt"
)

// VerifyReport is the structured output of offline verification.
// Designed for auditor consumption — every field is evidence-grade.
type VerifyReport struct {
	Bundle              string                                    `json:"bundle"`
	Verified            bool                                      `json:"verified"`
	Timestamp           time.Time                                 `json:"timestamp"`
	Roots               VerifyRoots                               `json:"roots,omitempty"`
	Checks              []CheckResult                             `json:"checks"`
	Summary             string                                    `json:"summary"`
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
	Name   string `json:"name"`
	Pass   bool   `json:"pass"`
	Detail string `json:"detail,omitempty"`
	Reason string `json:"reason,omitempty"` // failure reason
}

const VerifierVersion = "0.2.0"

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

// VerifyBundleWithOptions performs offline verification with an explicit trust profile.
func VerifyBundleWithOptions(bundlePath string, opts VerifyOptions) (*VerifyReport, error) {
	report := &VerifyReport{
		Bundle:      bundlePath,
		Verified:    true,
		Timestamp:   time.Now().UTC(),
		Checks:      make([]CheckResult, 0),
		VerifierVer: VerifierVersion,
	}

	// 1. Structure check
	report.addCheck(checkStructure(bundlePath))

	// 2. Index integrity
	report.addCheck(checkIndex(bundlePath))
	roots, err := computeIndexRoots(bundlePath)
	if err != nil {
		report.addCheck(CheckResult{Name: "roots", Pass: false, Reason: err.Error()})
	} else if roots.ManifestRootHash != "" {
		report.Roots = roots
		report.MerkleRoot = roots.MerkleRoot
		report.addCheck(CheckResult{
			Name:   "roots",
			Pass:   true,
			Detail: fmt.Sprintf("%d indexed entries; manifest_root_hash=%s; merkle_root=%s", roots.EntryCount, roots.ManifestRootHash, roots.MerkleRoot),
		})
	}

	// 3. Native EvidencePack seal.
	report.addCheck(checkEvidencePackSeal(bundlePath, report, opts))

	// 4. File hash integrity
	report.addChecks(checkFileHashes(bundlePath))

	// 4b. Optional EU AI Act profile integrity. Absence remains valid for
	// legacy EvidencePacks; presence must be complete and redaction-safe.
	report.addCheck(checkEUAIActEvidenceProfile(bundlePath))

	// 4c. Optional external connector evidence integrity. Absence remains valid
	// for legacy EvidencePacks; presence must bind production proof fields.
	report.addCheck(checkConnectorEvidence(bundlePath))

	// 5. Chain integrity (receipt ordering)
	report.addCheck(checkChainIntegrity(bundlePath))

	// 6. Lamport monotonicity
	report.addCheck(checkLamportMonotonicity(bundlePath))

	// 7. Policy decision hashes
	report.addCheck(checkPolicyDecisionHashes(bundlePath))

	// 8. Replay determinism verdict
	report.addCheck(checkReplayDeterminism(bundlePath))

	// 9. Optional external host evidence verification.
	hostEvidence := externalreceipt.VerifyBundleWithOptions(bundlePath, externalreceipt.VerifyOptions{PublicKeyHex: opts.ExternalHostKeyHex})
	if hostEvidence.Found {
		for _, check := range hostEvidence.Checks {
			report.addCheck(CheckResult{
				Name:   check.Name,
				Pass:   check.Pass,
				Detail: check.Detail,
				Reason: check.Reason,
			})
		}
	}
	report.addCheck(checkEmbeddedSignatureTrust(bundlePath, opts))

	enrichReportMetadata(bundlePath, report, opts)

	// Compute summary
	failed := 0
	for _, c := range report.Checks {
		if !c.Pass {
			failed++
		}
	}
	report.IssueCount = failed
	if failed > 0 {
		report.Verified = false
		report.Summary = fmt.Sprintf("FAIL: %d/%d checks failed", failed, len(report.Checks))
	} else {
		report.Summary = fmt.Sprintf("PASS: %d/%d checks passed", len(report.Checks), len(report.Checks))
	}

	return report, nil
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
		return CheckResult{
			Name:   "evidence_pack_seal",
			Pass:   true,
			Detail: fmt.Sprintf("seal valid; trust=%s; anchor=%s; storage=%s", seal.TrustLevel, seal.AnchorStatus, seal.StorageStatus),
		}
	}
	reason := strings.Join(seal.Errors, "; ")
	if reason == "" {
		reason = "native EvidencePack seal is invalid"
	}
	return CheckResult{Name: "evidence_pack_seal", Pass: false, Reason: reason}
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
	valid, total := countEmbeddedSignatures(bundlePath, opts)
	if total == 0 {
		return CheckResult{Name: "embedded_signature_trust", Pass: true, Detail: "no embedded receipt or witness signatures require verification"}
	}
	if valid == total {
		return CheckResult{
			Name:   "embedded_signature_trust",
			Pass:   true,
			Detail: fmt.Sprintf("%d embedded receipt or witness signatures verified against configured trust roots", valid),
		}
	}
	return CheckResult{
		Name:   "embedded_signature_trust",
		Pass:   false,
		Reason: fmt.Sprintf("%d/%d embedded receipt or witness signatures require a configured verifier; none are trusted by presence alone", total-valid, total),
	}
}

func countEmbeddedSignatures(bundlePath string, opts VerifyOptions) (int, int) {
	valid := 0
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
			var document map[string]any
			if json.Unmarshal(data, &document) != nil {
				return nil
			}
			if sig, ok := document["signature"].(string); ok && sig != "" {
				total++
				if verifyEmbeddedDocumentSignature(document, sig, opts) {
					valid++
				}
			}
			if witnesses, ok := document["witness_signatures"].([]any); ok {
				for _, witness := range witnesses {
					item, ok := witness.(map[string]any)
					if !ok {
						continue
					}
					sig, ok := item["signature"].(string)
					if !ok || sig == "" {
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
					if verifyWitnessReceiptSignature(document, sig, keyHex) {
						valid++
					}
				}
			}
			return nil
		})
	}
	return valid, total
}

func verifyEmbeddedDocumentSignature(document map[string]any, sig string, opts VerifyOptions) bool {
	switch firstString(document, "receipt_version") {
	case "managed_agent_live_scenario_receipt.v1":
		if firstString(document, "signature_payload") != "decision_hash" {
			return false
		}
		return verifyManagedAgentEd25519Signature(document, sig, opts.ManagedAgentReceiptPublicKeyHex, firstString(document, "decision_hash"))
	case "managed_agent_execution_receipt.v1":
		return verifyManagedAgentEd25519Signature(document, sig, opts.ManagedAgentReceiptPublicKeyHex, firstString(document, "receipt_hash"))
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
				return false
			}
		}
		switch class {
		case mcpPolicyDecisionClass:
			return verifyMCPPolicyDecisionReceiptSignature(document, sig, opts)
		case mcpGovernedEffectClass:
			return verifyMCPGovernedEffectReceiptSignature(document, sig, opts)
		default:
			return false
		}
	}
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
		lamportValue := firstUint(document, "lamport_clock")
		if lamportValue == nil {
			return false
		}
		var err error
		payload, err = canonicalize.JCS(receiptV5DocumentEnvelope{
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

func (r *VerifyReport) addCheck(c CheckResult) {
	r.Checks = append(r.Checks, c)
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

	return CheckResult{Name: "structure", Pass: true, Detail: "bundle structure valid"}
}

func checkIndex(bundlePath string) CheckResult {
	indexPath := filepath.Join(bundlePath, "00_INDEX.json")
	if !fileExists(indexPath) {
		// Try manifest.json as alternative
		manifestPath := filepath.Join(bundlePath, "manifest.json")
		if !fileExists(manifestPath) {
			return CheckResult{Name: "index_integrity", Pass: true, Detail: "no index file (legacy bundle)"}
		}
		data, err := os.ReadFile(manifestPath)
		if err != nil {
			return CheckResult{Name: "index_integrity", Pass: false, Reason: fmt.Sprintf("cannot read manifest: %v", err)}
		}
		var manifest map[string]any
		if err := json.Unmarshal(data, &manifest); err != nil {
			return CheckResult{Name: "index_integrity", Pass: false, Reason: fmt.Sprintf("invalid manifest JSON: %v", err)}
		}
		return CheckResult{Name: "index_integrity", Pass: true, Detail: "manifest.json valid JSON"}
	}

	data, err := os.ReadFile(indexPath)
	if err != nil {
		return CheckResult{Name: "index_integrity", Pass: false, Reason: fmt.Sprintf("cannot read index: %v", err)}
	}
	var index indexFile
	if err := json.Unmarshal(data, &index); err != nil {
		return CheckResult{Name: "index_integrity", Pass: false, Reason: fmt.Sprintf("invalid index JSON: %v", err)}
	}
	for _, entry := range index.Entries {
		if entry.Path == "" {
			return CheckResult{Name: "index_integrity", Pass: false, Reason: "index entry path is required"}
		}
		clean := filepath.Clean(entry.Path)
		if filepath.IsAbs(clean) || strings.HasPrefix(clean, "..") {
			return CheckResult{Name: "index_integrity", Pass: false, Reason: fmt.Sprintf("index entry escapes bundle: %s", entry.Path)}
		}
		data, err := os.ReadFile(filepath.Join(bundlePath, clean))
		if err != nil {
			return CheckResult{Name: "index_integrity", Pass: false, Reason: fmt.Sprintf("indexed file missing %s: %v", entry.Path, err)}
		}
		if actual := sha256Hex(data); actual != entry.SHA256 {
			return CheckResult{Name: "index_integrity", Pass: false, Reason: fmt.Sprintf("indexed hash mismatch for %s: expected %s, got %s", entry.Path, entry.SHA256, actual)}
		}
	}
	return CheckResult{Name: "index_integrity", Pass: true, Detail: "00_INDEX.json entries verified"}
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
		if err := json.Unmarshal(data, &manifest); err != nil || manifest.FileHashes == nil {
			return []CheckResult{{Name: "file_hashes", Pass: true, Detail: "no file hashes in manifest"}}
		}

		// Sort keys for deterministic output
		keys := make([]string, 0, len(manifest.FileHashes))
		for k := range manifest.FileHashes {
			keys = append(keys, k)
		}
		sort.Strings(keys)

		for _, name := range keys {
			expectedHash := manifest.FileHashes[name]
			filePath := filepath.Join(bundlePath, name)
			content, err := os.ReadFile(filePath)
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
					Detail: "hash verified",
				})
			}
		}
	}

	if len(results) == 0 {
		results = append(results, CheckResult{Name: "file_hashes", Pass: true, Detail: "no hash manifest (legacy bundle)"})
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
		return CheckResult{Name: "connector_evidence", Pass: true, Detail: "no connector evidence record"}
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
	return CheckResult{Name: "connector_evidence", Pass: true, Detail: fmt.Sprintf("%d connector evidence records verified", len(records))}
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

		// ExecutorID is the session key the typed producer chains on; receipts
		// without one form a single implicit chain.
		session := receipt.ExecutorID
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

// unchainedPackResult describes a pack that makes no chaining claim.
func unchainedPackResult(checkName, receiptsDir string) CheckResult {
	entries, _ := os.ReadDir(receiptsDir)
	n := 0
	for _, e := range entries {
		if !e.IsDir() && filepath.Ext(e.Name()) == ".json" {
			n++
		}
	}
	return CheckResult{
		Name: checkName, Pass: true,
		Detail: fmt.Sprintf("%d receipts carry no prev_hash — this pack asserts no chain of custody, "+
			"so none was verified", n),
	}
}

func checkPolicyDecisionHashes(bundlePath string) CheckResult {
	// Verify that decision records expose a signed policy binding. Legacy
	// receipts use decision_hash. Current MCP proof receipts use the signed
	// EffectID, OutputHash (complete authorization evaluation), and ArgsHash
	// (raw authorization inputs), avoiding an unsigned compatibility field.
	receiptsDir := receiptPath(bundlePath)
	if !dirExists(receiptsDir) {
		// Already caught by lamport check, but note here too
		return CheckResult{Name: "policy_decision_hashes", Pass: false, Reason: "no receipts directory (checked receipts/ and 02_PROOFGRAPH/receipts/) — cannot verify decision hashes"}
	}

	entries, err := os.ReadDir(receiptsDir)
	if err != nil || len(entries) == 0 {
		return CheckResult{Name: "policy_decision_hashes", Pass: false, Reason: "no receipt files to verify decision hashes"}
	}

	// Structural check: parse each receipt and verify either the legacy field or
	// the current signed MCP policy-receipt binding exists.
	legacyVerified := 0
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
		if firstString(receipt, "decision_hash") != "" {
			legacyVerified++
		}
	}

	if mcpPolicyTotal > 0 {
		if mcpPolicyTotal != mcpPolicyVerified {
			return CheckResult{Name: "policy_decision_hashes", Pass: false, Reason: fmt.Sprintf("%d/%d MCP policy receipts lack signed authorization bindings", mcpPolicyTotal-mcpPolicyVerified, mcpPolicyTotal)}
		}
		return CheckResult{Name: "policy_decision_hashes", Pass: true, Detail: fmt.Sprintf("%d MCP policy receipts with signed authorization bindings", mcpPolicyVerified)}
	}

	if legacyVerified == 0 {
		return CheckResult{Name: "policy_decision_hashes", Pass: false, Reason: "no receipts contain a policy decision binding"}
	}

	return CheckResult{Name: "policy_decision_hashes", Pass: true, Detail: fmt.Sprintf("%d receipts with legacy decision hashes", legacyVerified)}
}

func checkReplayDeterminism(bundlePath string) CheckResult {
	required, detail := replayDeterminismRequired(bundlePath)
	if !required {
		return CheckResult{Name: "replay_determinism", Pass: true, Detail: detail}
	}

	tapesDir := filepath.Join(bundlePath, "08_TAPES")
	if !dirExists(tapesDir) {
		return CheckResult{Name: "replay_determinism", Pass: false, Reason: "missing 08_TAPES directory — replay evidence required"}
	}

	manifestPath := filepath.Join(tapesDir, "tape_manifest.json")
	if !fileExists(manifestPath) {
		return CheckResult{Name: "replay_determinism", Pass: false, Reason: "missing 08_TAPES/tape_manifest.json — replay evidence required"}
	}

	manifestData, err := os.ReadFile(manifestPath)
	if err != nil {
		return CheckResult{Name: "replay_determinism", Pass: false, Reason: fmt.Sprintf("cannot read tape manifest: %v", err)}
	}
	var tapeManifest map[string]any
	if err := json.Unmarshal(manifestData, &tapeManifest); err != nil {
		return CheckResult{Name: "replay_determinism", Pass: false, Reason: fmt.Sprintf("invalid tape manifest JSON: %v", err)}
	}

	detManifestPath := filepath.Join(bundlePath, "02_PROOFGRAPH", "determinism_manifest.json")
	if !fileExists(detManifestPath) {
		return CheckResult{Name: "replay_determinism", Pass: false, Reason: "missing 02_PROOFGRAPH/determinism_manifest.json — replay hash proof required"}
	}
	detManifestData, err := os.ReadFile(detManifestPath)
	if err != nil {
		return CheckResult{Name: "replay_determinism", Pass: false, Reason: fmt.Sprintf("cannot read determinism manifest: %v", err)}
	}
	var detManifest map[string]any
	if err := json.Unmarshal(detManifestData, &detManifest); err != nil {
		return CheckResult{Name: "replay_determinism", Pass: false, Reason: fmt.Sprintf("invalid determinism manifest JSON: %v", err)}
	}

	liveHash, liveOK := detManifest["live_hash"].(string)
	replayHash, replayOK := detManifest["replay_hash"].(string)
	if !liveOK || liveHash == "" || !replayOK || replayHash == "" {
		return CheckResult{Name: "replay_determinism", Pass: false, Reason: "determinism manifest must declare live_hash and replay_hash"}
	}
	if liveHash != replayHash {
		return CheckResult{Name: "replay_determinism", Pass: false, Reason: fmt.Sprintf("replay hash divergence: live=%s replay=%s", liveHash, replayHash)}
	}

	diffsDir := filepath.Join(bundlePath, "05_DIFFS")
	if entries, err := os.ReadDir(diffsDir); err == nil && len(entries) > 0 {
		return CheckResult{Name: "replay_determinism", Pass: false, Reason: "05_DIFFS contains replay differences"}
	}

	entryCount := 0
	if entries, ok := tapeManifest["entries"].([]any); ok {
		entryCount = len(entries)
	}

	return CheckResult{
		Name:   "replay_determinism",
		Pass:   true,
		Detail: fmt.Sprintf("replay evidence verified: tape_manifest.json present, determinism hashes match, tape entries=%d", entryCount),
	}
}

func replayDeterminismRequired(bundlePath string) (bool, string) {
	indexPath := filepath.Join(bundlePath, "00_INDEX.json")
	if !fileExists(indexPath) {
		return false, "n/a: 00_INDEX.json missing; index integrity handles bundle validity"
	}

	data, err := os.ReadFile(indexPath)
	if err != nil {
		return false, "n/a: cannot read 00_INDEX.json gate scope"
	}

	var document map[string]any
	if err := json.Unmarshal(data, &document); err != nil {
		return false, "n/a: invalid 00_INDEX.json gate scope"
	}

	gates, ok := document["gates"].([]any)
	if !ok {
		return false, "n/a: 00_INDEX.json has no gates declaration"
	}

	for _, gate := range gates {
		if value, ok := gate.(string); ok && value == "G2" {
			return true, "replay evidence required by 00_INDEX.json gates"
		}
	}

	return false, "n/a: 00_INDEX.json gates omit G2 replay determinism"
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
