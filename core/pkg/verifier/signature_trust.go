package verifier

// quantum_posture: embedded receipt and witness signature checks use classical Ed25519.

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	evidencepkg "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/evidence"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/receiptverify"
)

func checkEmbeddedSignatureTrust(bundlePath string, opts VerifyOptions) CheckResult {
	valid, selfAttested, notChecked, tooDeep, total := countEmbeddedSignatureTrust(bundlePath, opts)
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
	// A file refused for its depth was not read, so it is not counted as a
	// signature in the reason.
	signatures := total - tooDeep
	reason := fmt.Sprintf("%d/%d embedded receipt or witness signatures require a configured verifier; none are trusted by presence alone", signatures-valid, signatures)
	if notChecked > 0 {
		reason = fmt.Sprintf("%d/%d embedded receipt or witness signatures were not verified, %d of them not checked: no signature_version. "+
			"--allow-legacy-v4-receipts checks a dev-local MCP proof receipt that has none against the legacy V4 preimage; pass it only for a pack known to predate receipt.v5",
			signatures-valid, signatures, notChecked)
	}
	if tooDeep > 0 {
		refused := fmt.Sprintf("%d file(s) refused unread: %v", tooDeep, receiptverify.ErrJSONTooDeep)
		if signatures == valid {
			reason = refused
		} else {
			reason += "; " + refused
		}
	}
	return CheckResult{
		Name:   "embedded_signature_trust",
		Pass:   false,
		Reason: reason,
	}
}

func countEmbeddedSignatures(bundlePath string, opts VerifyOptions) (int, int) {
	valid, _, _, _, total := countEmbeddedSignatureTrust(bundlePath, opts)
	return valid, total
}

// countEmbeddedSignatureTrust returns how many embedded signatures verified,
// how many of those verified only against a key carried in the pack, how many
// were left unchecked for want of a signature_version (legacyReceiptNotChecked),
// how many files were refused unread for their depth, and the total that
// required verification, those files included.
func countEmbeddedSignatureTrust(bundlePath string, opts VerifyOptions) (int, int, int, int, int) {
	valid := 0
	selfAttested := 0
	notChecked := 0
	tooDeep := 0
	total := 0
	pack := openPack(bundlePath)
	defer pack.close()
	receipts, _ := receiptDir(pack)
	for _, dir := range []string{receipts, "07_ATTESTATIONS"} {
		if has, _ := pack.hasDir(dir); !has {
			continue
		}
		// A file that cannot be read safely is skipped here; the chain checks
		// and the seal fail a pack that holds one.
		_ = pack.walk(dir, func(path string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() || filepath.Ext(path) != ".json" {
				return nil
			}
			data, readErr := pack.readFile(path)
			if readErr != nil {
				return nil
			}
			document, parseErr := receiptverify.ParseReceiptDocument(data)
			if document == nil {
				// A file refused for its depth was not read; skipping it would
				// pass a receipt no check looked at.
				if errors.Is(parseErr, receiptverify.ErrJSONTooDeep) {
					tooDeep++
					total++
				}
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
					} else if legacyReceiptNotChecked(document, opts) {
						notChecked++
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
	return valid, selfAttested, notChecked, tooDeep, total
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
		if legacyV4ReceiptRefused(document, opts) {
			return false, false
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

// legacyV4ReceiptRefused reports whether document is a receipt with no
// signature_version that this verification must not check.
//
// The dev-local MCP branches verify such a receipt against the legacy V4
// preimage under a key the pack itself carries. That preimage is eight fields
// joined with ":" with no escaping, so the signed bytes of a receipt.v5
// receipt can be read back as those eight fields: its signature, with the
// real key beside it, verified here for an unversioned receipt that says
// something else. The legacy preimage is therefore used only under
// VerifyOptions.AllowLegacyV4Receipts, and never for a receipt_id that begins
// with "{": the preimage begins with receipt_id, and a replayed versioned
// payload is JSON text, which a receipt id the kernel issued never is.
func legacyV4ReceiptRefused(document map[string]any, opts VerifyOptions) bool {
	if firstString(document, "signature_version") != "" {
		return false
	}
	return !opts.AllowLegacyV4Receipts || strings.HasPrefix(firstString(document, "receipt_id"), "{")
}

// legacyReceiptNotChecked reports whether verifyEmbeddedDocumentSignature
// left document unchecked under legacyV4ReceiptRefused because it has no
// signature_version and the legacy opt-in is off. Managed-agent receipts have
// no signature_version and are checked on their own branch.
func legacyReceiptNotChecked(document map[string]any, opts VerifyOptions) bool {
	switch firstString(document, "receipt_version") {
	case "managed_agent_live_scenario_receipt.v1", "managed_agent_execution_receipt.v1":
		return false
	}
	return !opts.AllowLegacyV4Receipts && legacyV4ReceiptRefused(document, opts)
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
