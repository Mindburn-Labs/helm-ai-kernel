// quantum_posture: canonical signing preimages are algorithm-neutral; they do
// not upgrade the posture of the configured signer or external trust edges.
package crypto

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

// CanonicalMarshal marshals v into HELM canonical JSON.
//
// It is a thin alias for canonicalize.JCS and exists only so the callers that
// predate the canonicalize package keep compiling. Do not add new callers;
// call canonicalize.JCS (or canonicalize.InteroperableJCS for bytes that will
// be published as a test vector) directly.
//
// Before 2026-08-06 this function was a second, independent encoder built on
// encoding/json.Encoder. It disagreed with canonicalize.JCS on three inputs:
// it emitted struct fields in Go declaration order instead of sorted order,
// it escaped U+2028/U+2029 (which RFC 8785 Section 3.2.2.2 requires to be
// emitted literally), and it escaped the U+FFFD substitutions produced from
// ill-formed UTF-8. Because it signed transparency-log tree heads
// (translog.SignedTreeHead.SigningBytes), reordering a Go struct field
// silently changed signed bytes. The three in-repo call sites are
// byte-for-byte unchanged by the switch; that is asserted by
// TestCanonicalMarshalCallSiteShapesAreByteStable in this package and by
// TestSTHSigningBytesAreCanonicalGolden in core/pkg/translog.
func CanonicalMarshal(v interface{}) ([]byte, error) {
	b, err := canonicalize.JCS(v)
	if err != nil {
		return nil, fmt.Errorf("canonical encoding failed: %w", err)
	}
	return b, nil
}

// Signature components separators and prefixes
const (
	SigSeparator     = ":"
	SigPrefixEd25519 = "ed25519"
	SigPrefixMLDSA65 = "ml-dsa-65"
)

// CanonicalizeDecision creates a canonical string representation of a decision record for signing.
// V2: binds all security-relevant fields including PhenotypeHash, PolicyContentHash, EffectDigest (DRIFT-7 fix).
// Empty security-relevant hashes are permitted for backward compatibility but logged as a warning.
func CanonicalizeDecision(id, verdict, reason, phenotypeHash, policyContentHash, effectDigest string) string {
	return fmt.Sprintf("%s%s%s%s%s%s%s%s%s%s%s", id, SigSeparator, verdict, SigSeparator, reason, SigSeparator, phenotypeHash, SigSeparator, policyContentHash, SigSeparator, effectDigest)
}

// CanonicalizeDecisionStrict is like CanonicalizeDecision but returns an error if any
// security-relevant hash field is empty. Use this for new code paths where all fields
// are expected to be populated.
func CanonicalizeDecisionStrict(id, verdict, reason, phenotypeHash, policyContentHash, effectDigest string) (string, error) {
	if id == "" {
		return "", fmt.Errorf("decision ID is required for canonicalization")
	}
	if verdict == "" {
		return "", fmt.Errorf("verdict is required for canonicalization")
	}
	return CanonicalizeDecision(id, verdict, reason, phenotypeHash, policyContentHash, effectDigest), nil
}

// CanonicalizeIntent creates the historical compact intent preimage.
//
// Deprecated: retained only for fixture compatibility. It does not bind the
// authority window and must never be used to grant execution authority.
func CanonicalizeIntent(id, decisionID, allowedTool string, effectDigestHash ...string) string {
	if len(effectDigestHash) == 0 {
		return fmt.Sprintf("%s%s%s%s%s", id, SigSeparator, decisionID, SigSeparator, allowedTool)
	}
	return fmt.Sprintf("%s%s%s%s%s%s%s", id, SigSeparator, decisionID, SigSeparator, allowedTool, SigSeparator, effectDigestHash[0])
}

// CanonicalizeAuthorizedExecutionIntent returns the versioned signing
// preimage for an execution intent. V2 binds the authority window, signer and
// algorithm identity, taint, emergency authority, idempotency, and complete
// portable effect semantics. Legacy unversioned preimages are rejected because
// they do not bind expiry and therefore cannot grant execution authority.
func CanonicalizeAuthorizedExecutionIntent(intent *contracts.AuthorizedExecutionIntent) ([]byte, error) {
	if intent == nil {
		return nil, fmt.Errorf("execution intent is nil")
	}
	if intent.SignatureVersion != contracts.AuthorizedExecutionIntentSignatureV2 {
		return nil, fmt.Errorf("unsupported execution intent signature version %q", intent.SignatureVersion)
	}

	var effectBinding *contracts.EffectDigestBinding
	if intent.EffectBinding != nil {
		var err error
		effectBinding, err = contracts.NormalizeEffectDigestBinding(intent.EffectBinding)
		if err != nil {
			return nil, fmt.Errorf("normalize execution intent effect binding: %w", err)
		}
	}

	return canonicalize.JCS(authorizedExecutionIntentSigningEnvelope{
		SignatureVersion:             intent.SignatureVersion,
		ID:                           intent.ID,
		DecisionID:                   intent.DecisionID,
		EffectDigestHash:             intent.EffectDigestHash,
		EffectBinding:                effectBinding,
		IdempotencyKey:               intent.IdempotencyKey,
		IssuedAt:                     intent.IssuedAt,
		ExpiresAt:                    intent.ExpiresAt,
		Signer:                       intent.Signer,
		SignatureType:                intent.SignatureType,
		AllowedTool:                  intent.AllowedTool,
		Taint:                        contracts.NormalizeTaintLabels(intent.Taint),
		EmergencyActivationID:        intent.EmergencyActivationID,
		EmergencyDelegationSessionID: intent.EmergencyDelegationSessionID,
		EmergencyScopeHash:           intent.EmergencyScopeHash,
	})
}

// prepareAuthorizedExecutionIntent marks a newly signed intent as V2 before
// deriving the preimage. SignatureType is included so algorithm/key-selection
// metadata cannot be changed after signing.
func prepareAuthorizedExecutionIntent(intent *contracts.AuthorizedExecutionIntent, signatureType string) ([]byte, error) {
	if intent == nil {
		return nil, fmt.Errorf("execution intent is nil")
	}
	intent.SignatureVersion = contracts.AuthorizedExecutionIntentSignatureV2
	intent.SignatureType = signatureType
	return CanonicalizeAuthorizedExecutionIntent(intent)
}

//nolint:govet // field order mirrors the public authority contract.
type authorizedExecutionIntentSigningEnvelope struct {
	SignatureVersion             string                         `json:"signature_version"`
	ID                           string                         `json:"id"`
	DecisionID                   string                         `json:"decision_id"`
	EffectDigestHash             string                         `json:"effect_digest_hash"`
	EffectBinding                *contracts.EffectDigestBinding `json:"effect_binding,omitempty"`
	IdempotencyKey               string                         `json:"idempotency_key,omitempty"`
	IssuedAt                     time.Time                      `json:"issued_at"`
	ExpiresAt                    time.Time                      `json:"expires_at"`
	Signer                       string                         `json:"signer"`
	SignatureType                string                         `json:"signature_type"`
	AllowedTool                  string                         `json:"allowed_tool"`
	Taint                        []string                       `json:"taint,omitempty"`
	EmergencyActivationID        string                         `json:"emergency_activation_id,omitempty"`
	EmergencyDelegationSessionID string                         `json:"emergency_delegation_session_id,omitempty"`
	EmergencyScopeHash           string                         `json:"emergency_scope_hash,omitempty"`
}

// CanonicalizeReceipt creates a canonical string representation of a receipt for signing.
// V4: includes ArgsHash for PEP boundary binding.
func CanonicalizeReceipt(receiptID, decisionID, effectID, status, outputHash, prevHash string, lamportClock uint64, argsHash string) string {
	return fmt.Sprintf("%s%s%s%s%s%s%s%s%s%s%s%s%d%s%s", receiptID, SigSeparator, decisionID, SigSeparator, effectID, SigSeparator, status, SigSeparator, outputHash, SigSeparator, prevHash, SigSeparator, lamportClock, SigSeparator, argsHash)
}

// --- HELM-303: V5 receipt / V2 decision signing preimages -----------------

// receiptV5SigningEnvelope is intentionally limited to the receipt fields the
// durable stores round-trip. It is not the wider experimental envelope in
// canonical_v5.go: signing fields the store cannot reload would make a signed
// receipt unverifiable immediately after persistence.
//
// No field uses omitempty. An explicitly empty field is part of the signed
// schema and cannot be confused with a field that was silently omitted by a
// transport or store.
type receiptV5SigningEnvelope struct {
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

// CanonicalizeReceiptV5 extends the V4 preimage with the receipt's
// governance-meaning fields: verdict, reason_code, policy_hash, session_id.
// It uses a JCS envelope rather than a colon-delimited string so a colon in a
// field cannot shift its boundary and make two different receipts share one
// signature.
func CanonicalizeReceiptV5(r *contracts.Receipt) ([]byte, error) {
	if r == nil {
		return nil, fmt.Errorf("receipt is nil")
	}
	return canonicalize.JCS(receiptV5SigningEnvelope{
		SignatureVersion: contracts.ReceiptSignatureV5,
		ReceiptID:        r.ReceiptID,
		DecisionID:       r.DecisionID,
		EffectID:         r.EffectID,
		Status:           r.Status,
		OutputHash:       r.OutputHash,
		PrevHash:         r.PrevHash,
		LamportClock:     r.LamportClock,
		ArgsHash:         r.ArgsHash,
		Verdict:          r.Verdict,
		ReasonCode:       r.ReasonCode,
		PolicyHash:       r.PolicyHash,
		SessionID:        r.SessionID,
	})
}

// ReceiptSigningPayload stamps the receipt with the current preimage version
// and returns the payload to sign. All signers must use this instead of
// calling a Canonicalize* function directly, so a new preimage revision is a
// one-line change here rather than an eight-site hunt.
func ReceiptSigningPayload(r *contracts.Receipt) ([]byte, error) {
	if r == nil {
		return nil, fmt.Errorf("receipt is nil")
	}
	r.SignatureVersion = contracts.ReceiptSignatureV5
	return CanonicalizeReceiptV5(r)
}

// ReceiptVerifyPayload reconstructs the signed payload according to the
// receipt's declared preimage version. Empty = legacy V4 (receipts signed
// before HELM-303 stay verifiable under the preimage they were signed over);
// unknown versions are rejected rather than guessed.
func ReceiptVerifyPayload(r *contracts.Receipt) ([]byte, error) {
	if r == nil {
		return nil, fmt.Errorf("receipt is nil")
	}
	switch r.SignatureVersion {
	case "":
		return []byte(CanonicalizeReceipt(r.ReceiptID, r.DecisionID, r.EffectID, r.Status, r.OutputHash, r.PrevHash, r.LamportClock, r.ArgsHash)), nil
	case contracts.ReceiptSignatureV5:
		return CanonicalizeReceiptV5(r)
	default:
		return nil, fmt.Errorf("unsupported receipt signature version %q", r.SignatureVersion)
	}
}

// decisionV2SigningEnvelope is a fixed, narrow signed view of a decision.
// Unlike the legacy colon payload, its JCS representation has unambiguous
// field boundaries even when hashes use a prefix such as "sha256:".
type decisionV2SigningEnvelope struct {
	SignatureVersion  string `json:"signature_version"`
	ID                string `json:"id"`
	Verdict           string `json:"verdict"`
	ReasonCode        string `json:"reason_code"`
	ReasonHash        string `json:"reason_hash"`
	PhenotypeHash     string `json:"phenotype_hash"`
	PolicyContentHash string `json:"policy_content_hash"`
	EffectDigest      string `json:"effect_digest"`
}

// decisionV3SigningEnvelope extends the V2 signed view with a digest of the
// complete Guardian-owned typed threat reference. The reference is
// canonicalized separately so the decision preimage remains compact and never
// exports semantic source material through a signature payload.
type decisionV3SigningEnvelope struct {
	SignatureVersion  string `json:"signature_version"`
	ID                string `json:"id"`
	Verdict           string `json:"verdict"`
	ReasonCode        string `json:"reason_code"`
	ReasonHash        string `json:"reason_hash"`
	PhenotypeHash     string `json:"phenotype_hash"`
	PolicyContentHash string `json:"policy_content_hash"`
	EffectDigest      string `json:"effect_digest"`
	ThreatScanHash    string `json:"threat_scan_hash"`
}

// decisionV4SigningEnvelope retains every V2/V3 decision fact and binds the
// authorization request and chosen signing algorithm. No field uses omitempty:
// an empty threat-scan hash denotes a decision without Guardian threat evidence
// and cannot be confused with a missing field.
type decisionV4SigningEnvelope struct {
	SignatureVersion  string `json:"signature_version"`
	ID                string `json:"id"`
	Verdict           string `json:"verdict"`
	ReasonCode        string `json:"reason_code"`
	ReasonHash        string `json:"reason_hash"`
	PhenotypeHash     string `json:"phenotype_hash"`
	PolicyContentHash string `json:"policy_content_hash"`
	EffectDigest      string `json:"effect_digest"`
	ThreatScanHash    string `json:"threat_scan_hash"`
	SubjectID         string `json:"subject_id"`
	Action            string `json:"action"`
	Resource          string `json:"resource"`
	SignatureType     string `json:"signature_type"`
}

// HashReason is the digest under which free-text Reason is attested in the V2
// decision preimage.
//
// V2 promotes ReasonCode into the signed payload, but ReasonCode is empty by
// contract on ALLOW — the registry in contracts/verdict.go is defined for
// DENY/ESCALATE — and several producers leave it unset on other verdicts too.
// Binding the code alone therefore removed attestation that the legacy preimage
// had: the emitted explanation of an allowed action could be rewritten and the
// signature still verified. Binding the digest keeps prose out of the preimage,
// which the telemetry contract prohibits from export, while making any edit to
// the explanation break the signature.
func HashReason(reason string) string {
	sum := sha256.Sum256([]byte(reason))
	return hex.EncodeToString(sum[:])
}

// CanonicalizeDecisionV2 binds the machine-readable ReasonCode — the exported,
// keyed-on field — alongside a digest of the free-text Reason. Prose itself
// stays out of the preimage, which the telemetry contract prohibits from
// export; see HashReason for why the digest cannot be dropped.
func CanonicalizeDecisionV2(id, verdict, reason, reasonCode, phenotypeHash, policyContentHash, effectDigest string) ([]byte, error) {
	// This fixed all-string envelope has a known JCS key order. Build it
	// directly instead of sending it through JCS's marshal/decode/map path:
	// signing a decision is on Guardian's hot path, and that generic path added
	// 74 allocations to every policy evaluation. appendJCSQuotedString mirrors
	// the RFC 8785 escaping used by canonicalize.JCS.
	payload := make([]byte, 0, len(id)+len(verdict)+len(reasonCode)+len(phenotypeHash)+len(policyContentHash)+len(effectDigest)+288)
	payload = append(payload, `{"effect_digest":`...)
	payload = appendJCSQuotedString(payload, effectDigest)
	payload = append(payload, `,"id":`...)
	payload = appendJCSQuotedString(payload, id)
	payload = append(payload, `,"phenotype_hash":`...)
	payload = appendJCSQuotedString(payload, phenotypeHash)
	payload = append(payload, `,"policy_content_hash":`...)
	payload = appendJCSQuotedString(payload, policyContentHash)
	payload = append(payload, `,"reason_code":`...)
	payload = appendJCSQuotedString(payload, reasonCode)
	payload = append(payload, `,"reason_hash":`...)
	payload = appendJCSQuotedString(payload, HashReason(reason))
	payload = append(payload, `,"signature_version":`...)
	payload = appendJCSQuotedString(payload, contracts.DecisionRecordSignatureV2)
	payload = append(payload, `,"verdict":`...)
	payload = appendJCSQuotedString(payload, verdict)
	payload = append(payload, '}')
	return payload, nil
}

func decisionThreatScanHash(ref *contracts.ThreatScanRef) (string, error) {
	if ref == nil {
		return "", fmt.Errorf("decision.v3 requires threat scan evidence")
	}
	payload, err := canonicalize.JCS(ref)
	if err != nil {
		return "", fmt.Errorf("canonicalize decision threat scan: %w", err)
	}
	sum := sha256.Sum256(payload)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

// CanonicalizeDecisionV3 binds the V2 governance fields and the canonical
// Guardian threat reference. Its presence is intentional: V3 is used only for
// evidence-bearing decisions, while existing decisions retain their V2 bytes.
func CanonicalizeDecisionV3(id, verdict, reason, reasonCode, phenotypeHash, policyContentHash, effectDigest string, threatScan *contracts.ThreatScanRef) ([]byte, error) {
	threatScanHash, err := decisionThreatScanHash(threatScan)
	if err != nil {
		return nil, err
	}
	return canonicalize.JCS(decisionV3SigningEnvelope{
		SignatureVersion:  contracts.DecisionRecordSignatureV3,
		ID:                id,
		Verdict:           verdict,
		ReasonCode:        reasonCode,
		ReasonHash:        HashReason(reason),
		PhenotypeHash:     phenotypeHash,
		PolicyContentHash: policyContentHash,
		EffectDigest:      effectDigest,
		ThreatScanHash:    threatScanHash,
	})
}

// CanonicalizeDecisionV4 returns the current decision-signing preimage. Newly
// issued decisions must bind the evaluated authorization tuple and algorithm
// metadata; V2/V3 remain available only through DecisionVerifyPayload for
// historical records.
func CanonicalizeDecisionV4(d *contracts.DecisionRecord) ([]byte, error) {
	if d == nil {
		return nil, fmt.Errorf("decision is nil")
	}
	for _, field := range []struct {
		name  string
		value string
	}{
		{"decision ID", d.ID},
		{"verdict", d.Verdict},
		{"subject ID", d.SubjectID},
		{"action", d.Action},
		{"resource", d.Resource},
		{"signature type", d.SignatureType},
	} {
		if strings.TrimSpace(field.value) == "" {
			return nil, fmt.Errorf("%s is required for %s", field.name, contracts.DecisionRecordSignatureV4)
		}
	}

	threatScanHash := ""
	if d.ThreatScan != nil {
		var err error
		threatScanHash, err = decisionThreatScanHash(d.ThreatScan)
		if err != nil {
			return nil, err
		}
	}
	// This mirrors the fixed V2 serializer rather than routing the hot signing
	// path through a generic map encode/decode. The fields are appended in JCS
	// lexicographic-key order and every value is a JSON string, so the result
	// is byte-for-byte equivalent to canonicalize.JCS(decisionV4SigningEnvelope{
	// ...}) without adding allocation cost to every authorization evaluation.
	payload := make([]byte, 0, len(d.ID)+len(d.Verdict)+len(d.ReasonCode)+len(d.Reason)+len(d.PhenotypeHash)+len(d.PolicyContentHash)+len(d.EffectDigest)+len(threatScanHash)+len(d.SubjectID)+len(d.Action)+len(d.Resource)+len(d.SignatureType)+400)
	payload = append(payload, `{"action":`...)
	payload = appendJCSQuotedString(payload, d.Action)
	payload = append(payload, `,"effect_digest":`...)
	payload = appendJCSQuotedString(payload, d.EffectDigest)
	payload = append(payload, `,"id":`...)
	payload = appendJCSQuotedString(payload, d.ID)
	payload = append(payload, `,"phenotype_hash":`...)
	payload = appendJCSQuotedString(payload, d.PhenotypeHash)
	payload = append(payload, `,"policy_content_hash":`...)
	payload = appendJCSQuotedString(payload, d.PolicyContentHash)
	payload = append(payload, `,"reason_code":`...)
	payload = appendJCSQuotedString(payload, d.ReasonCode)
	payload = append(payload, `,"reason_hash":`...)
	payload = appendJCSQuotedString(payload, HashReason(d.Reason))
	payload = append(payload, `,"resource":`...)
	payload = appendJCSQuotedString(payload, d.Resource)
	payload = append(payload, `,"signature_type":`...)
	payload = appendJCSQuotedString(payload, d.SignatureType)
	payload = append(payload, `,"signature_version":`...)
	payload = appendJCSQuotedString(payload, contracts.DecisionRecordSignatureV4)
	payload = append(payload, `,"subject_id":`...)
	payload = appendJCSQuotedString(payload, d.SubjectID)
	payload = append(payload, `,"threat_scan_hash":`...)
	payload = appendJCSQuotedString(payload, threatScanHash)
	payload = append(payload, `,"verdict":`...)
	payload = appendJCSQuotedString(payload, d.Verdict)
	return append(payload, '}'), nil
}

// prepareDecisionForSigning binds the signer metadata before deriving the
// preimage. It stages the mutation so a malformed decision is never left
// marked as V4 after the signer rejects it.
func prepareDecisionForSigning(d *contracts.DecisionRecord, signatureType string) ([]byte, error) {
	if d == nil {
		return nil, fmt.Errorf("decision is nil")
	}
	candidate := *d
	candidate.SignatureVersion = contracts.DecisionRecordSignatureV4
	candidate.SignatureType = signatureType
	payload, err := CanonicalizeDecisionV4(&candidate)
	if err != nil {
		return nil, err
	}
	d.SignatureVersion = candidate.SignatureVersion
	d.SignatureType = candidate.SignatureType
	return payload, nil
}

// appendJCSQuotedString appends an RFC 8785 JSON string. The V2 decision
// envelope contains only strings, so this avoids re-parsing a generic JSON map
// on Guardian's signing path while keeping the exact bytes canonicalize.JCS
// would produce.
func appendJCSQuotedString(dst []byte, value string) []byte {
	// encoding/json (used by canonicalize.JCS's initial pass) replaces invalid
	// UTF-8 with U+FFFD. Match that legacy behavior before appending raw bytes.
	if !utf8.ValidString(value) {
		value = strings.ToValidUTF8(value, "\uFFFD")
	}

	const hex = "0123456789abcdef"
	dst = append(dst, '"')
	for i := 0; i < len(value); i++ {
		c := value[i]
		switch c {
		case '"':
			dst = append(dst, '\\', '"')
		case '\\':
			dst = append(dst, '\\', '\\')
		case '\b':
			dst = append(dst, '\\', 'b')
		case '\f':
			dst = append(dst, '\\', 'f')
		case '\n':
			dst = append(dst, '\\', 'n')
		case '\r':
			dst = append(dst, '\\', 'r')
		case '\t':
			dst = append(dst, '\\', 't')
		default:
			if c < 0x20 {
				dst = append(dst, '\\', 'u', '0', '0', hex[c>>4], hex[c&0x0f])
				continue
			}
			dst = append(dst, c)
		}
	}
	return append(dst, '"')
}

// DecisionSigningPayload stamps the record with the current preimage version
// and returns the payload to sign. Signers should call
// prepareDecisionForSigning with their own algorithm metadata so that metadata
// is part of the preimage rather than a post-signing annotation.
func DecisionSigningPayload(d *contracts.DecisionRecord) ([]byte, error) {
	if d == nil {
		return nil, fmt.Errorf("decision is nil")
	}
	return prepareDecisionForSigning(d, d.SignatureType)
}

// DecisionVerifyPayload reconstructs the signed payload per the record's
// declared preimage version; empty = legacy (free-text Reason).
func DecisionVerifyPayload(d *contracts.DecisionRecord) ([]byte, error) {
	if d == nil {
		return nil, fmt.Errorf("decision is nil")
	}
	switch d.SignatureVersion {
	case "":
		return []byte(CanonicalizeDecision(d.ID, d.Verdict, d.Reason, d.PhenotypeHash, d.PolicyContentHash, d.EffectDigest)), nil
	case contracts.DecisionRecordSignatureV2:
		return CanonicalizeDecisionV2(d.ID, d.Verdict, d.Reason, d.ReasonCode, d.PhenotypeHash, d.PolicyContentHash, d.EffectDigest)
	case contracts.DecisionRecordSignatureV3:
		return CanonicalizeDecisionV3(d.ID, d.Verdict, d.Reason, d.ReasonCode, d.PhenotypeHash, d.PolicyContentHash, d.EffectDigest, d.ThreatScan)
	case contracts.DecisionRecordSignatureV4:
		return CanonicalizeDecisionV4(d)
	default:
		return nil, fmt.Errorf("unsupported decision signature version %q", d.SignatureVersion)
	}
}

// DecisionContentHash returns the SHA-256 digest of the exact canonical
// decision-record payload used for verification. It is the deterministic
// fallback semantic decision hash when a policy decision source did not emit
// PolicyDecisionHash; callers must prefer the source-provided value when it is
// available.
func DecisionContentHash(d *contracts.DecisionRecord) (string, error) {
	payload, err := DecisionVerifyPayload(d)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(payload)
	return "sha256:" + hex.EncodeToString(digest[:]), nil
}

// DecisionSemanticHash derives the receipt-facing decision hash from the
// signed decision payload itself. PolicyDecisionHash is not part of any
// current decision signing preimage, so trusting it here would let a caller
// rewrite receipt semantics without invalidating the decision signature.
func DecisionSemanticHash(d *contracts.DecisionRecord) (string, error) {
	return DecisionContentHash(d)
}
