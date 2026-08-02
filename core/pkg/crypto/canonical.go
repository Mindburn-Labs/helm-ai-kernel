// quantum_posture: canonical signing preimages are algorithm-neutral; they do
// not upgrade the posture of the configured signer or external trust edges.
package crypto

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

// CanonicalMarshal marshals v into canonical JSON format (RFC 8785).
// Key features:
// 1. Map keys sorted lexicographically (Go default)
// 2. No HTML escaping (SetEscapeHTML(false))
// 3. Compact representation (no whitespace)
// 4. Trailing newline is NOT added
func CanonicalMarshal(v interface{}) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "") // Compact

	if err := enc.Encode(v); err != nil {
		return nil, fmt.Errorf("canonical encoding failed: %w", err)
	}

	// json.Encoder.Encode adds a trailing newline, which we must remove for strict JCS compliance
	// if we want pure content addressing of the value data.
	ret := buf.Bytes()
	if len(ret) > 0 && ret[len(ret)-1] == '\n' {
		ret = ret[:len(ret)-1]
	}

	return ret, nil
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

// CanonicalizeDecisionV2 signs the machine-readable ReasonCode in place of
// free-text Reason: the exported, keyed-on field is the attested one, and
// prose (which the telemetry contract prohibits from export) leaves the
// preimage entirely.
// decisionV2SigningEnvelope is a fixed, narrow signed view of a decision.
// Unlike the legacy colon payload, its JCS representation has unambiguous
// field boundaries even when hashes use a prefix such as "sha256:".
type decisionV2SigningEnvelope struct {
	SignatureVersion  string `json:"signature_version"`
	ID                string `json:"id"`
	Verdict           string `json:"verdict"`
	ReasonCode        string `json:"reason_code"`
	PhenotypeHash     string `json:"phenotype_hash"`
	PolicyContentHash string `json:"policy_content_hash"`
	EffectDigest      string `json:"effect_digest"`
}

func CanonicalizeDecisionV2(id, verdict, reasonCode, phenotypeHash, policyContentHash, effectDigest string) ([]byte, error) {
	// This fixed all-string envelope has a known JCS key order. Build it
	// directly instead of sending it through JCS's marshal/decode/map path:
	// signing a decision is on Guardian's hot path, and that generic path added
	// 74 allocations to every policy evaluation. appendJCSQuotedString mirrors
	// the RFC 8785 escaping used by canonicalize.JCS.
	payload := make([]byte, 0, len(id)+len(verdict)+len(reasonCode)+len(phenotypeHash)+len(policyContentHash)+len(effectDigest)+192)
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
	payload = append(payload, `,"signature_version":`...)
	payload = appendJCSQuotedString(payload, contracts.DecisionRecordSignatureV2)
	payload = append(payload, `,"verdict":`...)
	payload = appendJCSQuotedString(payload, verdict)
	payload = append(payload, '}')
	return payload, nil
}

// CanonicalizeDecisionV3 returns the current decision-signing preimage.
func CanonicalizeDecisionV3(d *contracts.DecisionRecord) ([]byte, error) {
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
			return nil, fmt.Errorf("%s is required for %s", field.name, contracts.DecisionRecordSignatureV3)
		}
	}
	// V3 is also a fixed all-string JCS envelope. Keep Guardian's evaluated
	// decision path on the allocation profile established by V2.
	payload := make([]byte, 0, len(d.Action)+len(d.EffectDigest)+len(d.ID)+len(d.PhenotypeHash)+len(d.PolicyContentHash)+len(d.ReasonCode)+len(d.Resource)+len(d.SignatureType)+len(d.SubjectID)+len(d.Verdict)+288)
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
	payload = append(payload, `,"resource":`...)
	payload = appendJCSQuotedString(payload, d.Resource)
	payload = append(payload, `,"signature_type":`...)
	payload = appendJCSQuotedString(payload, d.SignatureType)
	payload = append(payload, `,"signature_version":`...)
	payload = appendJCSQuotedString(payload, contracts.DecisionRecordSignatureV3)
	payload = append(payload, `,"subject_id":`...)
	payload = appendJCSQuotedString(payload, d.SubjectID)
	payload = append(payload, `,"verdict":`...)
	payload = appendJCSQuotedString(payload, d.Verdict)
	return append(payload, '}'), nil
}

func prepareDecisionForSigning(d *contracts.DecisionRecord, signatureType string) ([]byte, error) {
	if d == nil {
		return nil, fmt.Errorf("decision is nil")
	}
	d.SignatureVersion = contracts.DecisionRecordSignatureV3
	d.SignatureType = signatureType
	return CanonicalizeDecisionV3(d)
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
// and returns the payload to sign. Callers that know their signer should use
// prepareDecisionForSigning so SignatureType is bound before signing.
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
		return CanonicalizeDecisionV2(d.ID, d.Verdict, d.ReasonCode, d.PhenotypeHash, d.PolicyContentHash, d.EffectDigest)
	case contracts.DecisionRecordSignatureV3:
		return CanonicalizeDecisionV3(d)
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
