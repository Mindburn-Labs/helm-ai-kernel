package networkproof

// quantum_posture: Presentation parsing validates the classical proof envelope shape.

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"time"
	"unicode/utf8"
)

func preflightRequest(request VerificationRequest) error {
	if len(request.Scope) == 0 || len(request.Scope) > maxSetItems || len(request.Audience) == 0 || len(request.Audience) > maxSetItems {
		return errors.New("request set cardinality invalid")
	}
	if !validActorType(request.ActorType) ||
		!bounded(request.RequestID, maxIdentifierRunes) || !bounded(request.ChallengeID, maxIdentifierRunes) ||
		!bounded(request.SubjectID, maxIdentifierRunes) || !bounded(string(request.ActorType), maxIdentifierRunes) ||
		!bounded(request.ClaimID, maxIdentifierRunes) || !bounded(request.Predicate, maxPurposeRunes) ||
		!bounded(request.ValueDigest, maxIdentifierRunes) || !cheapStrings(request.Scope, maxIdentifierRunes) ||
		!cheapStrings(request.Audience, maxIdentifierRunes) || !bounded(request.Nonce, maxPurposeRunes) ||
		!bounded(request.Purpose, maxPurposeRunes) || !bounded(request.TransactionID, maxIdentifierRunes) ||
		!bounded(request.SchemaID, maxIdentifierRunes) || !bounded(request.SchemaVersion, maxIdentifierRunes) ||
		!bounded(request.DisclosureDigest, maxIdentifierRunes) || !bounded(request.ExpectedProfileDigest, maxIdentifierRunes) {
		return errors.New("request field bounds invalid")
	}
	return nil
}

func validateRequest(request VerificationRequest, profile AssuranceProfile, profileDigest string) error {
	for _, value := range []string{
		request.RequestID, request.ChallengeID, request.SubjectID, string(request.ActorType), request.ClaimID,
		request.Predicate, request.ValueDigest, request.Nonce, request.Purpose, request.TransactionID,
		request.SchemaID, request.SchemaVersion, request.DisclosureDigest, request.ExpectedProfileDigest,
	} {
		if !bounded(value, maxPurposeRunes) {
			return errors.New("required request binding is missing or too long")
		}
	}
	if request.ExpectedProfileDigest != profileDigest || !slices.Contains(profile.AllowedActorTypes, request.ActorType) || profile.HolderBinding != HolderBindingSubjectKeyV1 {
		return errors.New("request assurance profile or actor type mismatch")
	}
	if len(request.Nonce) < 32 || !validSHA256(request.ValueDigest) || !validSHA256(request.DisclosureDigest) ||
		validateExactSet(request.Scope, maxSetItems, true) != nil || validateAudience(request.Audience) != nil {
		return errors.New("invalid request digest, scope, audience, or nonce")
	}
	return nil
}

func preflightPresentation(presentation *Presentation) error {
	if presentation == nil || len(presentation.Context) != 2 || len(presentation.Type) != 2 || len(presentation.Credentials) != 1 ||
		len(presentation.Audience) == 0 || len(presentation.Audience) > maxSetItems {
		return errors.New("presentation cardinality invalid")
	}
	if !cheapStrings(presentation.Context, maxIdentifierRunes) || !cheapStrings(presentation.Type, maxIdentifierRunes) ||
		!cheapStrings(presentation.Audience, maxIdentifierRunes) || !bounded(presentation.ID, maxIdentifierRunes) ||
		!bounded(presentation.Holder, maxIdentifierRunes) || !bounded(presentation.Nonce, maxPurposeRunes) ||
		!bounded(presentation.Purpose, maxPurposeRunes) || !bounded(presentation.TransactionID, maxIdentifierRunes) ||
		!cheapProof(presentation.Proof) {
		return errors.New("presentation field bounds invalid")
	}
	credential := &presentation.Credentials[0]
	if len(credential.Context) != 2 || len(credential.Type) != 2 || len(credential.CredentialSubject.Scope) == 0 ||
		len(credential.CredentialSubject.Scope) > maxSetItems || len(credential.CredentialSubject.Audience) == 0 ||
		len(credential.CredentialSubject.Audience) > maxSetItems || len(credential.Evidence) == 0 || len(credential.Evidence) > maxEvidenceItems ||
		!cheapStrings(credential.Context, maxIdentifierRunes) || !cheapStrings(credential.Type, maxIdentifierRunes) ||
		!cheapStrings(credential.CredentialSubject.Scope, maxIdentifierRunes) || !cheapStrings(credential.CredentialSubject.Audience, maxIdentifierRunes) ||
		!bounded(credential.ID, maxIdentifierRunes) || !bounded(credential.SchemaID, maxIdentifierRunes) ||
		!bounded(credential.SchemaVersion, maxIdentifierRunes) || !bounded(credential.Issuer, maxIdentifierRunes) ||
		!bounded(credential.CredentialSubject.ID, maxIdentifierRunes) || !bounded(string(credential.CredentialSubject.ActorType), maxIdentifierRunes) ||
		!bounded(credential.CredentialSubject.ClaimID, maxIdentifierRunes) || !bounded(credential.CredentialSubject.Predicate, maxIdentifierRunes) ||
		!bounded(credential.CredentialSubject.ValueDigest, maxIdentifierRunes) || !bounded(credential.CredentialSubject.Purpose, maxPurposeRunes) ||
		!bounded(credential.CredentialStatus.ID, maxIdentifierRunes) || !bounded(credential.CredentialStatus.Type, maxIdentifierRunes) ||
		!cheapProof(credential.Proof) {
		return errors.New("credential field bounds invalid")
	}
	for _, evidence := range credential.Evidence {
		if !bounded(evidence.ID, maxIdentifierRunes) || !bounded(evidence.Kind, maxIdentifierRunes) || !bounded(evidence.Digest, maxIdentifierRunes) {
			return errors.New("evidence field bounds invalid")
		}
	}
	return nil
}

func validatePresentationEnvelope(request VerificationRequest, presentation *Presentation, profile AssuranceProfile, now time.Time) error {
	if !equalOrdered(presentation.Context, []string{ContextW3CCredentials, ContextNetworkClaim}) ||
		!equalSet(presentation.Type, []string{TypeVerifiablePresentation, TypeNetworkClaimPresentation}) {
		return codedError("presentation_schema_invalid")
	}
	if !bounded(presentation.ID, maxIdentifierRunes) || presentation.Holder != request.SubjectID || presentation.Nonce != request.Nonce ||
		presentation.Purpose != request.Purpose || presentation.TransactionID != request.TransactionID || !equalSet(presentation.Audience, request.Audience) {
		return codedError("presentation_binding_mismatch")
	}
	if presentation.IssuedAt.IsZero() || presentation.IssuedAt.After(now.Add(profile.ClockSkew)) ||
		now.Sub(presentation.IssuedAt) > profile.MaxPresentationAge+profile.ClockSkew {
		return codedError("presentation_expired")
	}
	if presentation.Proof == nil || presentation.Proof.Type != ProofTypeHELMJCS2026 || presentation.Proof.ProofPurpose != ProofPurposeAuthentication ||
		!slices.Contains(profile.AllowedPresentationProofs, presentation.Proof.Type) || presentation.Proof.Created.Before(presentation.IssuedAt) ||
		presentation.Proof.Created.After(presentation.IssuedAt.Add(profile.ClockSkew)) || presentation.Proof.Created.After(now.Add(profile.ClockSkew)) ||
		!validProofValue(presentation.Proof.ProofValue) {
		return codedError("presentation_proof_invalid")
	}
	return nil
}

// validateReplayEnvelope rechecks the request envelope only after the exact
// full presentation artifact digest has matched the signed stored decision.
// Historical trust and expiry are appraised separately and are intentionally
// not re-evaluated here.
func validateReplayEnvelope(request VerificationRequest, presentation *Presentation, credential *Credential, receipt *VerificationReceipt) error {
	if presentation == nil || credential == nil || receipt == nil ||
		!equalOrdered(presentation.Context, []string{ContextW3CCredentials, ContextNetworkClaim}) ||
		!equalSet(presentation.Type, []string{TypeVerifiablePresentation, TypeNetworkClaimPresentation}) ||
		presentation.Holder != request.SubjectID || presentation.Nonce != request.Nonce || presentation.Purpose != request.Purpose ||
		presentation.TransactionID != request.TransactionID || !equalSet(presentation.Audience, request.Audience) ||
		presentation.Proof == nil || presentation.Proof.Type != ProofTypeHELMJCS2026 ||
		presentation.Proof.ProofPurpose != ProofPurposeAuthentication || presentation.Proof.VerificationMethod != receipt.HolderKeyID ||
		!validProofValue(presentation.Proof.ProofValue) {
		return ErrChallengeConflict
	}
	subject := credential.CredentialSubject
	if !equalOrdered(credential.Context, []string{ContextW3CCredentials, ContextNetworkClaim}) ||
		!equalSet(credential.Type, []string{TypeVerifiableCredential, TypeNetworkClaimCredential}) ||
		credential.SchemaID != request.SchemaID || credential.SchemaVersion != request.SchemaVersion ||
		credential.Proof == nil || credential.Proof.VerificationMethod != receipt.IssuerKeyID ||
		subject.ID != request.SubjectID || subject.ActorType != request.ActorType || subject.ClaimID != request.ClaimID ||
		subject.Predicate != request.Predicate || subject.ValueDigest != request.ValueDigest || subject.Purpose != request.Purpose ||
		!equalSet(subject.Scope, request.Scope) || !equalSet(subject.Audience, request.Audience) || presentation.Holder != subject.ID {
		return ErrChallengeConflict
	}
	return nil
}

func validateCredentialEnvelope(request VerificationRequest, presentation *Presentation, credential *Credential, profile AssuranceProfile, now time.Time) (VerificationStatus, string) {
	if !equalOrdered(credential.Context, []string{ContextW3CCredentials, ContextNetworkClaim}) ||
		!equalSet(credential.Type, []string{TypeVerifiableCredential, TypeNetworkClaimCredential}) ||
		credential.SchemaID != request.SchemaID || credential.SchemaVersion != request.SchemaVersion {
		return StatusInvalid, "credential_schema_invalid"
	}
	if !bounded(credential.ID, maxIdentifierRunes) || !bounded(credential.Issuer, maxIdentifierRunes) || credential.ValidUntil.IsZero() ||
		credential.ValidFrom.IsZero() || !credential.ValidFrom.Before(credential.ValidUntil) {
		return StatusInvalid, "credential_lifetime_invalid"
	}
	if now.Add(profile.ClockSkew).Before(credential.ValidFrom) {
		return StatusInvalid, "credential_not_yet_valid"
	}
	if !now.Before(credential.ValidUntil) {
		return StatusExpired, "credential_expired"
	}
	subject := credential.CredentialSubject
	if subject.IssuedAt.IsZero() || credential.Proof == nil || subject.IssuedAt.Before(credential.ValidFrom.Add(-profile.ClockSkew)) ||
		subject.IssuedAt.After(credential.Proof.Created) || credential.Proof.Created.After(subject.IssuedAt.Add(profile.ClockSkew)) ||
		subject.IssuedAt.After(now.Add(profile.ClockSkew)) || credential.Proof.Created.After(now.Add(profile.ClockSkew)) ||
		!subject.IssuedAt.Before(credential.ValidUntil) || !credential.Proof.Created.Before(credential.ValidUntil) {
		return StatusInvalid, "credential_time_invalid"
	}
	if now.Sub(subject.IssuedAt) > profile.MaxCredentialAge+profile.ClockSkew ||
		now.Sub(credential.ValidFrom) > profile.MaxCredentialAge+profile.ClockSkew ||
		now.Sub(credential.Proof.Created) > profile.MaxCredentialAge+profile.ClockSkew {
		return StatusExpired, "credential_stale"
	}
	if subject.ID != request.SubjectID || subject.ActorType != request.ActorType || subject.ClaimID != request.ClaimID ||
		subject.Predicate != request.Predicate || subject.ValueDigest != request.ValueDigest || subject.Purpose != request.Purpose ||
		!equalSet(subject.Scope, request.Scope) || !equalSet(subject.Audience, request.Audience) || presentation.Holder != subject.ID {
		return StatusInvalid, "credential_binding_mismatch"
	}
	if validateExactSet(subject.Scope, maxSetItems, true) != nil || validateAudience(subject.Audience) != nil || !validSHA256(subject.ValueDigest) {
		return StatusInvalid, "credential_claim_invalid"
	}
	if !bounded(credential.CredentialStatus.ID, maxIdentifierRunes) || !bounded(credential.CredentialStatus.Type, maxIdentifierRunes) ||
		len(credential.Evidence) == 0 || len(credential.Evidence) > maxEvidenceItems {
		return StatusInvalid, "credential_dependencies_invalid"
	}
	seen := make(map[string]struct{}, len(credential.Evidence))
	for _, evidence := range credential.Evidence {
		if !bounded(evidence.ID, maxIdentifierRunes) || !bounded(evidence.Kind, maxIdentifierRunes) || !validSHA256(evidence.Digest) {
			return StatusInvalid, "credential_evidence_invalid"
		}
		if _, ok := seen[evidence.ID]; ok {
			return StatusInvalid, "credential_evidence_duplicate"
		}
		seen[evidence.ID] = struct{}{}
	}
	if credential.Proof.Type != ProofTypeHELMJCS2026 || !slices.Contains(profile.AllowedCredentialProofs, credential.Proof.Type) ||
		credential.Proof.ProofPurpose != ProofPurposeAssertion || !validProofValue(credential.Proof.ProofValue) {
		return StatusInvalid, "credential_proof_invalid"
	}
	return StatusVerified, ""
}

func validateChallenge(challenge Challenge, request VerificationRequest, requestBinding string, now time.Time, hasDecision bool) error {
	if challenge.ID != request.ChallengeID || challenge.RequestBindingDigest != requestBinding || challenge.ProfileDigest != request.ExpectedProfileDigest ||
		challenge.NonceDigest != digestString(request.Nonce) || challenge.TransactionID != request.TransactionID || !equalSet(challenge.Audience, request.Audience) ||
		!bounded(challenge.Generation, maxIdentifierRunes) || challenge.IssuedAt.IsZero() || challenge.ExpiresAt.IsZero() || !challenge.IssuedAt.Before(challenge.ExpiresAt) {
		return ErrChallengeConflict
	}
	if !hasDecision && (!now.Before(challenge.ExpiresAt) || now.Before(challenge.IssuedAt)) {
		return errors.New("networkproof: challenge is not active")
	}
	return nil
}

// ParsePresentationJSON is the strict transport helper: bounded input,
// duplicate-member/depth rejection, unknown-field rejection, and no trailing
// JSON. Callers should use it instead of json.Unmarshal at the trust boundary.
func ParsePresentationJSON(data []byte) (*Presentation, error) {
	if len(data) == 0 || len(data) > maxCanonicalBytes {
		return nil, errors.New("networkproof: presentation JSON size invalid")
	}
	if err := validateJSONShape(data); err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var presentation Presentation
	if err := decoder.Decode(&presentation); err != nil {
		return nil, fmt.Errorf("networkproof: decoding presentation: %w", err)
	}
	if err := expectJSONEOF(decoder); err != nil {
		return nil, err
	}
	if err := preflightPresentation(&presentation); err != nil {
		return nil, err
	}
	return &presentation, nil
}

func validateJSONShape(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := walkJSONValue(decoder, 0); err != nil {
		return err
	}
	return expectJSONEOF(decoder)
}

func walkJSONValue(decoder *json.Decoder, depth int) error {
	if depth > maxJSONDepth {
		return errors.New("networkproof: presentation JSON nesting too deep")
	}
	token, err := decoder.Token()
	if err != nil {
		return fmt.Errorf("networkproof: invalid presentation JSON: %w", err)
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delimiter {
	case '{':
		seen := map[string]struct{}{}
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("networkproof: JSON object key is not a string")
			}
			if _, duplicate := seen[key]; duplicate {
				return fmt.Errorf("networkproof: duplicate JSON member %q", key)
			}
			seen[key] = struct{}{}
			if err := walkJSONValue(decoder, depth+1); err != nil {
				return err
			}
		}
		_, err = decoder.Token()
		return err
	case '[':
		for decoder.More() {
			if err := walkJSONValue(decoder, depth+1); err != nil {
				return err
			}
		}
		_, err = decoder.Token()
		return err
	default:
		return errors.New("networkproof: unexpected JSON delimiter")
	}
}

func expectJSONEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("networkproof: trailing JSON value")
		}
		return fmt.Errorf("networkproof: trailing JSON: %w", err)
	}
	return nil
}

func cloneRequest(request VerificationRequest) VerificationRequest {
	request.Scope = append([]string(nil), request.Scope...)
	request.Audience = append([]string(nil), request.Audience...)
	return request
}

func clonePresentation(presentation *Presentation) *Presentation {
	if presentation == nil {
		return nil
	}
	copy := *presentation
	copy.Context = append([]string(nil), presentation.Context...)
	copy.Type = append([]string(nil), presentation.Type...)
	copy.Audience = append([]string(nil), presentation.Audience...)
	if presentation.Proof != nil {
		proof := *presentation.Proof
		copy.Proof = &proof
	}
	copy.Credentials = make([]Credential, len(presentation.Credentials))
	for i := range presentation.Credentials {
		copy.Credentials[i] = *cloneCredential(&presentation.Credentials[i])
	}
	return &copy
}

func cloneCredential(credential *Credential) *Credential {
	if credential == nil {
		return nil
	}
	copy := *credential
	copy.Context = append([]string(nil), credential.Context...)
	copy.Type = append([]string(nil), credential.Type...)
	copy.CredentialSubject.Scope = append([]string(nil), credential.CredentialSubject.Scope...)
	copy.CredentialSubject.Audience = append([]string(nil), credential.CredentialSubject.Audience...)
	copy.Evidence = append([]EvidenceReference(nil), credential.Evidence...)
	if credential.Proof != nil {
		proof := *credential.Proof
		copy.Proof = &proof
	}
	return &copy
}

func cheapString(value string, maxRunes int) bool {
	return value != "" && len(value) <= maxRunes*utf8.UTFMax && utf8.ValidString(value) && utf8.RuneCountInString(value) <= maxRunes
}

func cheapStrings(values []string, maxRunes int) bool {
	for _, value := range values {
		if !cheapString(value, maxRunes) {
			return false
		}
	}
	return true
}

func cheapProof(proof *Proof) bool {
	return proof != nil && bounded(proof.Type, maxIdentifierRunes) && bounded(proof.VerificationMethod, maxIdentifierRunes) &&
		bounded(proof.ProofPurpose, maxIdentifierRunes) && len(proof.ProofValue) <= 128 && utf8.ValidString(proof.ProofValue)
}

func validProofValue(value string) bool {
	if len(value) != 128 || value != strings.ToLower(value) {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}
