package networkproof

// quantum_posture: Verification receipts are signed and verified with classical Ed25519.

import (
	"errors"
	"fmt"
	"sort"
	"time"
)

func (v *Verifier) baseReceipt(request VerificationRequest, presentation *Presentation) *VerificationReceipt {
	presentationID := ""
	if presentation != nil {
		presentationID = presentation.ID
	}
	return &VerificationReceipt{
		SchemaVersion: ReceiptSchemaV1, RequestID: request.RequestID, ChallengeID: request.ChallengeID,
		ChallengeGeneration: ChallengeGenerationUnresolved,
		PresentationID:      presentationID, CredentialSchemaID: request.SchemaID, CredentialSchemaVersion: request.SchemaVersion,
		SubjectID: request.SubjectID, ActorType: request.ActorType, ClaimID: request.ClaimID, Predicate: request.Predicate,
		ValueDigest: request.ValueDigest, Scope: cloneSorted(request.Scope), Audience: cloneSorted(request.Audience),
		NonceDigest: digestString(request.Nonce), Purpose: request.Purpose, TransactionID: request.TransactionID,
		DisclosureDigest: request.DisclosureDigest, AssuranceProfileID: v.profile.ID,
		AssuranceProfileVersion: v.profile.Version, AssuranceProfileDigest: v.profileDigest,
		VerifierVersion: v.profile.VerifierVersion, Dependencies: []ReceiptDependency{},
		ProofGraphRoots: []ArtifactReference{}, EvidencePackRoots: []ArtifactReference{},
		SignerKeyID: v.signerKeyID, SignatureAlgorithm: v.signerAlgorithm,
	}
}

func (v *Verifier) addDependency(receipt *VerificationReceipt, kind, subject string, state TrustState, attestation DependencyAttestation) {
	receipt.Dependencies = append(receipt.Dependencies, ReceiptDependency{Kind: kind, Subject: subject, State: state, Attestation: attestation})
}

func (v *Verifier) signReceipt(receipt *VerificationReceipt) (*VerificationReceipt, error) {
	if !bounded(receipt.ReceiptID, maxIdentifierRunes) {
		return nil, errors.New("networkproof: receipt ID generator returned an invalid identifier")
	}
	sortReceiptDependencies(receipt.Dependencies)
	sortArtifactReferences(receipt.ProofGraphRoots)
	sortArtifactReferences(receipt.EvidencePackRoots)
	digest, err := dependencySnapshotDigest(receipt.Dependencies)
	if err != nil {
		return nil, err
	}
	receipt.DependencySnapshotDigest = digest
	if err := validateReceiptSchema(receipt); err != nil {
		return nil, fmt.Errorf("networkproof: refusing to sign an invalid receipt: %w", err)
	}
	bytes, err := ReceiptSigningBytes(receipt)
	if err != nil {
		return nil, fmt.Errorf("networkproof: canonicalizing verification receipt: %w", err)
	}
	if len(bytes) > maxCanonicalBytes {
		return nil, errors.New("networkproof: verification receipt exceeds canonical size limit")
	}
	signature, err := v.deps.Signer.Sign(bytes)
	if err != nil {
		return nil, fmt.Errorf("networkproof: signing verification receipt: %w", err)
	}
	receipt.Signature = signature
	if err := VerifyReceiptSignature(receipt, v.signerPublicKey); err != nil {
		return nil, fmt.Errorf("networkproof: receipt signer self-verification failed: %w", err)
	}
	return cloneReceipt(receipt), nil
}

func (v *Verifier) validateStoredDecision(requestBinding, decisionInput, credentialDigest, presentationDigest string, receipt *VerificationReceipt) error {
	if receipt == nil || receipt.RequestBindingDigest != requestBinding || receipt.DecisionInputDigest != decisionInput ||
		receipt.CanonicalCredentialDigest != credentialDigest || receipt.CanonicalPresentationDigest != presentationDigest {
		return ErrChallengeConflict
	}
	if receipt.SignerKeyID != v.signerKeyID {
		return errors.New("networkproof: stored decision signer differs from verifier signer")
	}
	if err := VerifyReceiptSignature(receipt, v.signerPublicKey); err != nil {
		return fmt.Errorf("networkproof: stored decision failed signature verification: %w", err)
	}
	return nil
}

func ReceiptSigningBytes(receipt *VerificationReceipt) ([]byte, error) {
	if receipt == nil {
		return nil, errors.New("networkproof: nil receipt")
	}
	copy := *cloneReceipt(receipt)
	copy.Signature = ""
	canonical, err := canonicalJCS(&copy)
	if err != nil {
		return nil, err
	}
	if len(canonical) > maxCanonicalBytes {
		return nil, errors.New("networkproof: canonical receipt exceeds size limit")
	}
	return domainSeparated(receiptDomain, canonical), nil
}

// VerifyReceiptSignature verifies historical schema and signature integrity
// against a supplied key. It is deliberately not current trust appraisal and
// never authorizes a rendered VERIFIED mark.
func VerifyReceiptSignature(receipt *VerificationReceipt, publicKey []byte) error {
	if err := validateReceiptSchema(receipt); err != nil {
		return err
	}
	if len(publicKey) != 32 || receipt.SignatureAlgorithm != AlgorithmEd25519 || !validProofValue(receipt.Signature) {
		return errors.New("networkproof: invalid receipt signature metadata")
	}
	bytes, err := ReceiptSigningBytes(receipt)
	if err != nil {
		return err
	}
	if !verifyEd25519(publicKey, receipt.Signature, bytes) {
		return errors.New("networkproof: invalid receipt signature")
	}
	return nil
}

func validateReceiptSchema(receipt *VerificationReceipt) error {
	if receipt == nil || receipt.SchemaVersion != ReceiptSchemaV1 || !bounded(receipt.ReceiptID, maxIdentifierRunes) ||
		!bounded(receipt.RequestID, maxIdentifierRunes) || !bounded(receipt.ChallengeID, maxIdentifierRunes) ||
		!bounded(receipt.ChallengeGeneration, maxIdentifierRunes) || !validSHA256(receipt.RequestBindingDigest) ||
		!bounded(receipt.SubjectID, maxIdentifierRunes) || !validActorType(receipt.ActorType) || !bounded(receipt.ClaimID, maxIdentifierRunes) ||
		!bounded(receipt.Predicate, maxPurposeRunes) || !bounded(receipt.ValueDigest, maxIdentifierRunes) ||
		!receiptStringsCanonical(receipt.Scope, maxSetItems) || !receiptStringsCanonical(receipt.Audience, maxSetItems) ||
		!validSHA256(receipt.NonceDigest) || !bounded(receipt.Purpose, maxPurposeRunes) ||
		!bounded(receipt.TransactionID, maxIdentifierRunes) || !bounded(receipt.DisclosureDigest, maxIdentifierRunes) ||
		!bounded(receipt.AssuranceProfileID, maxIdentifierRunes) || !bounded(receipt.AssuranceProfileVersion, maxIdentifierRunes) ||
		!validSHA256(receipt.AssuranceProfileDigest) || !bounded(receipt.VerifierVersion, maxIdentifierRunes) || receipt.EvaluatedAt.IsZero() ||
		!validVerificationStatus(receipt.DecisionStatusAtEvaluation) || !bounded(receipt.ReasonCode, maxIdentifierRunes) ||
		!bounded(receipt.PresentationID, maxIdentifierRunes) || !bounded(receipt.CredentialSchemaID, maxIdentifierRunes) ||
		!bounded(receipt.CredentialSchemaVersion, maxIdentifierRunes) || !optionalBounded(receipt.CredentialID, maxIdentifierRunes) ||
		!optionalBounded(receipt.Issuer, maxIdentifierRunes) || !optionalBounded(receipt.IssuerKeyID, maxIdentifierRunes) ||
		!optionalBounded(receipt.Holder, maxIdentifierRunes) || !optionalBounded(receipt.HolderKeyID, maxIdentifierRunes) ||
		!optionalSHA256(receipt.DecisionInputDigest) || !optionalSHA256(receipt.CanonicalPresentationDigest) ||
		!optionalSHA256(receipt.CanonicalCredentialDigest) || !optionalSHA256(receipt.CredentialSchemaDigest) ||
		!bounded(receipt.SignerKeyID, maxIdentifierRunes) || !validSHA256(receipt.DependencySnapshotDigest) {
		return errors.New("networkproof: invalid receipt schema")
	}
	if len(receipt.Dependencies) > maxReceiptDeps || len(receipt.ProofGraphRoots) > maxEvidenceItems ||
		len(receipt.EvidencePackRoots) > maxEvidenceItems || !receiptDependenciesCanonical(receipt.Dependencies) ||
		!artifactReferencesCanonical(receipt.ProofGraphRoots) || !artifactReferencesCanonical(receipt.EvidencePackRoots) {
		return errors.New("networkproof: receipt dependency or root ordering invalid")
	}
	digest, err := dependencySnapshotDigest(receipt.Dependencies)
	if err != nil || digest != receipt.DependencySnapshotDigest {
		return errors.New("networkproof: receipt dependency snapshot mismatch")
	}
	if receipt.DecisionStatusAtEvaluation == StatusVerified {
		if receipt.ChallengeGeneration == ChallengeGenerationUnresolved || !validSHA256(receipt.ValueDigest) ||
			!validSHA256(receipt.DisclosureDigest) || validateExactSet(receipt.Scope, maxSetItems, true) != nil ||
			validateAudience(receipt.Audience) != nil || !validSHA256(receipt.DecisionInputDigest) || !validSHA256(receipt.CanonicalPresentationDigest) ||
			!validSHA256(receipt.CanonicalCredentialDigest) || !validSHA256(receipt.CredentialSchemaDigest) ||
			!bounded(receipt.PresentationID, maxIdentifierRunes) || !bounded(receipt.Issuer, maxIdentifierRunes) ||
			!bounded(receipt.IssuerKeyID, maxIdentifierRunes) || !bounded(receipt.Holder, maxIdentifierRunes) ||
			!bounded(receipt.HolderKeyID, maxIdentifierRunes) || receipt.ReasonCode != "verified_exact_claim" ||
			!bounded(receipt.CredentialID, maxIdentifierRunes) || !bounded(receipt.CredentialSchemaID, maxIdentifierRunes) ||
			!bounded(receipt.CredentialSchemaVersion, maxIdentifierRunes) || receipt.FreshUntil.IsZero() ||
			!receipt.EvaluatedAt.Before(receipt.FreshUntil) ||
			len(receipt.Dependencies) < 6 || len(receipt.ProofGraphRoots) == 0 || len(receipt.EvidencePackRoots) == 0 {
			return errors.New("networkproof: verified receipt lacks exact evidence bindings")
		}
	}
	seenDependencies := make(map[[2]string]struct{}, len(receipt.Dependencies))
	requiredDependencies := map[string]int{
		"holder_key": 0, "claim_schema": 0, "issuer_authority": 0,
		"issuer_key": 0, "credential_status": 0, "evidence": 0,
	}
	for _, dependency := range receipt.Dependencies {
		if !bounded(dependency.Kind, maxIdentifierRunes) || !bounded(dependency.Subject, maxIdentifierRunes) || !validTrustState(dependency.State) ||
			!validAttestationShape(dependency.Attestation) {
			return errors.New("networkproof: invalid receipt dependency")
		}
		key := [2]string{dependency.Kind, dependency.Subject}
		if _, duplicate := seenDependencies[key]; duplicate {
			return errors.New("networkproof: duplicate receipt dependency")
		}
		seenDependencies[key] = struct{}{}
		if _, required := requiredDependencies[dependency.Kind]; required {
			requiredDependencies[dependency.Kind]++
		} else if receipt.DecisionStatusAtEvaluation == StatusVerified {
			return errors.New("networkproof: verified receipt contains an unknown dependency class")
		}
		if receipt.DecisionStatusAtEvaluation == StatusVerified {
			switch dependency.Kind {
			case "holder_key":
				if dependency.Subject != receipt.HolderKeyID {
					return errors.New("networkproof: holder dependency subject mismatch")
				}
			case "issuer_key":
				if dependency.Subject != receipt.IssuerKeyID {
					return errors.New("networkproof: issuer-key dependency subject mismatch")
				}
			case "issuer_authority":
				if dependency.Subject != receipt.Issuer {
					return errors.New("networkproof: issuer-authority dependency subject mismatch")
				}
			case "claim_schema":
				if dependency.Subject != receipt.CredentialSchemaID+"@"+receipt.CredentialSchemaVersion {
					return errors.New("networkproof: claim-schema dependency subject mismatch")
				}
			}
		}
		if receipt.DecisionStatusAtEvaluation == StatusVerified &&
			(dependency.State != TrustActive || dependency.Attestation.CheckedAt.After(receipt.EvaluatedAt) ||
				!receipt.EvaluatedAt.Before(dependency.Attestation.ExpiresAt) || receipt.FreshUntil.After(dependency.Attestation.ExpiresAt)) {
			return errors.New("networkproof: verified receipt dependency was not active and fresh at evaluation")
		}
	}
	if receipt.DecisionStatusAtEvaluation == StatusVerified {
		for kind, count := range requiredDependencies {
			if count == 0 || (kind != "evidence" && count != 1) {
				return errors.New("networkproof: verified receipt lacks a required dependency class")
			}
		}
	}
	for _, refs := range [][]ArtifactReference{receipt.ProofGraphRoots, receipt.EvidencePackRoots} {
		seenRoots := make(map[string]struct{}, len(refs))
		for _, reference := range refs {
			if !validArtifactReference(reference) {
				return errors.New("networkproof: invalid receipt evidence root")
			}
			if _, duplicate := seenRoots[reference.ID]; duplicate {
				return errors.New("networkproof: duplicate receipt evidence root")
			}
			seenRoots[reference.ID] = struct{}{}
		}
	}
	return nil
}

func cloneReceipt(receipt *VerificationReceipt) *VerificationReceipt {
	if receipt == nil {
		return nil
	}
	copy := *receipt
	copy.Scope = append([]string(nil), receipt.Scope...)
	copy.Audience = append([]string(nil), receipt.Audience...)
	copy.Dependencies = append([]ReceiptDependency(nil), receipt.Dependencies...)
	copy.ProofGraphRoots = append([]ArtifactReference(nil), receipt.ProofGraphRoots...)
	copy.EvidencePackRoots = append([]ArtifactReference(nil), receipt.EvidencePackRoots...)
	return &copy
}

func validVerificationStatus(status VerificationStatus) bool {
	switch status {
	case StatusPending, StatusVerified, StatusExpired, StatusRevoked, StatusDisputed, StatusInvalid, StatusUnknown:
		return true
	default:
		return false
	}
}

func validTrustState(state TrustState) bool {
	switch state {
	case TrustActive, TrustRevoked, TrustDisputed, TrustQuarantined, TrustCompromised, TrustUnknown:
		return true
	default:
		return false
	}
}

func validArtifactReference(reference ArtifactReference) bool {
	return bounded(reference.ID, maxIdentifierRunes) && validSHA256(reference.Digest)
}

func appendUniqueArtifact(values []ArtifactReference, value ArtifactReference) []ArtifactReference {
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
}

func sortArtifactReferences(values []ArtifactReference) {
	sort.Slice(values, func(i, j int) bool {
		if values[i].ID == values[j].ID {
			return values[i].Digest < values[j].Digest
		}
		return values[i].ID < values[j].ID
	})
}

func sortReceiptDependencies(values []ReceiptDependency) {
	sort.Slice(values, func(i, j int) bool {
		if values[i].Kind == values[j].Kind {
			return values[i].Subject < values[j].Subject
		}
		return values[i].Kind < values[j].Kind
	})
}

func receiptDependenciesCanonical(values []ReceiptDependency) bool {
	for i := 1; i < len(values); i++ {
		previous, current := values[i-1], values[i]
		if current.Kind < previous.Kind || (current.Kind == previous.Kind && current.Subject < previous.Subject) {
			return false
		}
	}
	return true
}

func receiptStringsCanonical(values []string, maxItems int) bool {
	if len(values) == 0 || len(values) > maxItems || !cheapStrings(values, maxIdentifierRunes) {
		return false
	}
	for i := 1; i < len(values); i++ {
		if values[i] < values[i-1] {
			return false
		}
	}
	return true
}

func optionalBounded(value string, maxRunes int) bool {
	return value == "" || bounded(value, maxRunes)
}

func optionalSHA256(value string) bool {
	return value == "" || validSHA256(value)
}

func artifactReferencesCanonical(values []ArtifactReference) bool {
	for i := 1; i < len(values); i++ {
		previous, current := values[i-1], values[i]
		if current.ID < previous.ID || (current.ID == previous.ID && current.Digest < previous.Digest) {
			return false
		}
	}
	return true
}

func minimumFreshUntil(presentation *Presentation, dependencies []ReceiptDependency) time.Time {
	if presentation == nil || len(presentation.Credentials) != 1 {
		return time.Time{}
	}
	minimum := presentation.Credentials[0].ValidUntil
	for _, dependency := range dependencies {
		if dependency.Attestation.ExpiresAt.Before(minimum) {
			minimum = dependency.Attestation.ExpiresAt
		}
	}
	return minimum
}
