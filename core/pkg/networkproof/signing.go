package networkproof

// quantum_posture: Network proof preimages use RFC 8785 canonicalization and SHA-256 digests for classical Ed25519.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
)

func CredentialSigningBytes(credential *Credential) ([]byte, error) {
	if credential == nil {
		return nil, errors.New("networkproof: nil credential")
	}
	copy := cloneCredential(credential)
	if copy.Proof != nil {
		copy.Proof.ProofValue = ""
	}
	canonical, err := canonicalJCS(copy)
	if err != nil {
		return nil, err
	}
	if len(canonical) > maxCanonicalBytes {
		return nil, errors.New("networkproof: canonical credential exceeds size limit")
	}
	return domainSeparated(credentialDomain, canonical), nil
}

func PresentationSigningBytes(presentation *Presentation) ([]byte, error) {
	if presentation == nil {
		return nil, errors.New("networkproof: nil presentation")
	}
	copy := clonePresentation(presentation)
	if copy.Proof != nil {
		copy.Proof.ProofValue = ""
	}
	canonical, err := canonicalJCS(copy)
	if err != nil {
		return nil, err
	}
	if len(canonical) > maxCanonicalBytes {
		return nil, errors.New("networkproof: canonical presentation exceeds size limit")
	}
	return domainSeparated(presentationDomain, canonical), nil
}

// CanonicalCredentialDigest binds the complete credential artifact, including
// its proof value. It is distinct from CredentialSigningBytes, which excludes
// only the proof value for signature verification.
func CanonicalCredentialDigest(credential *Credential) (string, error) {
	if credential == nil {
		return "", errors.New("networkproof: nil credential")
	}
	return canonicalArtifactDigest(credentialArtifactDomain, cloneCredential(credential))
}

// CanonicalPresentationDigest binds the complete presentation artifact,
// including both credential and presentation proof values.
func CanonicalPresentationDigest(presentation *Presentation) (string, error) {
	if presentation == nil {
		return "", errors.New("networkproof: nil presentation")
	}
	return canonicalArtifactDigest(presentationArtifactDomain, clonePresentation(presentation))
}

func canonicalArtifactDigest(domain string, value any) (string, error) {
	canonical, err := canonicalJCS(value)
	if err != nil {
		return "", err
	}
	if len(canonical) > maxCanonicalBytes {
		return "", errors.New("networkproof: canonical artifact exceeds size limit")
	}
	return digestBytes(domainSeparated(domain, canonical)), nil
}

func VerificationRequestBindingDigest(request VerificationRequest) (string, error) {
	request = cloneRequest(request)
	if err := preflightRequest(request); err != nil {
		return "", fmt.Errorf("networkproof: request binding preflight failed: %w", err)
	}
	binding := struct {
		RequestID        string    `json:"requestId"`
		ChallengeID      string    `json:"challengeId"`
		SubjectID        string    `json:"subjectId"`
		ActorType        ActorType `json:"actorType"`
		ClaimID          string    `json:"claimId"`
		Predicate        string    `json:"predicate"`
		ValueDigest      string    `json:"valueDigest"`
		Scope            []string  `json:"scope"`
		Audience         []string  `json:"audience"`
		NonceDigest      string    `json:"nonceDigest"`
		Purpose          string    `json:"purpose"`
		TransactionID    string    `json:"transactionId"`
		SchemaID         string    `json:"schemaId"`
		SchemaVersion    string    `json:"schemaVersion"`
		DisclosureDigest string    `json:"disclosureDigest"`
		ProfileDigest    string    `json:"profileDigest"`
	}{
		request.RequestID, request.ChallengeID, request.SubjectID, request.ActorType,
		request.ClaimID, request.Predicate, request.ValueDigest, cloneSorted(request.Scope), cloneSorted(request.Audience),
		digestString(request.Nonce), request.Purpose, request.TransactionID, request.SchemaID, request.SchemaVersion,
		request.DisclosureDigest, request.ExpectedProfileDigest,
	}
	return digestCanonical(requestDomain, binding)
}

func decisionInputDigest(requestBinding, holder, credentialDigest, presentationDigest string) (string, error) {
	return digestCanonical(decisionInputDomain, struct {
		RequestBinding     string `json:"requestBinding"`
		Holder             string `json:"holder"`
		CredentialDigest   string `json:"credentialDigest"`
		PresentationDigest string `json:"presentationDigest"`
	}{requestBinding, holder, credentialDigest, presentationDigest})
}

func AssuranceProfileDigest(profile AssuranceProfile) (string, error) {
	normalized, err := normalizeProfile(profile)
	if err != nil {
		return "", err
	}
	serializable := struct {
		ID                        string      `json:"id"`
		Version                   string      `json:"version"`
		VerifierVersion           string      `json:"verifierVersion"`
		HolderBinding             string      `json:"holderBinding"`
		AllowedActorTypes         []ActorType `json:"allowedActorTypes"`
		MaxCredentialAge          int64       `json:"maxCredentialAge"`
		MaxPresentationAge        int64       `json:"maxPresentationAge"`
		MaxDependencyAge          int64       `json:"maxDependencyAge"`
		ClockSkew                 int64       `json:"clockSkew"`
		AllowedCredentialProofs   []string    `json:"allowedCredentialProofs"`
		AllowedPresentationProofs []string    `json:"allowedPresentationProofs"`
		AllowedCredentialStatuses []string    `json:"allowedCredentialStatuses"`
		AllowedEvidenceKinds      []string    `json:"allowedEvidenceKinds"`
	}{
		normalized.ID, normalized.Version, normalized.VerifierVersion, normalized.HolderBinding, normalized.AllowedActorTypes,
		int64(normalized.MaxCredentialAge), int64(normalized.MaxPresentationAge), int64(normalized.MaxDependencyAge), int64(normalized.ClockSkew),
		normalized.AllowedCredentialProofs, normalized.AllowedPresentationProofs, normalized.AllowedCredentialStatuses, normalized.AllowedEvidenceKinds,
	}
	return digestCanonical(profileDomain, serializable)
}

func ClaimSchemaBindingDigest(request ClaimSchemaRequest) (string, error) {
	return digestCanonical(schemaDomain, request)
}

func AuthorityBindingDigest(request AuthorityRequest) (string, error) {
	copy := request
	copy.Scope, copy.Audience = cloneSorted(request.Scope), cloneSorted(request.Audience)
	return digestCanonical(authorityDomain, copy)
}

func KeyBindingDigest(request KeyRequest) (string, error) {
	return digestCanonical(keyDomain, request)
}

func StatusBindingDigest(request StatusRequest) (string, error) {
	return digestCanonical(statusDomain, request)
}

func EvidenceBindingDigest(request EvidenceRequest) (string, error) {
	copy := request
	copy.Scope, copy.Audience = cloneSorted(request.Scope), cloneSorted(request.Audience)
	return digestCanonical(evidenceDomain, copy)
}

func dependencySnapshotDigest(dependencies []ReceiptDependency) (string, error) {
	copy := append(make([]ReceiptDependency, 0, len(dependencies)), dependencies...)
	sortReceiptDependencies(copy)
	return digestCanonical(dependencyDomain, copy)
}

func AppraisalTrustBindingDigest(request AppraisalBindingRequest) (string, error) {
	return digestCanonical(appraisalDomain, request)
}

func canonicalJCS(value any) ([]byte, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("networkproof: JSON marshal failed: %w", err)
	}
	canonical, err := jsoncanonicalizer.Transform(raw)
	if err != nil {
		return nil, fmt.Errorf("networkproof: RFC 8785 canonicalization failed: %w", err)
	}
	return canonical, nil
}

func digestCanonical(domain string, value any) (string, error) {
	canonical, err := canonicalJCS(value)
	if err != nil {
		return "", err
	}
	if len(canonical) > maxCanonicalBytes {
		return "", errors.New("networkproof: canonical digest input exceeds size limit")
	}
	return digestBytes(domainSeparated(domain, canonical)), nil
}

func domainSeparated(domain string, canonical []byte) []byte {
	out := make([]byte, 0, len(domain)+1+len(canonical))
	out = append(out, domain...)
	out = append(out, 0)
	out = append(out, canonical...)
	return out
}

func digestString(value string) string { return digestBytes([]byte(value)) }

func digestBytes(value []byte) string {
	sum := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func verifyEd25519(publicKey []byte, signature string, payload []byte) bool {
	valid, err := crypto.Verify(hex.EncodeToString(publicKey), signature, payload)
	return err == nil && valid
}
