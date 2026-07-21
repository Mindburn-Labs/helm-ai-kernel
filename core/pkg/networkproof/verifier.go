package networkproof

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
	"github.com/google/uuid"
)

const (
	maxCanonicalBytes          = 1 << 20
	maxIdentifierRunes         = 1024
	maxPurposeRunes            = 2000
	maxSetItems                = 100
	maxEvidenceItems           = 32
	maxReceiptDeps             = maxEvidenceItems + 5
	maxJSONDepth               = 32
	bootstrapFreshness         = 10 * time.Minute
	credentialDomain           = "HELM_NETWORK_CREDENTIAL_V1"
	presentationDomain         = "HELM_NETWORK_PRESENTATION_V1"
	credentialArtifactDomain   = "HELM_NETWORK_CREDENTIAL_ARTIFACT_V1"
	presentationArtifactDomain = "HELM_NETWORK_PRESENTATION_ARTIFACT_V1"
	receiptDomain              = "HELM_NETWORK_VERIFICATION_RECEIPT_V1"
	requestDomain              = "HELM_NETWORK_VERIFICATION_REQUEST_V1"
	decisionInputDomain        = "HELM_NETWORK_DECISION_INPUT_V1"
	profileDomain              = "HELM_NETWORK_ASSURANCE_PROFILE_V1"
	schemaDomain               = "HELM_NETWORK_CLAIM_SCHEMA_V1"
	authorityDomain            = "HELM_NETWORK_ISSUER_AUTHORITY_V1"
	keyDomain                  = "HELM_NETWORK_KEY_RESOLUTION_V1"
	statusDomain               = "HELM_NETWORK_CREDENTIAL_STATUS_V1"
	evidenceDomain             = "HELM_NETWORK_EVIDENCE_V1"
	dependencyDomain           = "HELM_NETWORK_DEPENDENCY_SNAPSHOT_V1"
	appraisalDomain            = "HELM_NETWORK_RECEIPT_APPRAISAL_V1"
)

type Verifier struct {
	profile         AssuranceProfile
	profileDigest   string
	signerKeyID     string
	signerAlgorithm string
	signerPublicKey []byte
	deps            Dependencies
}

func NewVerifier(profile AssuranceProfile, deps Dependencies) (*Verifier, error) {
	normalized, err := normalizeProfile(profile)
	if err != nil {
		return nil, err
	}
	digest, err := AssuranceProfileDigest(normalized)
	if err != nil {
		return nil, fmt.Errorf("networkproof: digesting assurance profile: %w", err)
	}
	if deps.Keys == nil || deps.Schemas == nil || deps.Authority == nil || deps.Statuses == nil || deps.Evidence == nil || deps.Challenges == nil || deps.Signer == nil {
		return nil, errors.New("networkproof: every verification dependency is required")
	}
	signerKeyID, signerAlgorithm := deps.Signer.KeyID(), deps.Signer.Algorithm()
	signerPublicKey := append([]byte(nil), deps.Signer.PublicKey()...)
	if !bounded(signerKeyID, maxIdentifierRunes) || signerAlgorithm != AlgorithmEd25519 || len(signerPublicKey) != 32 {
		return nil, errors.New("networkproof: an identified Ed25519 receipt signer is required")
	}
	if deps.Clock == nil {
		deps.Clock = time.Now
	}
	if deps.NewID == nil {
		deps.NewID = uuid.NewString
	}
	return &Verifier{
		profile: normalized, profileDigest: digest, signerKeyID: signerKeyID,
		signerAlgorithm: signerAlgorithm, signerPublicKey: signerPublicKey, deps: deps,
	}, nil
}

// Verify evaluates one immutable input snapshot. A source-issued challenge is
// consumed only by the atomic commit of a signed decision. Exact retries return
// the original stored receipt; conflicting inputs fail closed.
func (v *Verifier) Verify(ctx context.Context, request VerificationRequest, presentation *Presentation) (*VerificationReceipt, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("networkproof: verification canceled before snapshot: %w", err)
	}
	request = cloneRequest(request)
	presentation = clonePresentation(presentation)
	if err := preflightRequest(request); err != nil {
		return nil, fmt.Errorf("networkproof: verification request exceeds structural bounds: %w", err)
	}
	if err := preflightPresentation(presentation); err != nil {
		return nil, fmt.Errorf("networkproof: presentation exceeds structural bounds: %w", err)
	}
	receipt := v.baseReceipt(request, presentation)
	requestBinding, bindingErr := VerificationRequestBindingDigest(request)
	if bindingErr == nil {
		receipt.RequestBindingDigest = requestBinding
	}

	commit := false
	finish := func(status VerificationStatus, reason string) (*VerificationReceipt, error) {
		if err := ctx.Err(); err != nil {
			return nil, fmt.Errorf("networkproof: verification canceled before decision: %w", err)
		}
		receipt.DecisionStatusAtEvaluation = status
		receipt.ReasonCode = reason
		receipt.EvaluatedAt = v.deps.Clock().UTC()
		receipt.ReceiptID = v.deps.NewID()
		if status == StatusVerified {
			if code := v.recheckVerifiedFreshness(receipt, presentation, receipt.EvaluatedAt); code != "" {
				receipt.DecisionStatusAtEvaluation = StatusUnknown
				receipt.ReasonCode = code
			}
		}
		signed, err := v.signReceipt(receipt)
		if err != nil {
			return nil, err
		}
		if err := ctx.Err(); err != nil {
			return nil, fmt.Errorf("networkproof: verification canceled before challenge commit: %w", err)
		}
		if !commit {
			return signed, nil
		}
		stored, err := v.deps.Challenges.CommitDecision(ctx, request.ChallengeID, requestBinding, receipt.DecisionInputDigest, *signed)
		if err != nil {
			return nil, fmt.Errorf("networkproof: committing signed challenge decision: %w", err)
		}
		stored.Decision = *cloneReceipt(&stored.Decision)
		if err := v.validateStoredDecision(
			requestBinding, receipt.DecisionInputDigest, receipt.CanonicalCredentialDigest,
			receipt.CanonicalPresentationDigest, &stored.Decision,
		); err != nil {
			return nil, err
		}
		return cloneReceipt(&stored.Decision), nil
	}

	if bindingErr != nil || validateRequest(request, v.profile, v.profileDigest) != nil {
		return finish(StatusInvalid, "invalid_verification_request")
	}
	record, err := v.deps.Challenges.LoadChallenge(ctx, request.ChallengeID)
	if err != nil {
		return finish(StatusUnknown, "challenge_unavailable")
	}
	record.Challenge.Audience = append([]string(nil), record.Challenge.Audience...)
	record.Decision = cloneReceipt(record.Decision)
	if bounded(record.Challenge.Generation, maxIdentifierRunes) {
		receipt.ChallengeGeneration = record.Challenge.Generation
	}
	if err := validateChallenge(record.Challenge, request, requestBinding, v.deps.Clock().UTC(), record.Decision != nil); err != nil {
		if errors.Is(err, ErrChallengeConflict) {
			return finish(StatusInvalid, "challenge_binding_mismatch")
		}
		return finish(StatusInvalid, "challenge_invalid")
	}
	presentationSigningBytes, err := PresentationSigningBytes(presentation)
	if err != nil || len(presentationSigningBytes) > maxCanonicalBytes {
		return finish(StatusInvalid, "presentation_invalid")
	}
	receipt.CanonicalPresentationDigest, err = CanonicalPresentationDigest(presentation)
	if err != nil {
		return finish(StatusInvalid, "presentation_invalid")
	}
	credential := &presentation.Credentials[0]
	credentialSigningBytes, err := CredentialSigningBytes(credential)
	if err != nil || len(credentialSigningBytes) > maxCanonicalBytes {
		return finish(StatusInvalid, "credential_invalid")
	}
	receipt.CanonicalCredentialDigest, err = CanonicalCredentialDigest(credential)
	if err != nil {
		return finish(StatusInvalid, "credential_invalid")
	}
	receipt.CredentialID = credential.ID
	receipt.PresentationID = presentation.ID
	receipt.Issuer = credential.Issuer
	receipt.DecisionInputDigest, err = decisionInputDigest(
		requestBinding, presentation.Holder, receipt.CanonicalCredentialDigest, receipt.CanonicalPresentationDigest,
	)
	if err != nil {
		return nil, err
	}

	if record.Decision != nil {
		if err := v.validateStoredDecision(
			requestBinding, receipt.DecisionInputDigest, receipt.CanonicalCredentialDigest,
			receipt.CanonicalPresentationDigest, record.Decision,
		); err != nil {
			return nil, err
		}
		if err := validateReplayEnvelope(request, presentation, credential, record.Decision); err != nil {
			return nil, ErrChallengeConflict
		}
		return cloneReceipt(record.Decision), nil
	}

	now := v.deps.Clock().UTC()
	if err := validatePresentationEnvelope(request, presentation, v.profile, now); err != nil {
		return finish(StatusInvalid, errorCode(err, "presentation_invalid"))
	}
	if status, code := validateCredentialEnvelope(request, presentation, credential, v.profile, now); status != StatusVerified {
		return finish(status, code)
	}

	holderRequest := KeyRequest{
		ControllerID: presentation.Holder, MethodID: presentation.Proof.VerificationMethod,
		Purpose: ProofPurposeAuthentication, ProofCreated: presentation.Proof.Created, ProfileDigest: v.profileDigest,
	}
	holderKey, status, code := v.resolveKey(ctx, holderRequest, now)
	if status != StatusVerified {
		return finish(status, "holder_"+code)
	}
	v.addDependency(receipt, "holder_key", holderKey.ID, holderKey.State, holderKey.Attestation)
	if !verifyEd25519(holderKey.PublicKey, presentation.Proof.ProofValue, presentationSigningBytes) {
		return finish(StatusInvalid, "presentation_signature_invalid")
	}
	receipt.Holder = presentation.Holder
	receipt.HolderKeyID = holderKey.ID
	commit = true

	schemaRequest := ClaimSchemaRequest{
		SchemaID: request.SchemaID, SchemaVersion: request.SchemaVersion, ActorType: request.ActorType,
		SubjectID: request.SubjectID, ClaimID: request.ClaimID, Predicate: request.Predicate,
		ValueDigest: request.ValueDigest, DisclosureDigest: request.DisclosureDigest, ProfileDigest: v.profileDigest,
	}
	schemaBinding, err := ClaimSchemaBindingDigest(schemaRequest)
	if err != nil {
		return nil, err
	}
	schema, err := v.deps.Schemas.AuthorizeClaimSchema(ctx, schemaRequest)
	if err != nil {
		return finish(StatusUnknown, "claim_schema_unavailable")
	}
	v.addDependency(receipt, "claim_schema", request.SchemaID+"@"+request.SchemaVersion, trustState(schema.Allowed), schema.Attestation)
	if !schema.Allowed || !validSHA256(schema.SchemaDigest) || !validAttestation(schema.Attestation, schemaBinding, now, v.profile) {
		return finish(StatusInvalid, "claim_schema_invalid")
	}
	receipt.CredentialSchemaDigest = schema.SchemaDigest

	authorityRequest := AuthorityRequest{
		Issuer: credential.Issuer, SubjectID: request.SubjectID, ActorType: request.ActorType,
		ClaimID: request.ClaimID, Predicate: request.Predicate, ValueDigest: request.ValueDigest,
		Scope: cloneSorted(request.Scope), Audience: cloneSorted(request.Audience), Purpose: request.Purpose,
		TransactionID: request.TransactionID, DisclosureDigest: request.DisclosureDigest,
		SchemaDigest: schema.SchemaDigest, ProfileDigest: v.profileDigest,
	}
	authorityBinding, err := AuthorityBindingDigest(authorityRequest)
	if err != nil {
		return nil, err
	}
	authority, err := v.deps.Authority.AuthorizeIssuer(ctx, authorityRequest)
	if err != nil {
		return finish(StatusUnknown, "issuer_authority_unavailable")
	}
	v.addDependency(receipt, "issuer_authority", credential.Issuer, authority.State, authority.Attestation)
	if !authority.Authorized || authority.State != TrustActive || !validAttestation(authority.Attestation, authorityBinding, now, v.profile) {
		return finish(statusForTrust(authority.State), "issuer_unauthorized")
	}

	issuerRequest := KeyRequest{
		ControllerID: credential.Issuer, MethodID: credential.Proof.VerificationMethod,
		Purpose: ProofPurposeAssertion, ProofCreated: credential.Proof.Created, ProfileDigest: v.profileDigest,
	}
	issuerKey, status, code := v.resolveKey(ctx, issuerRequest, now)
	if status != StatusVerified {
		return finish(status, "issuer_"+code)
	}
	v.addDependency(receipt, "issuer_key", issuerKey.ID, issuerKey.State, issuerKey.Attestation)
	if !verifyEd25519(issuerKey.PublicKey, credential.Proof.ProofValue, credentialSigningBytes) {
		return finish(StatusInvalid, "credential_signature_invalid")
	}
	receipt.IssuerKeyID = issuerKey.ID

	statusRequest := StatusRequest{
		Reference: credential.CredentialStatus, CredentialID: credential.ID,
		CredentialDigest: receipt.CanonicalCredentialDigest, Issuer: credential.Issuer,
		SubjectID: request.SubjectID, ClaimID: request.ClaimID, ValueDigest: request.ValueDigest,
		ProfileDigest: v.profileDigest,
	}
	statusBinding, err := StatusBindingDigest(statusRequest)
	if err != nil {
		return nil, err
	}
	statusResult, err := v.deps.Statuses.ResolveCredentialStatus(ctx, statusRequest)
	if err != nil {
		return finish(StatusUnknown, "credential_status_unavailable")
	}
	statusState := trustForCredentialStatus(statusResult.Status)
	v.addDependency(receipt, "credential_status", credential.CredentialStatus.ID, statusState, statusResult.Attestation)
	if !contains(v.profile.AllowedCredentialStatuses, credential.CredentialStatus.Type) || !validAttestation(statusResult.Attestation, statusBinding, now, v.profile) {
		return finish(StatusUnknown, "credential_status_stale")
	}
	switch statusResult.Status {
	case CredentialStatusValid:
	case CredentialStatusRevoked, CredentialStatusSuspended:
		return finish(StatusRevoked, "credential_revoked")
	case CredentialStatusDisputed:
		return finish(StatusDisputed, "credential_disputed")
	default:
		return finish(StatusUnknown, "credential_status_unknown")
	}

	for _, reference := range credential.Evidence {
		if !contains(v.profile.AllowedEvidenceKinds, reference.Kind) {
			return finish(StatusInvalid, "evidence_type_invalid")
		}
		evidenceRequest := EvidenceRequest{
			Reference: reference, CredentialID: credential.ID, CredentialDigest: receipt.CanonicalCredentialDigest,
			Issuer: credential.Issuer, SubjectID: request.SubjectID, ActorType: request.ActorType,
			ClaimID: request.ClaimID, Predicate: request.Predicate, ValueDigest: request.ValueDigest,
			Scope: cloneSorted(request.Scope), Audience: cloneSorted(request.Audience), Purpose: request.Purpose,
			TransactionID: request.TransactionID, DisclosureDigest: request.DisclosureDigest, ProfileDigest: v.profileDigest,
		}
		evidenceBinding, err := EvidenceBindingDigest(evidenceRequest)
		if err != nil {
			return nil, err
		}
		result, err := v.deps.Evidence.VerifyEvidence(ctx, evidenceRequest)
		if err != nil {
			return finish(StatusUnknown, "evidence_unavailable")
		}
		v.addDependency(receipt, "evidence", reference.ID, result.State, result.Attestation)
		if !validAttestation(result.Attestation, evidenceBinding, now, v.profile) {
			return finish(StatusUnknown, "evidence_stale")
		}
		if result.State != TrustActive {
			return finish(statusForTrust(result.State), "evidence_not_verified")
		}
		if !validArtifactReference(result.ProofGraphRoot) || !validArtifactReference(result.EvidencePackRoot) {
			return finish(StatusInvalid, "evidence_roots_invalid")
		}
		receipt.ProofGraphRoots = appendUniqueArtifact(receipt.ProofGraphRoots, result.ProofGraphRoot)
		receipt.EvidencePackRoots = appendUniqueArtifact(receipt.EvidencePackRoots, result.EvidencePackRoot)
	}

	receipt.FreshUntil = minimumFreshUntil(presentation, receipt.Dependencies)
	return finish(StatusVerified, "verified_exact_claim")
}

func (v *Verifier) resolveKey(ctx context.Context, request KeyRequest, now time.Time) (VerificationMethod, VerificationStatus, string) {
	binding, err := KeyBindingDigest(request)
	if err != nil {
		return VerificationMethod{}, StatusInvalid, "key_invalid"
	}
	method, err := v.deps.Keys.ResolveVerificationMethod(ctx, request)
	if err != nil {
		return VerificationMethod{}, StatusUnknown, "key_unavailable"
	}
	method.PublicKey = append([]byte(nil), method.PublicKey...)
	method.Purposes = append([]string(nil), method.Purposes...)
	if method.ID != request.MethodID || method.Controller != request.ControllerID || method.Algorithm != AlgorithmEd25519 ||
		!contains(method.Purposes, request.Purpose) || len(method.PublicKey) != 32 || !validAttestation(method.Attestation, binding, now, v.profile) {
		return VerificationMethod{}, StatusInvalid, "key_invalid"
	}
	if method.State != TrustActive {
		return VerificationMethod{}, statusForTrust(method.State), "key_not_active"
	}
	if method.ValidFrom.IsZero() || method.ValidUntil.IsZero() || !request.ProofCreated.Before(method.ValidUntil) || request.ProofCreated.Before(method.ValidFrom) ||
		now.Before(method.ValidFrom) || !now.Before(method.ValidUntil) {
		return VerificationMethod{}, StatusInvalid, "key_time_invalid"
	}
	return method, StatusVerified, ""
}

func (v *Verifier) recheckVerifiedFreshness(receipt *VerificationReceipt, presentation *Presentation, now time.Time) string {
	if presentation == nil || len(presentation.Credentials) != 1 || !now.Before(presentation.Credentials[0].ValidUntil) {
		return "credential_expired_during_verification"
	}
	if now.Sub(presentation.IssuedAt) > v.profile.MaxPresentationAge+v.profile.ClockSkew {
		return "presentation_expired_during_verification"
	}
	for _, dependency := range receipt.Dependencies {
		if dependency.Attestation.CheckedAt.After(now) || !dependencyFresh(dependency.Attestation.CheckedAt, dependency.Attestation.ExpiresAt, now, v.profile) {
			return "dependency_expired_during_verification"
		}
	}
	if !receipt.FreshUntil.IsZero() && !now.Before(receipt.FreshUntil) {
		return "verification_freshness_elapsed"
	}
	return ""
}

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
	if request.ExpectedProfileDigest != profileDigest || !containsActor(profile.AllowedActorTypes, request.ActorType) || profile.HolderBinding != HolderBindingSubjectKeyV1 {
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
		!contains(profile.AllowedPresentationProofs, presentation.Proof.Type) || presentation.Proof.Created.Before(presentation.IssuedAt) ||
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
	if credential.Proof.Type != ProofTypeHELMJCS2026 || !contains(profile.AllowedCredentialProofs, credential.Proof.Type) ||
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

func normalizeProfile(profile AssuranceProfile) (AssuranceProfile, error) {
	profile = cloneProfile(profile)
	if !bounded(profile.ID, maxIdentifierRunes) || !bounded(profile.Version, maxIdentifierRunes) ||
		!bounded(profile.VerifierVersion, maxIdentifierRunes) || profile.HolderBinding != HolderBindingSubjectKeyV1 {
		return AssuranceProfile{}, errors.New("networkproof: profile identity and subject-held-key binding are required")
	}
	if profile.MaxCredentialAge <= 0 || profile.MaxPresentationAge <= 0 || profile.MaxDependencyAge <= 0 {
		return AssuranceProfile{}, errors.New("networkproof: profile freshness windows must be positive")
	}
	if profile.ClockSkew < 0 || profile.ClockSkew > 10*time.Minute {
		return AssuranceProfile{}, errors.New("networkproof: profile clock skew must be between zero and ten minutes")
	}
	maxDuration := time.Duration(1<<63 - 1)
	if profile.MaxCredentialAge > maxDuration-profile.ClockSkew || profile.MaxPresentationAge > maxDuration-profile.ClockSkew ||
		profile.MaxDependencyAge > maxDuration-profile.ClockSkew {
		return AssuranceProfile{}, errors.New("networkproof: profile freshness window overflows clock-skew arithmetic")
	}
	sort.Slice(profile.AllowedActorTypes, func(i, j int) bool { return profile.AllowedActorTypes[i] < profile.AllowedActorTypes[j] })
	if !exactActorTypes(profile.AllowedActorTypes) {
		return AssuranceProfile{}, errors.New("networkproof: v1 profile must support all four subject-held-key actor types")
	}
	for _, values := range [][]string{profile.AllowedCredentialProofs, profile.AllowedPresentationProofs, profile.AllowedCredentialStatuses, profile.AllowedEvidenceKinds} {
		sort.Strings(values)
		if validateExactSet(values, maxSetItems, false) != nil {
			return AssuranceProfile{}, errors.New("networkproof: profile allowlists are invalid")
		}
	}
	if !contains(profile.AllowedCredentialProofs, ProofTypeHELMJCS2026) || !contains(profile.AllowedPresentationProofs, ProofTypeHELMJCS2026) {
		return AssuranceProfile{}, errors.New("networkproof: profile must allow the HELM RFC8785 Ed25519 proof suite")
	}
	return profile, nil
}

func cloneProfile(profile AssuranceProfile) AssuranceProfile {
	profile.AllowedActorTypes = append([]ActorType(nil), profile.AllowedActorTypes...)
	profile.AllowedCredentialProofs = append([]string(nil), profile.AllowedCredentialProofs...)
	profile.AllowedPresentationProofs = append([]string(nil), profile.AllowedPresentationProofs...)
	profile.AllowedCredentialStatuses = append([]string(nil), profile.AllowedCredentialStatuses...)
	profile.AllowedEvidenceKinds = append([]string(nil), profile.AllowedEvidenceKinds...)
	return profile
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

func dependencyFresh(checkedAt, expiresAt, now time.Time, profile AssuranceProfile) bool {
	return !checkedAt.IsZero() && !expiresAt.IsZero() && checkedAt.Before(expiresAt) &&
		!checkedAt.After(now.Add(profile.ClockSkew)) && now.Sub(checkedAt) <= profile.MaxDependencyAge+profile.ClockSkew && now.Before(expiresAt)
}

func validAttestation(attestation DependencyAttestation, expectedBinding string, now time.Time, profile AssuranceProfile) bool {
	return attestation.BindingDigest == expectedBinding && validAttestationShape(attestation) &&
		dependencyFresh(attestation.CheckedAt, attestation.ExpiresAt, now, profile)
}

func validAttestationShape(attestation DependencyAttestation) bool {
	return bounded(attestation.DecisionRef, maxIdentifierRunes) && validSHA256(attestation.BindingDigest) &&
		validSHA256(attestation.SnapshotDigest) && bounded(attestation.Generation, maxIdentifierRunes) &&
		!attestation.CheckedAt.IsZero() && !attestation.ExpiresAt.IsZero() && attestation.CheckedAt.Before(attestation.ExpiresAt)
}

func validateExactSet(values []string, maxItems int, rejectBroad bool) error {
	if len(values) == 0 || len(values) > maxItems {
		return errors.New("set cardinality invalid")
	}
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if value != strings.TrimSpace(value) || !bounded(value, maxIdentifierRunes) || strings.Contains(value, "*") {
			return errors.New("set item invalid")
		}
		lower := strings.ToLower(value)
		if rejectBroad && (lower == "all" || lower == "any" || lower == "everything" || strings.HasSuffix(lower, ":all")) {
			return errors.New("broad set item forbidden")
		}
		if _, ok := seen[value]; ok {
			return errors.New("duplicate set item")
		}
		seen[value] = struct{}{}
	}
	return nil
}

func validateAudience(values []string) error {
	if err := validateExactSet(values, maxSetItems, true); err != nil {
		return err
	}
	for _, value := range values {
		parsed, err := url.ParseRequestURI(value)
		if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" ||
			parsed.Host != strings.ToLower(parsed.Host) || parsed.String() != value {
			return errors.New("audience must be a canonical absolute HTTPS client identifier")
		}
	}
	return nil
}

func equalSet(a, b []string) bool {
	if validateExactSet(a, maxSetItems, false) != nil || validateExactSet(b, maxSetItems, false) != nil || len(a) != len(b) {
		return false
	}
	aa, bb := cloneSorted(a), cloneSorted(b)
	for i := range aa {
		if aa[i] != bb[i] {
			return false
		}
	}
	return true
}

func equalOrdered(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func cloneSorted(values []string) []string {
	out := append([]string(nil), values...)
	sort.Strings(out)
	return out
}

func bounded(value string, maxRunes int) bool {
	return cheapString(value, maxRunes) && value == strings.TrimSpace(value) && utf8.ValidString(value)
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

func contains(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}

func containsActor(values []ActorType, expected ActorType) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}

func exactActorTypes(values []ActorType) bool {
	want := []ActorType{ActorAgent, ActorOrganization, ActorPerson, ActorService}
	if len(values) != len(want) {
		return false
	}
	for i := range values {
		if values[i] != want[i] {
			return false
		}
	}
	return true
}

func validActorType(value ActorType) bool {
	return value == ActorPerson || value == ActorOrganization || value == ActorAgent || value == ActorService
}

func validSHA256(value string) bool {
	if !strings.HasPrefix(value, "sha256:") || len(value) != len("sha256:")+64 || value != strings.ToLower(value) {
		return false
	}
	_, err := hex.DecodeString(strings.TrimPrefix(value, "sha256:"))
	return err == nil
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

func statusForTrust(state TrustState) VerificationStatus {
	switch state {
	case TrustRevoked:
		return StatusRevoked
	case TrustDisputed:
		return StatusDisputed
	case TrustQuarantined, TrustCompromised, TrustUnknown:
		return StatusUnknown
	default:
		return StatusInvalid
	}
}

func trustForCredentialStatus(status CredentialStatus) TrustState {
	switch status {
	case CredentialStatusValid:
		return TrustActive
	case CredentialStatusRevoked, CredentialStatusSuspended:
		return TrustRevoked
	case CredentialStatusDisputed:
		return TrustDisputed
	default:
		return TrustUnknown
	}
}

func trustState(allowed bool) TrustState {
	if allowed {
		return TrustActive
	}
	return TrustUnknown
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

func digestString(value string) string { return digestBytes([]byte(value)) }

func digestBytes(value []byte) string {
	sum := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func verifyEd25519(publicKey []byte, signature string, payload []byte) bool {
	valid, err := crypto.Verify(hex.EncodeToString(publicKey), signature, payload)
	return err == nil && valid
}

type codedError string

func (e codedError) Error() string { return string(e) }

func errorCode(err error, fallback string) string {
	var coded codedError
	if errors.As(err, &coded) {
		return string(coded)
	}
	return fallback
}
