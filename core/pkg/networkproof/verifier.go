package networkproof

// quantum_posture: presentation and receipt signatures are classical Ed25519
// over SHA-256 RFC 8785 preimages; no post-quantum assurance is claimed or
// provided by this file.

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

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
	if !slices.Contains(v.profile.AllowedCredentialStatuses, credential.CredentialStatus.Type) || !validAttestation(statusResult.Attestation, statusBinding, now, v.profile) {
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
		if !slices.Contains(v.profile.AllowedEvidenceKinds, reference.Kind) {
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
		!slices.Contains(method.Purposes, request.Purpose) || len(method.PublicKey) != 32 || !validAttestation(method.Attestation, binding, now, v.profile) {
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
	if !slices.Contains(profile.AllowedCredentialProofs, ProofTypeHELMJCS2026) || !slices.Contains(profile.AllowedPresentationProofs, ProofTypeHELMJCS2026) {
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

type codedError string

func (e codedError) Error() string { return string(e) }

func errorCode(err error, fallback string) string {
	var coded codedError
	if errors.As(err, &coded) {
		return string(coded)
	}
	return fallback
}
