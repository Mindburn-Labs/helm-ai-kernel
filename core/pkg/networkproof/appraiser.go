package networkproof

import (
	"context"
	"errors"
	"time"
)

type ReceiptAppraiser struct {
	resolver ReceiptTrustResolver
	clock    func() time.Time
}

func NewReceiptAppraiser(resolver ReceiptTrustResolver, clock func() time.Time) (*ReceiptAppraiser, error) {
	if resolver == nil {
		return nil, errors.New("networkproof: receipt trust resolver is required")
	}
	if clock == nil {
		clock = time.Now
	}
	return &ReceiptAppraiser{resolver: resolver, clock: clock}, nil
}

// Appraise resolves the signer, profile, and every recorded dependency from
// current source-owned registries. It is the sole path to CanRenderVerified.
func (a *ReceiptAppraiser) Appraise(ctx context.Context, receipt *VerificationReceipt, expected AppraisalExpectation) ReceiptAppraisal {
	now := a.clock().UTC()
	result := ReceiptAppraisal{AppraisedAt: now, Status: AppraisalInvalid, ReasonCode: "receipt_invalid"}
	if err := ctx.Err(); err != nil {
		result.ReasonCode = "appraisal_canceled"
		return result
	}
	if receipt != nil {
		result.ReceiptID = receipt.ReceiptID
		receipt = cloneReceipt(receipt)
	}
	expected.Scope = append([]string(nil), expected.Scope...)
	expected.Audience = append([]string(nil), expected.Audience...)
	if err := validateReceiptSchema(receipt); err != nil || !matchesExpectation(receipt, expected) {
		return result
	}

	signerRequest := AppraisalBindingRequest{
		Kind: "receipt_signer", Subject: receipt.SignerKeyID, ReceiptID: receipt.ReceiptID,
		ProfileDigest: receipt.AssuranceProfileDigest, BindingDigest: receipt.RequestBindingDigest,
	}
	signerBinding, err := AppraisalTrustBindingDigest(signerRequest)
	if err != nil {
		return result
	}
	signer, ok := a.resolveBootstrap(ctx, signerRequest, now)
	if !ok {
		result.Status, result.ReasonCode = AppraisalWarning, "receipt_signer_unavailable"
		return result
	}
	if signer.State == TrustRevoked {
		result.Status, result.ReasonCode = AppraisalRevoked, "receipt_signer_revoked"
		return result
	}
	if signer.State != TrustActive || signer.Algorithm != AlgorithmEd25519 || len(signer.PublicKey) != 32 {
		result.Status, result.ReasonCode = AppraisalWarning, "receipt_signer_not_trusted"
		return result
	}
	if err := VerifyReceiptSignature(receipt, signer.PublicKey); err != nil {
		return result
	}

	profileRequest := AppraisalBindingRequest{
		Kind: "assurance_profile", Subject: receipt.AssuranceProfileID + "@" + receipt.AssuranceProfileVersion,
		ReceiptID: receipt.ReceiptID, ProfileDigest: receipt.AssuranceProfileDigest,
		BindingDigest: receipt.RequestBindingDigest,
	}
	profileTrust, ok := a.resolveBootstrap(ctx, profileRequest, now)
	if !ok || profileTrust.Profile == nil {
		result.Status, result.ReasonCode = AppraisalWarning, "assurance_profile_unavailable"
		return result
	}
	if profileTrust.State != TrustActive {
		result.Status, result.ReasonCode = appraisalForTrust(profileTrust.State), "assurance_profile_not_active"
		return result
	}
	profile, err := normalizeProfile(*profileTrust.Profile)
	if err != nil {
		result.Status, result.ReasonCode = AppraisalWarning, "assurance_profile_invalid"
		return result
	}
	profileBinding, err := AppraisalTrustBindingDigest(profileRequest)
	if err != nil {
		return result
	}
	profileDigest, err := AssuranceProfileDigest(profile)
	if err != nil || profileDigest != receipt.AssuranceProfileDigest || profile.VerifierVersion != receipt.VerifierVersion ||
		!validAttestation(profileTrust.Attestation, profileBinding, now, profile) {
		result.Status, result.ReasonCode = AppraisalWarning, "assurance_profile_mismatch"
		return result
	}
	if !validAttestation(signer.Attestation, signerBinding, now, profile) {
		result.Status, result.ReasonCode = AppraisalWarning, "receipt_signer_stale"
		return result
	}

	if receipt.DecisionStatusAtEvaluation != StatusVerified {
		switch receipt.DecisionStatusAtEvaluation {
		case StatusRevoked:
			result.Status, result.ReasonCode = AppraisalRevoked, "historical_decision_revoked"
		case StatusInvalid:
			result.Status, result.ReasonCode = AppraisalInvalid, "historical_decision_invalid"
		default:
			result.Status, result.ReasonCode = AppraisalWarning, "historical_decision_not_verified"
		}
		return result
	}
	if receipt.EvaluatedAt.After(now.Add(profile.ClockSkew)) || receipt.FreshUntil.IsZero() || !now.Before(receipt.FreshUntil) {
		result.Status, result.ReasonCode = AppraisalWarning, "receipt_freshness_elapsed"
		return result
	}

	for _, dependency := range receipt.Dependencies {
		request := AppraisalBindingRequest{
			Kind: dependency.Kind, Subject: dependency.Subject, ReceiptID: receipt.ReceiptID,
			ProfileDigest: receipt.AssuranceProfileDigest, BindingDigest: dependency.Attestation.BindingDigest,
			Generation: dependency.Attestation.Generation,
		}
		current, err := a.resolver.ResolveCurrentTrust(ctx, request)
		if err != nil {
			result.Status, result.ReasonCode = AppraisalWarning, "dependency_unavailable"
			return result
		}
		binding, err := AppraisalTrustBindingDigest(request)
		if err != nil {
			return result
		}
		if current.Attestation.CheckedAt.After(now) || !validAttestation(current.Attestation, binding, now, profile) ||
			current.Attestation.Generation != dependency.Attestation.Generation {
			result.Status, result.ReasonCode = AppraisalWarning, "dependency_stale"
			return result
		}
		if current.State != TrustActive {
			result.Status, result.ReasonCode = appraisalForTrust(current.State), "dependency_not_active"
			return result
		}
	}
	if err := ctx.Err(); err != nil {
		result.Status, result.ReasonCode = AppraisalWarning, "appraisal_canceled"
		return result
	}

	result.Status, result.ReasonCode = AppraisalVerified, "currently_verified_exact_claim"
	return result
}

func (a *ReceiptAppraiser) resolveBootstrap(ctx context.Context, request AppraisalBindingRequest, now time.Time) (CurrentTrustResult, bool) {
	result, err := a.resolver.ResolveCurrentTrust(ctx, request)
	if err != nil {
		return CurrentTrustResult{}, false
	}
	binding, err := AppraisalTrustBindingDigest(request)
	if err != nil || result.Attestation.BindingDigest != binding || !validAttestationShape(result.Attestation) ||
		result.Attestation.CheckedAt.After(now) || now.Sub(result.Attestation.CheckedAt) > bootstrapFreshness || !now.Before(result.Attestation.ExpiresAt) {
		return CurrentTrustResult{}, false
	}
	result.PublicKey = append([]byte(nil), result.PublicKey...)
	if result.Profile != nil {
		profile := cloneProfile(*result.Profile)
		result.Profile = &profile
	}
	return result, true
}

func matchesExpectation(receipt *VerificationReceipt, expected AppraisalExpectation) bool {
	return receipt != nil && validSHA256(expected.RequestBindingDigest) && validSHA256(expected.ProfileDigest) &&
		validActorType(expected.ActorType) && bounded(expected.SubjectID, maxIdentifierRunes) &&
		bounded(expected.ClaimID, maxIdentifierRunes) && bounded(expected.Predicate, maxPurposeRunes) &&
		validSHA256(expected.ValueDigest) && validateExactSet(expected.Scope, maxSetItems, true) == nil &&
		validateAudience(expected.Audience) == nil && bounded(expected.Purpose, maxPurposeRunes) &&
		bounded(expected.TransactionID, maxIdentifierRunes) && validSHA256(expected.DisclosureDigest) &&
		receipt.RequestBindingDigest == expected.RequestBindingDigest && receipt.SubjectID == expected.SubjectID &&
		receipt.ActorType == expected.ActorType && receipt.ClaimID == expected.ClaimID &&
		receipt.Predicate == expected.Predicate && receipt.ValueDigest == expected.ValueDigest &&
		equalSet(receipt.Scope, expected.Scope) && equalSet(receipt.Audience, expected.Audience) &&
		receipt.Purpose == expected.Purpose && receipt.TransactionID == expected.TransactionID &&
		receipt.DisclosureDigest == expected.DisclosureDigest && receipt.AssuranceProfileDigest == expected.ProfileDigest
}

func appraisalForTrust(state TrustState) AppraisalStatus {
	if state == TrustRevoked {
		return AppraisalRevoked
	}
	if state == TrustActive {
		return AppraisalVerified
	}
	return AppraisalWarning
}
