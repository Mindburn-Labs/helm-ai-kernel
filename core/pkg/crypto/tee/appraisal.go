package tee

import (
	"context"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

type AppraisalInput struct {
	Result     *VerifyResult
	Profile    contracts.VerifierProfile
	EnvelopeID string
	Subject    string
	Nonce      string
	PolicyHash string
	Signature  string
	IssuedAt   time.Time
	ExpiresAt  time.Time
}

func NewAttestationResultEnvelope(in AppraisalInput) (contracts.AttestationResultEnvelope, error) {
	if in.Result == nil {
		return contracts.AttestationResultEnvelope{}, fmt.Errorf("tee: verify result is required")
	}
	if in.Profile.ProfileID == "" {
		return contracts.AttestationResultEnvelope{}, fmt.Errorf("tee: verifier profile id is required")
	}
	if in.EnvelopeID == "" || in.Subject == "" {
		return contracts.AttestationResultEnvelope{}, fmt.Errorf("tee: envelope id and subject are required")
	}
	if in.Signature == "" {
		return contracts.AttestationResultEnvelope{}, fmt.Errorf("tee: signed attestation result envelope is required")
	}
	if in.ExpiresAt.IsZero() {
		return contracts.AttestationResultEnvelope{}, fmt.Errorf("tee: attestation result expiry is required")
	}
	nonce := in.Nonce
	if nonce == "" {
		nonce = fmt.Sprintf("%x", in.Result.Nonce)
	}
	policyHash := in.PolicyHash
	if policyHash == "" {
		policyHash = in.Profile.AppraisalPolicyHash
	}
	return contracts.AttestationResultEnvelope{
		EnvelopeID:      in.EnvelopeID,
		ProfileID:       in.Profile.ProfileID,
		Subject:         in.Subject,
		Platform:        string(in.Result.Platform),
		MeasurementHash: fmt.Sprintf("%x", in.Result.Measurement),
		Nonce:           nonce,
		TrustTier:       "verified",
		PolicyHash:      policyHash,
		Synthetic:       false,
		IssuedAt:        in.IssuedAt,
		ExpiresAt:       in.ExpiresAt,
		Signature:       in.Signature,
	}, nil
}

type EnvelopeSigner interface {
	Sign(data []byte) (string, error)
}

type NitroAppraiser struct {
	Roots   TrustRoots
	Signer  EnvelopeSigner
	Subject string
	Clock   func() time.Time
	TTL     time.Duration
}

func (a NitroAppraiser) Appraise(ctx context.Context, raw []byte, expectedNonce []byte, profile contracts.VerifierProfile) (contracts.AttestationResultEnvelope, error) {
	if err := ctx.Err(); err != nil {
		return contracts.AttestationResultEnvelope{}, err
	}
	if a.Signer == nil {
		return contracts.AttestationResultEnvelope{}, fmt.Errorf("tee/nitro: appraiser signer is required")
	}
	now := time.Now().UTC()
	if a.Clock != nil {
		now = a.Clock().UTC()
	}
	if profile.ProfileID == "" {
		return contracts.AttestationResultEnvelope{}, fmt.Errorf("tee/nitro: verifier profile id is required")
	}
	if profile.AllowSynthetic {
		return contracts.AttestationResultEnvelope{}, fmt.Errorf("tee/nitro: synthetic attestation is not allowed for production appraisal")
	}
	if !profile.ExpiresAt.IsZero() && !now.Before(profile.ExpiresAt) {
		return contracts.AttestationResultEnvelope{}, fmt.Errorf("tee/nitro: verifier profile expired")
	}
	if profile.Platform != "" && !strings.EqualFold(profile.Platform, string(PlatformNitro)) && !strings.EqualFold(profile.Platform, "aws-nitro") {
		return contracts.AttestationResultEnvelope{}, fmt.Errorf("tee/nitro: verifier profile platform %q is not Nitro", profile.Platform)
	}
	roots := a.Roots
	roots.RequireSignedChain = true
	result, err := Verify(PlatformNitro, raw, expectedNonce, roots)
	if err != nil {
		return contracts.AttestationResultEnvelope{}, err
	}
	if err := validateNitroPCRPolicy(result.PCRs, profile.RequiredPCRs); err != nil {
		return contracts.AttestationResultEnvelope{}, err
	}
	measurementHash := fmt.Sprintf("%x", result.Measurement)
	if profile.MeasurementHash != "" && !strings.EqualFold(profile.MeasurementHash, measurementHash) {
		return contracts.AttestationResultEnvelope{}, fmt.Errorf("tee/nitro: measurement mismatch")
	}
	ttl := a.TTL
	if ttl == 0 {
		ttl = time.Minute
	}
	subject := a.Subject
	if subject == "" {
		subject = "nitro-appraiser"
	}
	env := contracts.AttestationResultEnvelope{
		EnvelopeID:      "attestation-" + strings.TrimPrefix(canonicalize.HashBytes(result.Measurement), "sha256:")[:16],
		ProfileID:       profile.ProfileID,
		Subject:         subject,
		Platform:        string(PlatformNitro),
		MeasurementHash: measurementHash,
		Nonce:           fmt.Sprintf("%x", result.Nonce),
		TrustTier:       "verified",
		PolicyHash:      profile.AppraisalPolicyHash,
		Synthetic:       false,
		IssuedAt:        now,
		ExpiresAt:       now.Add(ttl),
	}
	payload, err := canonicalize.JCS(env)
	if err != nil {
		return contracts.AttestationResultEnvelope{}, err
	}
	sig, err := a.Signer.Sign(payload)
	if err != nil {
		return contracts.AttestationResultEnvelope{}, err
	}
	env.Signature = sig
	return env, nil
}

func validateNitroPCRPolicy(actual map[uint][]byte, required map[string]string) error {
	for name, expected := range required {
		idx, ok := parsePCRIndex(name)
		if !ok {
			return fmt.Errorf("tee/nitro: invalid PCR policy key %q", name)
		}
		pcr, ok := actual[idx]
		if !ok {
			return fmt.Errorf("tee/nitro: required PCR%d missing", idx)
		}
		got := strings.ToLower(hex.EncodeToString(pcr))
		want := strings.ToLower(strings.TrimSpace(expected))
		want = strings.TrimPrefix(want, "sha384:")
		want = strings.TrimPrefix(want, "0x")
		if got != want {
			return fmt.Errorf("tee/nitro: PCR%d mismatch", idx)
		}
	}
	return nil
}

func parsePCRIndex(name string) (uint, bool) {
	name = strings.TrimSpace(strings.ToUpper(name))
	name = strings.TrimPrefix(name, "PCR")
	if name == "" {
		return 0, false
	}
	n, err := strconv.ParseUint(name, 10, 8)
	if err != nil || n > 31 {
		return 0, false
	}
	return uint(n), true
}
