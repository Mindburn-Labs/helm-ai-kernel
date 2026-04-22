package channels

import (
	"context"
	"fmt"
	"time"
)

// AntiSpoofResult is the outcome of an anti-spoofing validation check.
type AntiSpoofResult struct {
	// Passed is true when all checks passed and the envelope is considered legitimate.
	Passed bool `json:"passed"`
	// SenderTrust is the trust class assigned after the check.
	// When Passed is false this will be SenderTrustSuspicious.
	SenderTrust SenderTrustClass `json:"sender_trust"`
	// Reason is a human-readable explanation of the result.
	Reason string `json:"reason"`
}

// AntiSpoofValidator validates incoming channel envelopes for spoofing indicators.
type AntiSpoofValidator interface {
	// Validate checks the envelope for spoofing indicators.
	// It always returns a non-nil *AntiSpoofResult; err is non-nil only on internal failure.
	Validate(ctx context.Context, env ChannelEnvelope) (*AntiSpoofResult, error)
}

// DefaultAntiSpoofValidator performs basic envelope integrity checks.
// It is intentionally conservative: any suspicious signal causes the envelope to fail.
type DefaultAntiSpoofValidator struct {
	// secrets holds the per-channel signing secrets for signature verification.
	secrets SignatureSecrets
}

// NewAntiSpoofValidator returns a DefaultAntiSpoofValidator with no signature secrets.
// Signature verification is skipped when secrets are not configured.
func NewAntiSpoofValidator() *DefaultAntiSpoofValidator {
	return &DefaultAntiSpoofValidator{}
}

// NewAntiSpoofValidatorWithSecrets returns a validator configured with channel signing secrets.
// When secrets are provided, the validator will verify HMAC/token signatures for each channel.
func NewAntiSpoofValidatorWithSecrets(secrets SignatureSecrets) *DefaultAntiSpoofValidator {
	return &DefaultAntiSpoofValidator{secrets: secrets}
}

// antiSpoofMaxClockSkewMs is the maximum tolerated age of an inbound message timestamp.
// Messages older than this are rejected to prevent replay attacks.
const antiSpoofMaxClockSkewMs = 5 * 60 * 1000 // 5 minutes

// Validate performs structural and temporal anti-spoofing checks on env.
//
// Checks performed:
//  1. EnvelopeID is non-empty.
//  2. SenderID is non-empty.
//  3. ReceivedAtUnixMs is plausible (not in the future, not too old).
//  4. Channel-specific placeholder check.
func (v *DefaultAntiSpoofValidator) Validate(_ context.Context, env ChannelEnvelope) (*AntiSpoofResult, error) {
	fail := func(reason string) (*AntiSpoofResult, error) {
		return &AntiSpoofResult{
			Passed:      false,
			SenderTrust: SenderTrustSuspicious,
			Reason:      reason,
		}, nil
	}

	// Check 1: envelope identity.
	if env.EnvelopeID == "" {
		return fail("envelope_id is empty")
	}

	// Check 2: sender identity.
	if env.SenderID == "" {
		return fail("sender_id is empty")
	}

	// Check 3: timestamp plausibility.
	if env.ReceivedAtUnixMs <= 0 {
		return fail("received_at_unix_ms is not a valid positive timestamp")
	}
	nowMs := time.Now().UnixMilli()
	if env.ReceivedAtUnixMs > nowMs+1000 {
		// Allow 1 s of clock drift for messages slightly in the future.
		return fail(fmt.Sprintf(
			"received_at_unix_ms %d is in the future (now %d)", env.ReceivedAtUnixMs, nowMs,
		))
	}
	age := nowMs - env.ReceivedAtUnixMs
	if age > antiSpoofMaxClockSkewMs {
		return fail(fmt.Sprintf(
			"received_at_unix_ms %d is too old (%dms ago, max %dms)", env.ReceivedAtUnixMs, age, antiSpoofMaxClockSkewMs,
		))
	}

	// Check 4: channel-specific placeholder.
	// Each channel may extend this with signature or HMAC verification.
	if err := channelSpecificCheck(env, v.secrets); err != nil {
		return fail(fmt.Sprintf("channel-specific check failed: %s", err.Error()))
	}

	// Preserve the trust class provided by the adapter; default to unknown.
	trust := env.SenderTrust
	if trust == "" {
		trust = SenderTrustUnknown
	}

	return &AntiSpoofResult{
		Passed:      true,
		SenderTrust: trust,
		Reason:      "all checks passed",
	}, nil
}

// channelSpecificCheck verifies per-channel cryptographic signatures.
// It delegates to the appropriate ChannelSignatureVerifier based on the channel kind.
func channelSpecificCheck(env ChannelEnvelope, secrets SignatureSecrets) error {
	if !ValidChannelKind(env.Channel) {
		return fmt.Errorf("unknown channel %q", env.Channel)
	}
	verifier := NewSignatureVerifier(env.Channel, secrets)
	return verifier.Verify(env)
}
