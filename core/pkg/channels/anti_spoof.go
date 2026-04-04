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
type DefaultAntiSpoofValidator struct{}

// NewAntiSpoofValidator returns a DefaultAntiSpoofValidator.
func NewAntiSpoofValidator() *DefaultAntiSpoofValidator {
	return &DefaultAntiSpoofValidator{}
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
	if err := channelSpecificCheck(env); err != nil {
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

// channelSpecificCheck is a placeholder for per-channel signature validation.
// Implementations should verify HMAC headers, bot tokens, or similar channel-level proofs.
func channelSpecificCheck(env ChannelEnvelope) error {
	switch env.Channel {
	case ChannelSlack:
		// TODO: verify X-Slack-Signature HMAC when SignatureRef is populated.
		return nil
	case ChannelTelegram:
		// TODO: verify Telegram bot token hash.
		return nil
	case ChannelLark:
		// TODO: verify Lark verification token.
		return nil
	case ChannelWhatsApp:
		// TODO: verify WhatsApp webhook signature.
		return nil
	case ChannelSignal:
		// TODO: verify Signal message authentication.
		return nil
	default:
		return fmt.Errorf("unknown channel %q", env.Channel)
	}
}
