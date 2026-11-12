package inferencegateway

import (
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts/economic"
)

// envelopeConsumed is what env's requests have reserved and used in the window
// that contains now.
func (l *BalanceLedger) envelopeConsumed(env *economic.AgentSpendEnvelope, now time.Time) int64 {
	s := l.envelopeState(env, now)
	return addSaturating(s.reserved, s.used)
}

// Settle is the five-argument settlement the engine tests were written
// against, before SettleUsage carried notes (helm-tracker#313). Shipped code
// settles through SettleUsage and SettleAtHold.
func (e *Engine) Settle(
	quote *economic.RouteQuote,
	providerRequestID string,
	providerCostCents int64,
	actualInputTokens, actualOutputTokens int64,
) (*SettleResult, error) {
	return e.SettleUsage(quote, Usage{ProviderRequestID: providerRequestID, ProviderCostCents: providerCostCents,
		InputTokens: actualInputTokens, OutputTokens: actualOutputTokens})
}
