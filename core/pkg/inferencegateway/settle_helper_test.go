package inferencegateway

import "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts/economic"

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
