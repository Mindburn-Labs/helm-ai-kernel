package modelgw

import (
	"context"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/adapters"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/admission"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/effectargs"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/server"
)

var (
	_ Ledger        = (*admission.Service)(nil)
	_ Authenticator = (*server.Authenticator)(nil)
)

// Adapter declares model.inference to the effect gateway (adapters, target
// architecture §9.1) so that the effect type is in its catalog, its risk class
// is the adapter's and a call left UNKNOWN is reconciled like any other.
//
// It performs nothing: a model call is dispatched by the model gateway's own
// endpoints, in the request that proposes it, because the response streams
// back to the caller. A Dispatch through the RPC is refused before any provider
// call (NOT_SENT), and a read-back is inconclusive: the provider offers no way
// to ask what a chat call generated, so a call whose fate is unknown keeps its
// hold as an estimate until an operator resolves it.
type Adapter struct{}

// NewAdapter returns the model.inference declaration.
func NewAdapter() *Adapter { return &Adapter{} }

// Declarations lists model.inference: a low-risk effect that writes nothing
// outside the provider, whose repeat is conditional on the stored response, and
// that is enforced because the only credential is the gateway's (R8).
func (Adapter) Declarations() []adapters.Declaration {
	return []adapters.Declaration{{
		EffectType: effectargs.ModelInference,
		RiskClass:  adapters.RiskLow,
		Idempotent: adapters.IdempotentConditional,
		Observable: adapters.ObservablePartial,
		Reversible: adapters.ReversibleNotApplicable,
		Mediation:  adapters.MediationEnforced,
		Notes: "One call to a model API, priced at its worst case and settled from the usage the provider reports. " +
			"Dispatched by the model gateway's inference endpoints; a repeat in the same episode replays the stored response.",
	}}
}

// Prepare refuses: the model gateway prices a call itself.
func (Adapter) Prepare(context.Context, adapters.TokenSource, adapters.Effect) (*adapters.Preparation, error) {
	return nil, adapters.Refuse(contracts.ReasonPreconditionFailed, "a model call is prepared by the model gateway's inference endpoint")
}

// Dispatch never sends: a model call is dispatched where its response can
// stream back.
func (Adapter) Dispatch(context.Context, adapters.TokenSource, adapters.Effect, []byte) adapters.DispatchResult {
	return adapters.DispatchResult{Status: adapters.DispatchNotSent, Reason: contracts.ReasonPreconditionFailed,
		Detail: "a model call is dispatched by the model gateway's inference endpoint, in the request that proposes it"}
}

// Observe is inconclusive.
func (Adapter) Observe(context.Context, adapters.TokenSource, adapters.Effect) adapters.ObserveResult {
	return adapters.ObserveResult{Outcome: adapters.OutcomeUnknown, Reason: contracts.ReasonProviderError,
		Detail: "a provider cannot be asked what a model call generated"}
}
