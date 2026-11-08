// Package sandbox is the sandbox effect adapter of helm-gateway (P17): the
// effects sandbox.create, sandbox.exec and sandbox.terminate, performed through
// one of the configured sandbox providers (Docker, E2B, Daytona, OpenSandbox,
// Claude Managed Agents).
//
// One adapter serves every provider. A provider is a Backend: a constructor of
// a actuators.Provider (the provider's SandboxActuator plus its Inventory
// read side) bound to one call's credential. The provider and the sandbox come
// only from the effect's target, never from its arguments (09-02):
//
//	sandbox.create     sandbox/{provider}
//	sandbox.exec       sandbox/{provider}/{sandbox_id}
//	sandbox.terminate  sandbox/{provider}/{sandbox_id}
//
// What the adapter guarantees:
//
//   - R8: it holds no credential. It asks the gateway's connection custody for
//     the provider key on every operation (TokenSource), builds the provider
//     client with it for that operation and drops both. Effect arguments carry
//     no environment and no secret; a command runs with the sandbox's own
//     environment only.
//   - R9: every sandbox the gateway creates carries a label with a digest of
//     the creating tenant, and exec and terminate act only on a sandbox that
//     carries the caller's own. A sandbox the gateway did not create, or one of
//     another tenant, is refused like one that does not exist.
//   - R6: a dispatch is never retried. Create looks for a sandbox carrying its
//     attempt label first and does not create a second; exec leaves a record in
//     the sandbox and does not start twice.
//   - 09-01: Dispatch compares the permit's argument digest with the bytes it
//     acts on before any provider call.
//   - NOT_SENT only when the effect certainly did not happen (a refusal before
//     any write, or a provider's 4xx to the write); everything else after a
//     write is INDEFINITE, and Observe reconciles by reading the provider back
//     (create, terminate: the provider's inventory; exec: the record the
//     command left in the sandbox).
//   - A provider answer of the wrong shape or size is
//     ERR_CONNECTOR_CONTRACT_DRIFT / PROVIDER_RESPONSE_TOO_LARGE, and an
//     established result is a schema-checked artifact (admission.typedResult).
//
// Cloud providers are off unless the operator configures them (config.go).
// The wire shapes of E2B, Daytona and OpenSandbox are proven here only against
// fake provider servers: no provider account exists.
//
// This package must not import the legacy runtime (guardian, proxy, mcp,
// executor); the gateway is Zone C.
package sandbox

// quantum_posture: labels bind a SHA-256 digest of the tenant id; nothing here
// signs or verifies, and no post-quantum claim is made.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts/actuators"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/adapters"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/effectargs"
)

// AdapterVersion is the version qualification records name.
const AdapterVersion = "1.0.0"

// The effect types this adapter performs.
const (
	EffectCreate    = effectargs.SandboxCreate
	EffectExec      = effectargs.SandboxExec
	EffectTerminate = effectargs.SandboxTerminate
)

const (
	observationSource = "sandbox.provider.readback"
	// trustProvider: the provider's own inventory answered.
	trustProvider = "provider_readback"
	// trustSandbox: the sandbox's own record of the command answered.
	trustSandbox = "sandbox_reported"
)

// Backend is one configured provider.
type Backend struct {
	// Name is the provider's target segment, one of effectargs.SandboxProviders.
	Name string
	// NeedsKey is whether the provider takes a credential from the gateway's
	// custody. A local provider (Docker) takes none.
	NeedsKey bool
	// Open binds the provider to one call's credential. It returns the
	// context the provider calls must use (a provider that carries the
	// credential in its context returns a derived one). The provider and the
	// credential are used for that operation only.
	Open func(ctx context.Context, token string) (actuators.Provider, context.Context, error)
	// ValidateRuntime checks a create's runtime (a template id or an image).
	ValidateRuntime func(runtime string) error
	// CompareRuntime is whether the runtime the provider reports must equal
	// the requested one (an image reference does; a template alias need not
	// equal the template id a provider reports).
	CompareRuntime bool
}

// Adapter is the sandbox effect adapter. It holds no credential.
type Adapter struct {
	backends map[string]Backend
	now      func() time.Time
}

// New builds an adapter over the configured backends. It refuses none, a
// backend of an unknown provider, a repeated one and one that cannot open.
func New(backends []Backend) (*Adapter, error) {
	if len(backends) == 0 {
		return nil, errors.New("sandbox adapter: no provider is configured")
	}
	a := &Adapter{backends: map[string]Backend{}, now: time.Now}
	for _, b := range backends {
		known := false
		for _, p := range effectargs.SandboxProviders {
			known = known || p == b.Name
		}
		switch {
		case !known:
			return nil, fmt.Errorf("sandbox adapter: %q is not a sandbox provider", b.Name)
		case b.Open == nil || b.ValidateRuntime == nil:
			return nil, fmt.Errorf("sandbox adapter: provider %q has no constructor", b.Name)
		}
		if _, dup := a.backends[b.Name]; dup {
			return nil, fmt.Errorf("sandbox adapter: provider %q is configured twice", b.Name)
		}
		a.backends[b.Name] = b
	}
	return a, nil
}

var _ adapters.Adapter = (*Adapter)(nil)

// Providers lists the configured providers, sorted.
func (a *Adapter) Providers() []string {
	out := make([]string, 0, len(a.backends))
	for name := range a.backends {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

func (a *Adapter) declarations() []adapters.Declaration {
	providers := a.Providers()
	configured := fmt.Sprintf("Providers configured on this gateway: %v.", providers)
	return []adapters.Declaration{
		{
			EffectType: EffectCreate,
			RiskClass:  adapters.RiskMedium, Idempotent: adapters.IdempotentConditional,
			Observable: adapters.ObservableYes, Reversible: adapters.ReversibleYes,
			Mediation: adapters.MediationEnforced, Grantable: true,
			Quote:      []adapters.Amount{{Unit: "count", Amount: 1}},
			TargetForm: "sandbox/{provider}", ArgumentSchema: []byte(createArgumentSchema),
			ResultSchemaID: createResultID, ResultSchema: []byte(createResultSchema),
			Description: "Creates a sandbox on a configured provider, labelled with the creating tenant and attempt.",
			Notes: "Dispatch looks for a sandbox carrying the attempt's label first and never creates a second. The read-back " +
				"finds the sandbox by that label and checks it is running (and its runtime, where the provider reports one). " +
				"Terminating it reverses it. " + configured,
		},
		{
			EffectType: EffectExec,
			RiskClass:  adapters.RiskHigh, Idempotent: adapters.IdempotentConditional,
			Observable: adapters.ObservablePartial, Reversible: adapters.ReversibleNo,
			Mediation: adapters.MediationEnforced, Grantable: true,
			Quote:      []adapters.Amount{{Unit: "count", Amount: 1}},
			TargetForm: "sandbox/{provider}/{sandbox_id}", ArgumentSchema: []byte(execArgumentSchema),
			ResultSchemaID: execResultID, ResultSchema: []byte(execResultSchema),
			Description: "Runs one command, given as an argument vector, in a sandbox this tenant created. The command runs with the sandbox's own environment: no environment or secret is passed.",
			Notes: "The command runs under a fixed wrapper that records its start, output and exit status in the sandbox, and does " +
				"not start twice for one attempt. The read-back reads that record: it is the sandbox's own account, so its trust " +
				"class is sandbox_reported, and a sandbox that is gone leaves the outcome UNKNOWN. The result carries the exit " +
				"code, output sizes and bounded excerpts, not the complete output. " + configured,
		},
		{
			EffectType: EffectTerminate,
			RiskClass:  adapters.RiskLow, Idempotent: adapters.IdempotentYes,
			Observable: adapters.ObservableYes, Reversible: adapters.ReversibleNo,
			Mediation: adapters.MediationEnforced, Grantable: true,
			TargetForm: "sandbox/{provider}/{sandbox_id}", ArgumentSchema: []byte(terminateArgumentSchema),
			ResultSchemaID: terminateResultID, ResultSchema: []byte(terminateResultSchema),
			Description: "Terminates a sandbox this tenant created.",
			Notes: "The read-back asks the provider for the sandbox: gone or terminated is SUCCEEDED; still running is " +
				"UNKNOWN, since a provider may take time to stop it. " + configured,
		},
	}
}

// Declarations implements adapters.Adapter.
func (a *Adapter) Declarations() []adapters.Declaration { return a.declarations() }

func (a *Adapter) declaration(effectType string) (adapters.Declaration, bool) {
	for _, d := range a.declarations() {
		if d.EffectType == effectType {
			return d, true
		}
	}
	return adapters.Declaration{}, false
}

// op is one operation's resolved context.
type op struct {
	backend  Backend
	provider actuators.Provider
	ctx      context.Context
	name     string // provider name
	id       string // sandbox id, "" for create
	tenant   string // label value
	attempt  string // label value
	hasScope bool   // the effect carries an invocation
}

var attemptLabelPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

// tenantLabel is the label value that binds a sandbox to a tenant.
func tenantLabel(tenantID string) string {
	sum := sha256.Sum256([]byte("helm.sandbox.tenant.v1\x00" + tenantID))
	return hex.EncodeToString(sum[:16])
}

func (o *op) labels() map[string]string {
	return map[string]string{actuators.LabelTenant: o.tenant, actuators.LabelAttempt: o.attempt}
}

// resolve parses the target and the invocation and opens the provider with the
// custody's credential for this operation.
func (a *Adapter) resolve(ctx context.Context, creds adapters.TokenSource, effect adapters.Effect, needScope bool) (*op, *adapters.Refusal) {
	provider, id, err := effectargs.SandboxTarget(effect.EffectType, effect.Target)
	if err != nil {
		return nil, schemaViolation("%v", err)
	}
	backend, ok := a.backends[provider]
	if !ok {
		return nil, adapters.Refuse(contracts.ReasonPreconditionFailed, "sandbox provider %q is not configured on this gateway", provider)
	}
	o := &op{backend: backend, name: provider, id: id}
	if inv := effect.Invocation; inv != nil {
		if inv.TenantID == "" || !attemptLabelPattern.MatchString(inv.AttemptID) {
			return nil, adapters.Refuse(contracts.ReasonPreconditionFailed, "the invocation names no tenant or no attempt")
		}
		o.tenant, o.attempt, o.hasScope = tenantLabel(inv.TenantID), inv.AttemptID, true
	} else if needScope {
		return nil, adapters.Refuse(contracts.ReasonPreconditionFailed, "a sandbox effect runs only under a gateway invocation")
	}
	token := ""
	if backend.NeedsKey {
		if creds == nil {
			return nil, adapters.Refuse(contracts.ReasonProviderCredentialRejected, "no credential source")
		}
		token, err = creds.Token(ctx)
		if err != nil || token == "" {
			return nil, adapters.Refuse(contracts.ReasonProviderCredentialRejected, "the credential source returned no key for %s", provider)
		}
	}
	p, pctx, err := backend.Open(ctx, token)
	if err != nil || p == nil {
		return nil, adapters.Refuse(contracts.ReasonProviderError, "opening the %s provider: %s", provider, describe(err))
	}
	if pctx == nil {
		pctx = ctx
	}
	o.provider, o.ctx = p, pctx
	return o, nil
}

// owned looks the sandbox up and refuses one that is not this tenant's. A
// sandbox another tenant created, or one the gateway did not create, is refused
// exactly like one that does not exist.
func (o *op) owned() (*actuators.Info, *adapters.Refusal) {
	info, err := o.provider.Lookup(o.ctx, o.id)
	switch {
	case errors.Is(err, actuators.ErrSandboxNotFound):
		return nil, adapters.Refuse(contracts.ReasonPreconditionFailed, "no sandbox %s on %s", o.id, o.name)
	case err != nil:
		return nil, providerRefusal(err)
	case info == nil || info.ID != o.id:
		return nil, adapters.Refuse(contracts.ReasonConnectorContractDrift, "the provider answered for another sandbox than %s", o.id)
	case !o.hasScope || info.Labels[actuators.LabelTenant] != o.tenant:
		return nil, adapters.Refuse(contracts.ReasonPreconditionFailed, "no sandbox %s on %s", o.id, o.name)
	}
	return info, nil
}

// Prepare implements adapters.Adapter: it validates the effect and reads the
// sandbox, and changes nothing.
func (a *Adapter) Prepare(ctx context.Context, creds adapters.TokenSource, effect adapters.Effect) (*adapters.Preparation, error) {
	decl, ok := a.declaration(effect.EffectType)
	if !ok {
		return nil, schemaViolation("effect type %q is not a sandbox effect", effect.EffectType)
	}
	var runtime string
	switch effect.EffectType {
	case EffectCreate:
		args, r := parseCreate(effect.Arguments)
		if r != nil {
			return nil, r
		}
		runtime = args.Runtime
	case EffectExec:
		if _, r := parseExec(effect.Arguments); r != nil {
			return nil, r
		}
	default:
		if _, r := parseTerminate(effect.Arguments); r != nil {
			return nil, r
		}
	}
	o, r := a.resolve(ctx, creds, effect, false)
	if r != nil {
		return nil, r
	}
	if effect.EffectType == EffectCreate {
		if err := o.backend.ValidateRuntime(runtime); err != nil {
			return nil, adapters.Refuse(contracts.ReasonPreconditionFailed, "runtime: %s", describe(err))
		}
	} else if o.hasScope {
		if _, r := o.owned(); r != nil {
			return nil, r
		}
	}
	return &adapters.Preparation{Declaration: decl, Target: effect.Target, Quote: append([]adapters.Amount(nil), decl.Quote...),
		Resolved: map[string]string{"provider": o.name}}, nil
}

// Dispatch implements adapters.Adapter.
func (a *Adapter) Dispatch(ctx context.Context, creds adapters.TokenSource, effect adapters.Effect, permitArgumentDigest []byte) adapters.DispatchResult {
	if r := adapters.CheckPermitDigest(effect.Arguments, permitArgumentDigest); r != nil {
		return notSent(r)
	}
	switch effect.EffectType {
	case EffectCreate:
		args, r := parseCreate(effect.Arguments)
		if r != nil {
			return notSent(r)
		}
		o, r := a.resolve(ctx, creds, effect, true)
		if r != nil {
			return notSent(r)
		}
		return o.dispatchCreate(args)
	case EffectExec:
		args, r := parseExec(effect.Arguments)
		if r != nil {
			return notSent(r)
		}
		o, r := a.resolve(ctx, creds, effect, true)
		if r != nil {
			return notSent(r)
		}
		return o.dispatchExec(args)
	case EffectTerminate:
		if _, r := parseTerminate(effect.Arguments); r != nil {
			return notSent(r)
		}
		o, r := a.resolve(ctx, creds, effect, true)
		if r != nil {
			return notSent(r)
		}
		return o.dispatchTerminate()
	}
	return notSent(schemaViolation("effect type %q is not a sandbox effect", effect.EffectType))
}

// Observe implements adapters.Adapter.
func (a *Adapter) Observe(ctx context.Context, creds adapters.TokenSource, effect adapters.Effect) adapters.ObserveResult {
	switch effect.EffectType {
	case EffectCreate:
		args, r := parseCreate(effect.Arguments)
		if r != nil {
			return unknown(r)
		}
		o, r := a.resolve(ctx, creds, effect, true)
		if r != nil {
			return unknown(r)
		}
		return o.observeCreate(a, args)
	case EffectExec:
		args, r := parseExec(effect.Arguments)
		if r != nil {
			return unknown(r)
		}
		o, r := a.resolve(ctx, creds, effect, true)
		if r != nil {
			return unknown(r)
		}
		return o.observeExec(a, args)
	case EffectTerminate:
		if _, r := parseTerminate(effect.Arguments); r != nil {
			return unknown(r)
		}
		o, r := a.resolve(ctx, creds, effect, true)
		if r != nil {
			return unknown(r)
		}
		return o.observeTerminate(a)
	}
	return unknown(schemaViolation("effect type %q is not a sandbox effect", effect.EffectType))
}
