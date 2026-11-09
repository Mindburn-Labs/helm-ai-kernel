package custody

// quantum_posture: provider API keys are opaque bearer strings read from
// mounted files; nothing here signs, verifies or negotiates a key exchange,
// and no post-quantum claim is made.

import (
	"context"
	"errors"
	"fmt"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/adapters"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/effectargs"
)

// TokenSource is the gateway's connection custody for one family of effects:
// admission.Credentials, which this package cannot import.
type TokenSource interface {
	Token(ctx context.Context, tenantID string, effect adapters.Effect) (string, error)
}

// SandboxKeys is the connection custody of the sandbox effects (target
// architecture §9.6, R8): the key of the sandbox provider a sandbox effect
// targets, from the key file the operator mounted into the gateway Pod only.
// The sandbox adapter asks for it on every operation and keeps nothing; no
// key is ever put in an effect's arguments or reaches a sandbox.
//
// The keys are the gateway's own provider accounts, shared by tenants. What
// keeps a tenant to its own sandboxes is the tenant label the adapter puts on
// every sandbox it creates and checks before it acts on one.
type SandboxKeys struct {
	keys *ProviderKeys
}

// NewSandboxKeys reads the key file of every provider (provider name to path).
// A gateway with only keyless providers (Docker) passes none.
func NewSandboxKeys(files map[string]string) (*SandboxKeys, error) {
	if len(files) == 0 {
		return &SandboxKeys{}, nil
	}
	keys, err := NewProviderKeys(files)
	if err != nil {
		return nil, err
	}
	return &SandboxKeys{keys: keys}, nil
}

// Token returns the provider key for a sandbox effect. The provider comes
// from the effect's target. An error means there is none, and the adapter
// answers NOT_SENT.
func (s *SandboxKeys) Token(ctx context.Context, _ string, effect adapters.Effect) (string, error) {
	provider, _, err := effectargs.SandboxTarget(effect.EffectType, effect.Target)
	if err != nil {
		return "", err
	}
	if s == nil || s.keys == nil {
		return "", fmt.Errorf("%w: %q is not configured", ErrNoProviderKey, provider)
	}
	return s.keys.Key(ctx, provider)
}

// Route sends a sandbox effect's credential request to the sandbox custody
// and every other effect's to Rest (the GitHub App).
type Route struct {
	Sandbox TokenSource
	Rest    TokenSource
}

// Token implements admission.Credentials.
func (r Route) Token(ctx context.Context, tenantID string, effect adapters.Effect) (string, error) {
	if effectargs.IsSandboxEffect(effect.EffectType) {
		if r.Sandbox == nil {
			return "", errors.New("the gateway has no sandbox credentials configured")
		}
		return r.Sandbox.Token(ctx, tenantID, effect)
	}
	if r.Rest == nil {
		return "", errors.New("the gateway has no provider credentials configured")
	}
	return r.Rest.Token(ctx, tenantID, effect)
}
