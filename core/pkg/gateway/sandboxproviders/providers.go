// Package sandboxproviders builds helm-gateway's sandbox backends: it joins the
// sandbox adapter (core/pkg/gateway/adapters/sandbox) to the provider adapters
// under core/pkg/connectors/sandbox and core/pkg/sandbox/docker.
//
// The join is a package of its own, outside core/pkg/gateway/adapters, because
// that tree must not depend on the legacy connector packages (CTL-051): the
// adapter reads a provider through the actuators.Provider contract alone, and
// only this composition knows which provider adapters exist.
package sandboxproviders

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/connectors/sandbox/claudemanaged"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/connectors/sandbox/daytona"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/connectors/sandbox/e2b"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/connectors/sandbox/opensandbox"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts/actuators"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/adapters/sandbox"
	dockersandbox "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/sandbox/docker"
)

// BuildOptions are what a composition supplies besides the configuration.
type BuildOptions struct {
	// HTTPClient replaces the providers' default client, for tests.
	HTTPClient *http.Client
	// ManagedSigner signs Claude Managed Agents' execution receipts. The
	// gateway passes its own receipt signer, so there is one key (R4).
	ManagedSigner claudemanaged.ManagedAgentReceiptSigner
	Clock         func() time.Time
}

var cloudRuntime = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,255}$`)
var pinnedImage = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/+-]{0,200}@sha256:[0-9a-f]{64}$`)

func cloudValidate(runtime string) error {
	if !cloudRuntime.MatchString(runtime) {
		return errors.New("not a template id")
	}
	return nil
}

// Build turns a configuration into backends.
func Build(c sandbox.Config, o BuildOptions) ([]sandbox.Backend, error) {
	var out []sandbox.Backend
	for _, p := range c.Providers {
		b, err := buildOne(p, o)
		if err != nil {
			return nil, fmt.Errorf("provider %s: %w", p.Provider, err)
		}
		out = append(out, b)
	}
	return out, nil
}

func buildOne(p sandbox.ProviderConfig, o BuildOptions) (sandbox.Backend, error) {
	switch p.Provider {
	case "e2b":
		cfg := e2b.DefaultConfig()
		if p.APIURL != "" {
			cfg.APIURL = p.APIURL
		}
		cfg.TemplateID = p.TemplateID
		if p.DefaultTimeoutSeconds > 0 {
			cfg.DefaultTimeout = time.Duration(p.DefaultTimeoutSeconds) * time.Second
		}
		return sandbox.Backend{Name: p.Provider, NeedsKey: true, ValidateRuntime: cloudValidate,
			Open: func(ctx context.Context, token string) (actuators.Provider, context.Context, error) {
				c := cfg
				c.APIKey = token
				a := e2b.New(c)
				if o.HTTPClient != nil {
					a = a.WithHTTPClient(o.HTTPClient)
				}
				return a, ctx, nil
			}}, nil
	case "daytona":
		cfg := daytona.DefaultConfig()
		cfg.BaseURL = p.BaseURL
		if p.DefaultLanguage != "" {
			cfg.DefaultLanguage = p.DefaultLanguage
		}
		return sandbox.Backend{Name: p.Provider, NeedsKey: true, ValidateRuntime: cloudValidate,
			Open: func(ctx context.Context, token string) (actuators.Provider, context.Context, error) {
				c := cfg
				c.APIKey = token
				a := daytona.New(c)
				if o.HTTPClient != nil {
					a = a.WithHTTPClient(o.HTTPClient)
				}
				return a, ctx, nil
			}}, nil
	case "opensandbox":
		cfg := opensandbox.DefaultConfig()
		cfg.BaseURL = p.BaseURL
		if p.TLSRequired != nil {
			cfg.TLSRequired = *p.TLSRequired
		}
		if p.EgressStrictMode != nil {
			cfg.EgressStrictMode = *p.EgressStrictMode
		}
		return sandbox.Backend{Name: p.Provider, NeedsKey: true, ValidateRuntime: cloudValidate,
			Open: func(ctx context.Context, token string) (actuators.Provider, context.Context, error) {
				c := cfg
				c.APIKey = token
				a := opensandbox.New(c)
				if o.HTTPClient != nil {
					a = a.WithHTTPClient(o.HTTPClient)
				}
				return a, ctx, nil
			}}, nil
	case "docker":
		cfg := dockersandbox.DefaultSandboxesConfig()
		if p.DockerBin != "" {
			cfg.DockerBin = p.DockerBin
		}
		cfg.DockerSocket = p.DockerSocket
		provider := dockersandbox.NewProvider(cfg)
		return sandbox.Backend{Name: p.Provider, CompareRuntime: true,
			ValidateRuntime: func(runtime string) error {
				if !pinnedImage.MatchString(runtime) {
					return errors.New("a Docker runtime must be an image pinned by digest (name@sha256:<64 hex>)")
				}
				return nil
			},
			Open: func(ctx context.Context, _ string) (actuators.Provider, context.Context, error) {
				return provider, ctx, nil
			}}, nil
	case "claude-managed-agents":
		cfg := claudemanaged.DefaultConfig()
		dec := json.NewDecoder(bytes.NewReader(p.ManagedAgents))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&cfg); err != nil {
			return sandbox.Backend{}, fmt.Errorf("managed_agents: %w", err)
		}
		if o.ManagedSigner == nil {
			return sandbox.Backend{}, errors.New("a managed-agent receipt signer is required")
		}
		runner, err := claudemanaged.NewRemoteRunner(cfg.RemoteEndpoint, o.HTTPClient)
		if err != nil {
			return sandbox.Backend{}, err
		}
		hosted, err := claudemanaged.NewHosted(cfg, runner, o.ManagedSigner, o.Clock)
		if err != nil {
			return sandbox.Backend{}, err
		}
		return sandbox.Backend{Name: p.Provider, NeedsKey: true, ValidateRuntime: cloudValidate,
			Open: func(ctx context.Context, token string) (actuators.Provider, context.Context, error) {
				return hosted, claudemanaged.ContextWithToken(ctx, token), nil
			}}, nil
	}
	return sandbox.Backend{}, fmt.Errorf("%q is not a sandbox provider", p.Provider)
}
