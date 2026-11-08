package runtime

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/adapters/sandbox"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/admission"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/custody"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/sandboxproviders"
)

// envSandboxConfigFile names the sandbox provider configuration. Unset, no
// sandbox effect type exists on the gateway: every provider is off until an
// operator lists it.
const envSandboxConfigFile = "HELM_GATEWAY_SANDBOX_CONFIG_FILE"

// managedSigner lets Claude Managed Agents' execution receipts be signed with
// the gateway's own receipt key: one key, one signing envelope (R4).
type managedSigner struct {
	signer interface {
		Sign(data []byte) (string, error)
		GetKeyID() string
	}
}

func (m managedSigner) Sign(data []byte) (string, error) { return m.signer.Sign(data) }
func (m managedSigner) SignerKeyID() string              { return m.signer.GetKeyID() }

// sandboxFromEnv wires the sandbox effects (P17). The providers it enables,
// and the path of each provider's key file, come from the configuration file;
// the keys themselves are read per call by the gateway's custody and reach
// neither a sandbox nor an effect's arguments.
func sandboxFromEnv(getenv func(string) string, c *admission.Config) error {
	path := strings.TrimSpace(getenv(envSandboxConfigFile))
	if path == "" {
		slog.Info("no sandbox provider is configured; the sandbox effect types are off", "set", envSandboxConfigFile)
		return nil
	}
	raw, err := readBounded(path, sandbox.MaxConfigBytes)
	if err != nil {
		return fmt.Errorf("%s: %w", envSandboxConfigFile, err)
	}
	config, err := sandbox.ParseConfig(raw)
	if err != nil {
		return fmt.Errorf("%s: %w", envSandboxConfigFile, err)
	}
	keys, err := custody.NewSandboxKeys(config.KeyFiles())
	if err != nil {
		return fmt.Errorf("sandbox provider keys: %w", err)
	}
	options := sandboxproviders.BuildOptions{}
	if signer, ok := c.ReceiptSigner.(interface {
		Sign(data []byte) (string, error)
		GetKeyID() string
	}); ok {
		options.ManagedSigner = managedSigner{signer: signer}
	}
	backends, err := sandboxproviders.Build(config, options)
	if err != nil {
		return fmt.Errorf("sandbox providers: %w", err)
	}
	adapter, err := sandbox.New(backends)
	if err != nil {
		return err
	}
	c.Adapters = append(c.Adapters, adapter)
	// Sandbox effects take their key from the sandbox custody; everything
	// else keeps the credentials it had (the GitHub App, or none).
	c.Credentials = custody.Route{Sandbox: keys, Rest: c.Credentials}
	slog.Info("sandbox providers enabled", "providers", adapter.Providers())
	return nil
}

func readBounded(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path) // #nosec G304 -- operator-supplied configuration mount path
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	raw, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > limit {
		return nil, fmt.Errorf("the file is larger than %d bytes", limit)
	}
	return raw, nil
}

// withoutSandboxRoute returns the credentials the sandbox route wraps: the
// GitHub activity trail asks for GitHub tokens only, and must still see "no
// GitHub App" as no credentials.
func withoutSandboxRoute(c admission.Credentials) admission.Credentials {
	route, ok := c.(custody.Route)
	if !ok {
		return c
	}
	if rest, ok := route.Rest.(admission.Credentials); ok && rest != nil {
		return rest
	}
	return nil
}
