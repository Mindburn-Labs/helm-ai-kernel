package sandbox

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
)

// MaxConfigBytes bounds the provider configuration file.
const MaxConfigBytes = 64 << 10

// Config is the operator's provider configuration (the file the gateway names
// in HELM_GATEWAY_SANDBOX_CONFIG_FILE). It holds settings and the path of each
// provider's key file, never a key: the key stays in the file the chart mounts
// into the gateway Pod only (R8), and custody reads it per call. A provider
// that is not listed is off.
type Config struct {
	Providers []ProviderConfig `json:"providers"`
}

// ProviderConfig is one provider's settings. A field that does not belong to
// the provider is refused.
type ProviderConfig struct {
	Provider string `json:"provider"`
	// KeyFile is the file that holds the provider's API key (or, for Claude
	// Managed Agents, the bearer token of the customer's worker). Docker has
	// none.
	KeyFile string `json:"key_file,omitempty"`

	// E2B.
	APIURL                string `json:"api_url,omitempty"`
	TemplateID            string `json:"template_id,omitempty"`
	DefaultTimeoutSeconds int    `json:"default_timeout_seconds,omitempty"`

	// Daytona and OpenSandbox.
	BaseURL         string `json:"base_url,omitempty"`
	DefaultLanguage string `json:"default_language,omitempty"`

	// OpenSandbox. Both default to true; the adapter's preflight refuses a
	// server that is not strict.
	TLSRequired      *bool `json:"tls_required,omitempty"`
	EgressStrictMode *bool `json:"egress_strict_mode,omitempty"`

	// Docker.
	DockerBin    string `json:"docker_bin,omitempty"`
	DockerSocket string `json:"docker_socket,omitempty"`

	// ManagedAgents is Claude Managed Agents' claudemanaged.Config (its
	// remote_endpoint is the customer's worker).
	ManagedAgents json.RawMessage `json:"managed_agents,omitempty"`
}

// ParseConfig reads and validates a configuration. It refuses unknown fields,
// an empty list, a provider twice and a field that does not belong.
func ParseConfig(raw []byte) (Config, error) {
	var c Config
	if len(raw) == 0 || len(raw) > MaxConfigBytes {
		return c, fmt.Errorf("the sandbox configuration must be 1 to %d bytes", MaxConfigBytes)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return c, fmt.Errorf("the sandbox configuration: %w", err)
	}
	if dec.More() {
		return c, errors.New("the sandbox configuration holds more than one JSON value")
	}
	if len(c.Providers) == 0 {
		return c, errors.New("the sandbox configuration lists no provider")
	}
	seen := map[string]bool{}
	for i, p := range c.Providers {
		if seen[p.Provider] {
			return c, fmt.Errorf("providers[%d]: %q is listed twice", i, p.Provider)
		}
		seen[p.Provider] = true
		if err := p.validate(); err != nil {
			return c, fmt.Errorf("providers[%d] (%s): %w", i, p.Provider, err)
		}
	}
	return c, nil
}

func (p ProviderConfig) validate() error {
	stray := func(set bool, name string) error {
		if set {
			return fmt.Errorf("%s does not belong to this provider", name)
		}
		return nil
	}
	e2bFields := p.APIURL != "" || p.TemplateID != "" || p.DefaultTimeoutSeconds != 0
	baseFields := p.BaseURL != "" || p.DefaultLanguage != ""
	osFields := p.TLSRequired != nil || p.EgressStrictMode != nil
	dockerFields := p.DockerBin != "" || p.DockerSocket != ""
	managed := len(p.ManagedAgents) != 0
	var errs []error
	need := func(v, name string) {
		if v == "" {
			errs = append(errs, fmt.Errorf("%s is required", name))
		}
	}
	switch p.Provider {
	case "e2b":
		need(p.KeyFile, "key_file")
		errs = append(errs, stray(baseFields, "base_url or default_language"), stray(osFields, "tls_required or egress_strict_mode"),
			stray(dockerFields, "docker_bin or docker_socket"), stray(managed, "managed_agents"))
	case "daytona":
		need(p.KeyFile, "key_file")
		need(p.BaseURL, "base_url")
		errs = append(errs, stray(e2bFields, "api_url, template_id or default_timeout_seconds"), stray(osFields, "tls_required or egress_strict_mode"),
			stray(dockerFields, "docker_bin or docker_socket"), stray(managed, "managed_agents"))
	case "opensandbox":
		need(p.KeyFile, "key_file")
		need(p.BaseURL, "base_url")
		errs = append(errs, stray(e2bFields, "api_url, template_id or default_timeout_seconds"), stray(p.DefaultLanguage != "", "default_language"),
			stray(dockerFields, "docker_bin or docker_socket"), stray(managed, "managed_agents"))
	case "docker":
		errs = append(errs, stray(p.KeyFile != "", "key_file: a local provider takes no credential"), stray(e2bFields, "api_url, template_id or default_timeout_seconds"),
			stray(baseFields, "base_url or default_language"), stray(osFields, "tls_required or egress_strict_mode"), stray(managed, "managed_agents"))
	case "claude-managed-agents":
		need(p.KeyFile, "key_file")
		if !managed {
			errs = append(errs, errors.New("managed_agents is required"))
		}
		errs = append(errs, stray(e2bFields, "api_url, template_id or default_timeout_seconds"), stray(baseFields, "base_url or default_language"),
			stray(osFields, "tls_required or egress_strict_mode"), stray(dockerFields, "docker_bin or docker_socket"))
	default:
		return fmt.Errorf("%q is not a sandbox provider", p.Provider)
	}
	return errors.Join(errs...)
}

// KeyFiles maps each provider that takes a key to its key file, for the
// gateway's connection custody.
func (c Config) KeyFiles() map[string]string {
	out := map[string]string{}
	for _, p := range c.Providers {
		if p.KeyFile != "" {
			out[p.Provider] = p.KeyFile
		}
	}
	return out
}
