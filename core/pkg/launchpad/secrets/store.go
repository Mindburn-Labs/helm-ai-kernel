package secrets

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/launchpad/modelproviders"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/launchpad/registry"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/launchpad/session"
)

type Binding struct {
	Name      string    `json:"name"`
	Provider  string    `json:"provider"`
	ValueEnv  string    `json:"value_env"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type Status struct {
	Name      string    `json:"name"`
	Provider  string    `json:"provider"`
	ValueEnv  string    `json:"value_env"`
	Available bool      `json:"available"`
	UpdatedAt time.Time `json:"updated_at"`
}

type Store struct {
	root string
}

// Resolution is a launch-scoped child environment plus redacted audit
// metadata. RuntimeEnv is intentionally excluded from JSON so callers cannot
// accidentally serialize resolved secret values in compile-only responses.
type Resolution struct {
	RuntimeEnv map[string]string             `json:"-"`
	Accesses   []session.RuntimeSecretAccess `json:"accesses,omitempty"`
}

func NewStore(root string) Store {
	if root == "" {
		root = session.DefaultRoot()
	}
	return Store{root: root}
}

func (s Store) Set(name, provider, valueEnv string) (Binding, error) {
	name = strings.TrimSpace(name)
	provider = strings.TrimSpace(provider)
	valueEnv = strings.TrimSpace(valueEnv)
	if name == "" {
		return Binding{}, errors.New("secret name is required")
	}
	if provider == "" {
		return Binding{}, errors.New("secret provider is required")
	}
	if valueEnv == "" {
		return Binding{}, errors.New("secret value env is required")
	}
	if os.Getenv(valueEnv) == "" {
		return Binding{}, fmt.Errorf("%s is not set in the current environment", valueEnv)
	}
	bindings, err := s.load()
	if err != nil {
		return Binding{}, err
	}
	now := time.Now().UTC()
	key := bindingKey(name, provider)
	binding := Binding{Name: name, Provider: provider, ValueEnv: valueEnv, CreatedAt: now, UpdatedAt: now}
	if existing, ok := bindings[key]; ok {
		binding.CreatedAt = existing.CreatedAt
	}
	bindings[key] = binding
	if err := s.save(bindings); err != nil {
		return Binding{}, err
	}
	return binding, nil
}

func (s Store) Statuses() ([]Status, error) {
	bindings, err := s.load()
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(bindings))
	for name := range bindings {
		names = append(names, name)
	}
	sort.Strings(names)
	statuses := make([]Status, 0, len(names))
	for _, name := range names {
		binding := bindings[name]
		statuses = append(statuses, Status{
			Name:      binding.Name,
			Provider:  binding.Provider,
			ValueEnv:  binding.ValueEnv,
			Available: os.Getenv(binding.ValueEnv) != "",
			UpdatedAt: binding.UpdatedAt,
		})
	}
	return statuses, nil
}

func (s Store) ResolveAppEnv(app registry.AppSpec) (Resolution, error) {
	bindings, err := s.load()
	if err != nil {
		return Resolution{}, err
	}
	resolved := Resolution{RuntimeEnv: map[string]string{}}
	catalog, err := modelproviders.DefaultCatalog()
	if err != nil {
		return Resolution{}, err
	}
	envNames := modelGatewayEnvNames(app, catalog)
	for _, envName := range envNames {
		if value, ok := os.LookupEnv(envName); ok && value != "" {
			provider := ""
			if spec, found := catalog.ProviderForEnv(envName); found {
				provider = spec.ID
			}
			resolved.Accesses = append(resolved.Accesses, session.RuntimeSecretAccess{
				SecretRef: envName, Provider: provider, Source: "process_env",
				SourceEnvName: envName, RuntimeEnvName: envName, Verdict: "ALLOW",
			})
			continue
		}
		for _, providerID := range catalog.ProviderIDsForEnv(envName) {
			if !providerCanProjectCredential(catalog, providerID, envName) {
				continue
			}
			if binding, ok := bindings[bindingKey("model_gateway", providerID)]; ok {
				value := os.Getenv(binding.ValueEnv)
				if value == "" {
					resolved.Accesses = append(resolved.Accesses, secretAccess(binding, envName, "DENY"))
					continue
				}
				resolved.RuntimeEnv[envName] = value
				resolved.Accesses = append(resolved.Accesses, secretAccess(binding, envName, "ALLOW"))
				goto nextEnv
			}
		}
		for _, logical := range app.RequiredSecrets {
			binding, ok := bindings[logical]
			if !ok || binding.ValueEnv == "" {
				continue
			}
			if logical == "model_gateway" && binding.Provider != "" && !providerMatchesEnv(catalog, binding.Provider, envName) {
				continue
			}
			if logical == "model_gateway" && binding.Provider != "" && !providerCanProjectCredential(catalog, binding.Provider, envName) {
				continue
			}
			value := os.Getenv(binding.ValueEnv)
			if value == "" {
				resolved.Accesses = append(resolved.Accesses, secretAccess(binding, envName, "DENY"))
				continue
			}
			resolved.RuntimeEnv[envName] = value
			resolved.Accesses = append(resolved.Accesses, secretAccess(binding, envName, "ALLOW"))
			break
		}
	nextEnv:
	}
	sort.SliceStable(resolved.Accesses, func(i, j int) bool {
		left, right := resolved.Accesses[i], resolved.Accesses[j]
		if left.RuntimeEnvName != right.RuntimeEnvName {
			return left.RuntimeEnvName < right.RuntimeEnvName
		}
		if left.SecretRef != right.SecretRef {
			return left.SecretRef < right.SecretRef
		}
		if left.Provider != right.Provider {
			return left.Provider < right.Provider
		}
		return left.Verdict < right.Verdict
	})
	return resolved, nil
}

func secretAccess(binding Binding, runtimeEnvName, verdict string) session.RuntimeSecretAccess {
	ref := binding.Name
	if binding.Provider != "" {
		ref += ":" + binding.Provider
	}
	return session.RuntimeSecretAccess{
		SecretRef: ref, Provider: binding.Provider, Source: "binding_store",
		SourceEnvName: binding.ValueEnv, RuntimeEnvName: runtimeEnvName, Verdict: verdict,
	}
}

func (s Store) load() (map[string]Binding, error) {
	data, err := os.ReadFile(s.path())
	if errors.Is(err, os.ErrNotExist) {
		return map[string]Binding{}, nil
	}
	if err != nil {
		return nil, err
	}
	var payload struct {
		Bindings map[string]Binding `json:"bindings"`
	}
	if err := json.Unmarshal(data, &payload); err != nil {
		return nil, err
	}
	if payload.Bindings == nil {
		payload.Bindings = map[string]Binding{}
	}
	return payload.Bindings, nil
}

func (s Store) save(bindings map[string]Binding) error {
	if err := os.MkdirAll(filepath.Dir(s.path()), 0o700); err != nil {
		return err
	}
	payload := struct {
		SchemaVersion int                `json:"schema_version"`
		Bindings      map[string]Binding `json:"bindings"`
	}{SchemaVersion: 1, Bindings: bindings}
	data, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.path(), append(data, '\n'), 0o600)
}

func (s Store) path() string {
	return filepath.Join(s.root, "secrets", "bindings.json")
}

func bindingKey(name, provider string) string {
	if name == "model_gateway" && provider != "" {
		return name + ":" + provider
	}
	return name
}

func providerMatchesEnv(catalog modelproviders.Catalog, providerID, envName string) bool {
	for _, candidate := range catalog.ProviderIDsForEnv(envName) {
		if candidate == providerID {
			return true
		}
	}
	return false
}

func providerCanProjectCredential(catalog modelproviders.Catalog, providerID, envName string) bool {
	provider, ok := catalog.ProviderForID(providerID)
	return ok && provider.CanProjectCredential(envName)
}

func modelGatewayEnvNames(app registry.AppSpec, catalog modelproviders.Catalog) []string {
	if len(app.ModelGatewayEnv) > 0 {
		return app.ModelGatewayEnv
	}
	provider := strings.ToLower(strings.TrimSpace(app.ModelGateway.Provider))
	if provider != "byo" && provider != "multi" {
		return nil
	}
	envNames, err := catalog.EnvNamesForProviderIDs(app.ModelGateway.ProviderIDs)
	if err != nil {
		return nil
	}
	return envNames
}
