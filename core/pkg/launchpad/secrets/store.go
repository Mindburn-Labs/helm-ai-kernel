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
	binding := Binding{Name: name, Provider: provider, ValueEnv: valueEnv, CreatedAt: now, UpdatedAt: now}
	if existing, ok := bindings[name]; ok {
		binding.CreatedAt = existing.CreatedAt
	}
	bindings[name] = binding
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

func (s Store) ApplyAppEnv(app registry.AppSpec) (map[string]string, error) {
	bindings, err := s.load()
	if err != nil {
		return nil, err
	}
	projected := map[string]string{}
	for _, envName := range app.ModelGatewayEnv {
		if os.Getenv(envName) != "" {
			continue
		}
		for _, logical := range app.RequiredSecrets {
			binding, ok := bindings[logical]
			if !ok || binding.ValueEnv == "" {
				continue
			}
			value := os.Getenv(binding.ValueEnv)
			if value == "" {
				continue
			}
			if err := os.Setenv(envName, value); err != nil {
				return nil, err
			}
			projected[envName] = logical
			break
		}
	}
	return projected, nil
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
