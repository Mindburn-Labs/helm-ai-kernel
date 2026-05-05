package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/BurntSushi/toml"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/prg"
)

type servePolicy struct {
	Name          string `toml:"name"`
	Profile       string `toml:"profile"`
	ReferencePack string `toml:"reference_pack"`
	Server        struct {
		Bind string `toml:"bind"`
		Port int    `toml:"port"`
	} `toml:"server"`
	Receipts struct {
		Store string `toml:"store"`
		Path  string `toml:"path"`
	} `toml:"receipts"`
}

func loadServePolicy(path string) (*servePolicy, error) {
	if path == "" {
		return nil, fmt.Errorf("policy path is required")
	}
	if ext := strings.ToLower(filepath.Ext(path)); ext != ".toml" {
		return nil, fmt.Errorf("unsupported policy format %q: expected .toml", ext)
	}
	if _, err := os.Stat(path); err != nil {
		return nil, fmt.Errorf("policy not found: %w", err)
	}

	var policy servePolicy
	if _, err := toml.DecodeFile(path, &policy); err != nil {
		return nil, fmt.Errorf("decode policy: %w", err)
	}
	if err := policy.validate(); err != nil {
		return nil, err
	}
	return &policy, nil
}

type servePolicyRuntime struct {
	Policy        *servePolicy
	ReferencePack serveReferencePack
	Graph         *prg.Graph
}

type serveReferencePack struct {
	PackID         string               `json:"pack_id"`
	Label          string               `json:"label"`
	Version        any                  `json:"version"`
	RuntimeActions []serveRuntimeAction `json:"runtime_actions"`
	Actions        []serveRuntimeAction `json:"actions"`
}

type serveRuntimeAction struct {
	Action         string             `json:"action"`
	Resource       string             `json:"resource,omitempty"`
	Enabled        *bool              `json:"enabled,omitempty"`
	RequirementSet prg.RequirementSet `json:"requirement_set,omitempty"`
	Expression     string             `json:"expression,omitempty"`
	Description    string             `json:"description,omitempty"`
}

func loadServePolicyRuntime(path string) (*servePolicyRuntime, error) {
	policy, err := loadServePolicy(path)
	if err != nil {
		return nil, err
	}

	refPath := policy.ReferencePack
	if !filepath.IsAbs(refPath) {
		refPath = filepath.Join(filepath.Dir(path), refPath)
	}
	data, err := os.ReadFile(refPath)
	if err != nil {
		return nil, fmt.Errorf("read reference_pack %s: %w", policy.ReferencePack, err)
	}

	var pack serveReferencePack
	if err := json.Unmarshal(data, &pack); err != nil {
		return nil, fmt.Errorf("decode reference_pack %s: %w", policy.ReferencePack, err)
	}
	if strings.TrimSpace(pack.PackID) == "" {
		return nil, fmt.Errorf("reference_pack missing required key: pack_id")
	}
	if pack.Version == nil {
		return nil, fmt.Errorf("reference_pack missing required key: version")
	}

	graph, err := compileServePolicyGraph(policy, pack)
	if err != nil {
		return nil, err
	}
	return &servePolicyRuntime{Policy: policy, ReferencePack: pack, Graph: graph}, nil
}

func (r *servePolicyRuntime) AllowMap() map[string]bool {
	allow := make(map[string]bool)
	if r == nil || r.Graph == nil {
		return allow
	}
	for action := range r.Graph.Rules {
		allow[action] = true
	}
	return allow
}

func compileServePolicyGraph(policy *servePolicy, pack serveReferencePack) (*prg.Graph, error) {
	graph := prg.NewGraph()
	actions := append([]serveRuntimeAction{}, pack.RuntimeActions...)
	actions = append(actions, pack.Actions...)
	for i, action := range actions {
		enabled := action.Enabled == nil || *action.Enabled
		if !enabled {
			continue
		}
		actionID := strings.TrimSpace(action.Action)
		if actionID == "" {
			return nil, fmt.Errorf("reference_pack action %d missing action", i)
		}
		set := action.RequirementSet
		if strings.TrimSpace(set.ID) == "" {
			set.ID = fmt.Sprintf("%s:%s", policy.Name, actionID)
		}
		if set.Logic == "" {
			set.Logic = prg.AND
		}
		if strings.TrimSpace(action.Expression) != "" {
			set.Requirements = append(set.Requirements, prg.Requirement{
				ID:          set.ID + ":expression",
				Description: strings.TrimSpace(action.Description),
				Expression:  strings.TrimSpace(action.Expression),
			})
		}
		if err := graph.AddRule(actionID, set); err != nil {
			return nil, fmt.Errorf("reference_pack action %q: %w", actionID, err)
		}
	}
	return graph, nil
}

func (p *servePolicy) validate() error {
	if strings.TrimSpace(p.Name) == "" {
		return fmt.Errorf("policy missing required key: name")
	}
	if strings.TrimSpace(p.Profile) == "" {
		return fmt.Errorf("policy missing required key: profile")
	}
	if strings.TrimSpace(p.ReferencePack) == "" {
		return fmt.Errorf("policy missing required key: reference_pack")
	}
	if strings.TrimSpace(p.Server.Bind) == "" {
		return fmt.Errorf("policy missing required key: server.bind")
	}
	if p.Server.Port <= 0 || p.Server.Port > 65535 {
		return fmt.Errorf("policy server.port must be between 1 and 65535")
	}
	if strings.TrimSpace(p.Receipts.Store) == "" {
		return fmt.Errorf("policy missing required key: receipts.store")
	}
	if strings.TrimSpace(p.Receipts.Path) == "" {
		return fmt.Errorf("policy missing required key: receipts.path")
	}
	return nil
}
