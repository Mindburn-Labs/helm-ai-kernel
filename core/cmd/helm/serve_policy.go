package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/BurntSushi/toml"
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
