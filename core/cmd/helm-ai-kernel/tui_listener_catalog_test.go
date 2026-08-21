package main

import (
	"strings"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/internal/cli/tui"
)

func TestListenerCatalogHygiene(t *testing.T) {
	required := []struct {
		name string
		args []string
	}{
		{"server", nil},
		{"serve", []string{"--policy", "p.toml"}},
		{"quickstart", nil},
		{"onboard", nil},
		{"dev", nil},
		{"proxy", nil},
		{"connect", nil},
		{"login", nil},
		{"receipts", []string{"tail"}},
		{"mcp", []string{"serve"}},
		{"scan", nil},
		{"scan", []string{"--path", "."}},
	}
	for _, tc := range required {
		if !tui.IsListenerVerb(tc.name, tc.args) {
			t.Errorf("IsListenerVerb(%q, %v) = false, want true", tc.name, tc.args)
		}
	}

	looksLikeBind := func(name string) bool {
		n := strings.ToLower(name)
		return strings.Contains(n, "serve") || strings.Contains(n, "proxy") || strings.Contains(n, "tail")
	}
	bindArgs := func(name string) []string {
		if strings.EqualFold(name, "serve") {
			return []string{"--policy", "p.toml"}
		}
		return nil
	}
	for _, cmd := range commandCatalog().Commands {
		names := append([]string{cmd.Name}, cmd.Aliases...)
		for _, name := range names {
			if !looksLikeBind(name) {
				continue
			}
			args := bindArgs(name)
			if !tui.IsListenerVerb(name, args) {
				t.Errorf("catalog %q %v looks like a bind but IsListenerVerb is false", name, args)
			}
		}
	}
}
