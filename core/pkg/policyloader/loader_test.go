package policyloader

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoader_LoadFile(t *testing.T) {
	dir := t.TempDir()

	bundle := `{
		"version": "1.0.0",
		"name": "security-rules",
		"rules": [
			{
				"id": "R-001",
				"name": "Block dangerous tools",
				"expression": "request.tool_name in ['rm', 'dd', 'format']",
				"action": "BLOCK",
				"priority": 100,
				"enabled": true
			},
			{
				"id": "R-002",
				"name": "Warn on network access",
				"expression": "request.requires_network == true",
				"action": "WARN",
				"priority": 50,
				"enabled": true
			},
			{
				"id": "R-003",
				"name": "Disabled rule",
				"expression": "true",
				"action": "LOG",
				"priority": 10,
				"enabled": false
			}
		]
	}`

	path := filepath.Join(dir, "security.json")
	if err := os.WriteFile(path, []byte(bundle), 0600); err != nil {
		t.Fatal(err)
	}

	loader := NewLoader(dir)
	if err := loader.LoadFile(path); err != nil {
		t.Fatalf("LoadFile: %v", err)
	}

	b, ok := loader.GetBundle("security-rules")
	if !ok {
		t.Fatal("bundle not found")
	}
	if b.Version != "1.0.0" {
		t.Errorf("version = %q, want 1.0.0", b.Version)
	}
	if len(b.Rules) != 3 {
		t.Errorf("rules count = %d, want 3", len(b.Rules))
	}
}

func TestLoader_LoadAll(t *testing.T) {
	dir := t.TempDir()

	for _, name := range []string{"a.json", "b.json"} {
		data := `{"version":"1","name":"` + name + `","rules":[{"id":"1","name":"test","expression":"true","action":"LOG","priority":1,"enabled":true}]}`
		if err := os.WriteFile(filepath.Join(dir, name), []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	// Non-json file should be ignored
	if err := os.WriteFile(filepath.Join(dir, "readme.txt"), []byte("ignore"), 0600); err != nil {
		t.Fatal(err)
	}

	loader := NewLoader(dir)
	if err := loader.LoadAll(); err != nil {
		t.Fatalf("LoadAll: %v", err)
	}

	bundles := loader.AllBundles()
	if len(bundles) != 2 {
		t.Errorf("bundles = %d, want 2", len(bundles))
	}
}

func TestLoader_ActiveRules_SortedByPriority(t *testing.T) {
	dir := t.TempDir()

	bundle := `{
		"version": "1",
		"name": "test",
		"rules": [
			{"id":"lo","name":"low","expression":"true","action":"LOG","priority":1,"enabled":true},
			{"id":"hi","name":"high","expression":"true","action":"BLOCK","priority":100,"enabled":true},
			{"id":"mid","name":"mid","expression":"true","action":"WARN","priority":50,"enabled":true},
			{"id":"off","name":"off","expression":"true","action":"LOG","priority":200,"enabled":false}
		]
	}`

	path := filepath.Join(dir, "test.json")
	if err := os.WriteFile(path, []byte(bundle), 0600); err != nil {
		t.Fatal(err)
	}

	loader := NewLoader(dir)
	if err := loader.LoadFile(path); err != nil {
		t.Fatal(err)
	}

	rules := loader.ActiveRules()
	if len(rules) != 3 {
		t.Fatalf("active rules = %d, want 3 (disabled excluded)", len(rules))
	}

	// Should be sorted: high (100), mid (50), low (1)
	if rules[0].ID != "hi" || rules[1].ID != "mid" || rules[2].ID != "lo" {
		t.Errorf("priority order wrong: %s, %s, %s", rules[0].ID, rules[1].ID, rules[2].ID)
	}
}

func TestLoader_OnReload(t *testing.T) {
	dir := t.TempDir()
	bundle := `{"version":"1","name":"callback-test","rules":[]}`
	path := filepath.Join(dir, "cb.json")
	if err := os.WriteFile(path, []byte(bundle), 0600); err != nil {
		t.Fatal(err)
	}

	loader := NewLoader(dir)

	var called bool
	loader.OnReload(func(b *PolicyBundle) {
		called = true
		if b.Name != "callback-test" {
			t.Errorf("reload bundle name = %q, want callback-test", b.Name)
		}
	})

	if err := loader.LoadFile(path); err != nil {
		t.Fatal(err)
	}

	if !called {
		t.Error("OnReload callback not invoked")
	}
}
