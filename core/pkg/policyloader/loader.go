// Package policyloader provides GOV-002: external policy bundle loading.
//
// Policy bundles are JSON files containing CEL rules that can be loaded
// from the filesystem or embedded in container images, enabling policy
// changes without code deployments.
package policyloader

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// PolicyRule represents a single CEL governance rule.
type PolicyRule struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Expression  string `json:"expression"` // CEL expression
	Action      string `json:"action"`     // "BLOCK", "WARN", "LOG"
	Priority    int    `json:"priority"`   // Higher = evaluated first
	Enabled     bool   `json:"enabled"`
}

// PolicyBundle is a versioned collection of CEL rules.
type PolicyBundle struct {
	Version   string       `json:"version"`
	Name      string       `json:"name"`
	Rules     []PolicyRule `json:"rules"`
	CreatedAt time.Time    `json:"created_at"`
	Hash      string       `json:"hash,omitempty"` // Content-addressed hash
}

// Loader loads and manages policy bundles from external sources.
type Loader struct {
	mu        sync.RWMutex
	bundles   map[string]*PolicyBundle // name -> bundle
	bundleDir string
	onReload  func(bundle *PolicyBundle)
}

// NewLoader creates a policy bundle loader watching the given directory.
func NewLoader(bundleDir string) *Loader {
	return &Loader{
		bundles:   make(map[string]*PolicyBundle),
		bundleDir: bundleDir,
	}
}

// OnReload registers a callback invoked when a bundle is loaded or reloaded.
func (l *Loader) OnReload(fn func(bundle *PolicyBundle)) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.onReload = fn
}

// LoadAll loads all .json bundle files from the configured directory.
func (l *Loader) LoadAll() error {
	entries, err := os.ReadDir(l.bundleDir)
	if err != nil {
		return fmt.Errorf("policyloader: read dir %s: %w", l.bundleDir, err)
	}

	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}

		path := filepath.Join(l.bundleDir, entry.Name())
		if err := l.LoadFile(path); err != nil {
			return fmt.Errorf("policyloader: load %s: %w", entry.Name(), err)
		}
	}

	return nil
}

// LoadFile loads a single policy bundle from a JSON file.
func (l *Loader) LoadFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read file: %w", err)
	}

	var bundle PolicyBundle
	if err := json.Unmarshal(data, &bundle); err != nil {
		return fmt.Errorf("parse bundle: %w", err)
	}

	if bundle.Name == "" {
		bundle.Name = filepath.Base(path)
	}

	l.mu.Lock()
	l.bundles[bundle.Name] = &bundle
	callback := l.onReload
	l.mu.Unlock()

	if callback != nil {
		callback(&bundle)
	}

	return nil
}

// GetBundle returns a loaded bundle by name.
func (l *Loader) GetBundle(name string) (*PolicyBundle, bool) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	b, ok := l.bundles[name]
	return b, ok
}

// AllBundles returns all loaded bundles.
func (l *Loader) AllBundles() []*PolicyBundle {
	l.mu.RLock()
	defer l.mu.RUnlock()

	result := make([]*PolicyBundle, 0, len(l.bundles))
	for _, b := range l.bundles {
		result = append(result, b)
	}
	return result
}

// ActiveRules returns all enabled rules across all bundles, sorted by priority.
func (l *Loader) ActiveRules() []PolicyRule {
	l.mu.RLock()
	defer l.mu.RUnlock()

	var rules []PolicyRule
	for _, b := range l.bundles {
		for _, r := range b.Rules {
			if r.Enabled {
				rules = append(rules, r)
			}
		}
	}

	// Sort by priority (highest first)
	for i := 0; i < len(rules); i++ {
		for j := i + 1; j < len(rules); j++ {
			if rules[j].Priority > rules[i].Priority {
				rules[i], rules[j] = rules[j], rules[i]
			}
		}
	}

	return rules
}
