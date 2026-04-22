// Package bundles implements the HELM policy bundle runtime.
// It provides loading, verification, and composition of signed policy
// bundles — YAML files containing CEL rules that define organizational
// governance law for the HELM kernel.
package bundles

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// ── Errors ───────────────────────────────────────────────────────────

var (
	ErrBundleNotFound      = errors.New("bundles: bundle not found")
	ErrBundleInvalid       = errors.New("bundles: invalid bundle format")
	ErrBundleHashMismatch  = errors.New("bundles: content hash mismatch")
	ErrRuleInvalid         = errors.New("bundles: invalid rule")
	ErrCompositionConflict = errors.New("bundles: composition conflict")
)

// ── Types ────────────────────────────────────────────────────────────

// Bundle represents a loaded policy bundle.
type Bundle struct {
	APIVersion string         `yaml:"apiVersion" json:"api_version"`
	Kind       string         `yaml:"kind" json:"kind"`
	Metadata   BundleMetadata `yaml:"metadata" json:"metadata"`
	Rules      []Rule         `yaml:"rules" json:"rules"`
}

// BundleMetadata provides identity and integrity for a bundle.
type BundleMetadata struct {
	Name    string `yaml:"name" json:"name"`
	Version string `yaml:"version" json:"version"`
	Hash    string `yaml:"hash" json:"hash"` // Computed on load
}

// Rule is a single policy rule within a bundle.
type Rule struct {
	ID         string `yaml:"id" json:"id"`
	Action     string `yaml:"action" json:"action"`         // Effect type pattern
	Expression string `yaml:"expression" json:"expression"` // CEL expression
	Verdict    string `yaml:"verdict" json:"verdict"`       // BLOCK, ALLOW, ESCALATE
	Reason     string `yaml:"reason" json:"reason"`
}

// ComposedPolicy is the result of composing multiple bundles.
type ComposedPolicy struct {
	Bundles   []BundleMetadata `json:"bundles"`
	Rules     []Rule           `json:"rules"`
	Hash      string           `json:"hash"` // Content-addressed hash of composition
	RuleCount int              `json:"rule_count"`
	Conflicts []string         `json:"conflicts,omitempty"`
}

// BundleInfo provides inspection metadata for a bundle.
type BundleInfo struct {
	Name      string   `json:"name"`
	Version   string   `json:"version"`
	Hash      string   `json:"hash"`
	RuleCount int      `json:"rule_count"`
	Actions   []string `json:"actions"`
	Valid     bool     `json:"valid"`
}

// ── Loader ───────────────────────────────────────────────────────────

// LoadFromFile loads and validates a policy bundle from a YAML file.
func LoadFromFile(path string) (*Bundle, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBundleNotFound, err)
	}
	return LoadFromBytes(data)
}

// LoadFromBytes loads and validates a policy bundle from raw YAML bytes.
func LoadFromBytes(data []byte) (*Bundle, error) {
	var bundle Bundle
	if err := yaml.Unmarshal(data, &bundle); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBundleInvalid, err)
	}

	// Validate structure
	if err := validateBundle(&bundle); err != nil {
		return nil, err
	}

	// Compute content hash
	bundle.Metadata.Hash = computeBundleHash(&bundle)

	return &bundle, nil
}

// ── Verification ─────────────────────────────────────────────────────

// Verify checks bundle integrity against an expected hash.
func Verify(bundle *Bundle, expectedHash string) error {
	computed := computeBundleHash(bundle)
	if computed != expectedHash {
		return fmt.Errorf("%w: expected %s, got %s", ErrBundleHashMismatch, expectedHash, computed)
	}
	return nil
}

// ── Composition ──────────────────────────────────────────────────────

// Compose merges multiple bundles into a single composed policy.
// Rules are deduplicated by ID. If two bundles define the same rule ID
// with different verdicts, a conflict is recorded.
func Compose(bundles ...*Bundle) (*ComposedPolicy, error) {
	if len(bundles) == 0 {
		return &ComposedPolicy{}, nil
	}

	ruleMap := make(map[string]Rule)
	var conflicts []string
	var metadata []BundleMetadata

	for _, b := range bundles {
		metadata = append(metadata, b.Metadata)
		for _, r := range b.Rules {
			if existing, ok := ruleMap[r.ID]; ok {
				if existing.Verdict != r.Verdict {
					conflicts = append(conflicts,
						fmt.Sprintf("rule %q: %s says %s, %s says %s",
							r.ID, existing.Reason, existing.Verdict, r.Reason, r.Verdict))
				}
				continue // First rule wins
			}
			ruleMap[r.ID] = r
		}
	}

	// Sort rules deterministically by ID
	rules := make([]Rule, 0, len(ruleMap))
	for _, r := range ruleMap {
		rules = append(rules, r)
	}
	sort.Slice(rules, func(i, j int) bool { return rules[i].ID < rules[j].ID })

	composed := &ComposedPolicy{
		Bundles:   metadata,
		Rules:     rules,
		RuleCount: len(rules),
		Conflicts: conflicts,
	}
	composed.Hash = computeComposedHash(composed)

	return composed, nil
}

// ── Inspection ───────────────────────────────────────────────────────

// Inspect returns metadata about a bundle without activating it.
func Inspect(bundle *Bundle) *BundleInfo {
	actions := make(map[string]bool)
	for _, r := range bundle.Rules {
		actions[r.Action] = true
	}
	actionList := make([]string, 0, len(actions))
	for a := range actions {
		actionList = append(actionList, a)
	}
	sort.Strings(actionList)

	return &BundleInfo{
		Name:      bundle.Metadata.Name,
		Version:   bundle.Metadata.Version,
		Hash:      bundle.Metadata.Hash,
		RuleCount: len(bundle.Rules),
		Actions:   actionList,
		Valid:     validateBundle(bundle) == nil,
	}
}

// ── Internal ─────────────────────────────────────────────────────────

func validateBundle(b *Bundle) error {
	if b.Metadata.Name == "" {
		return fmt.Errorf("%w: missing metadata.name", ErrBundleInvalid)
	}
	for i, r := range b.Rules {
		if r.ID == "" {
			return fmt.Errorf("%w: rule %d missing id", ErrRuleInvalid, i)
		}
		if r.Action == "" {
			return fmt.Errorf("%w: rule %q missing action", ErrRuleInvalid, r.ID)
		}
		v := strings.ToUpper(r.Verdict)
		if v != "BLOCK" && v != "ALLOW" && v != "ESCALATE" {
			return fmt.Errorf("%w: rule %q has invalid verdict %q", ErrRuleInvalid, r.ID, r.Verdict)
		}
	}
	return nil
}

func computeBundleHash(b *Bundle) string {
	canonical := struct {
		Name    string `json:"name"`
		Version string `json:"version"`
		Rules   []Rule `json:"rules"`
	}{b.Metadata.Name, b.Metadata.Version, b.Rules}
	data, _ := json.Marshal(canonical)
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

func computeComposedHash(c *ComposedPolicy) string {
	data, _ := json.Marshal(c.Rules)
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}
