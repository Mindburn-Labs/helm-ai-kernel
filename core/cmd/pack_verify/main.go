// Command pack_verify verifies a pack directory structure and policy integrity.
//
// Usage: pack_verify <pack-dir>
//
// Checks: pack.yaml exists and parses, policies/ directory exists, each
// policy file is valid YAML with required fields, and no duplicate rule IDs
// exist across policies (circular-dependency proxy check).
//
// Exits 0 on success, 1 on verification failure, 2 on usage error.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// packManifest is the minimal structure we validate from pack.yaml.
type packManifest struct {
	Name        string `yaml:"name"`
	Version     string `yaml:"version"`
	Type        string `yaml:"type"`
	Description string `yaml:"description,omitempty"`
}

// policyFile is the minimal structure we validate from each policy YAML.
type policyFile struct {
	Name        string       `yaml:"name"`
	Priority    int          `yaml:"priority"`
	Description string       `yaml:"description,omitempty"`
	Rules       []policyRule `yaml:"rules"`
}

// policyRule is a single rule within a policy file.
type policyRule struct {
	ID          string `yaml:"id"`
	Description string `yaml:"description,omitempty"`
	Effect      string `yaml:"effect"`
	Condition   string `yaml:"condition,omitempty"`
}

// verificationResult is the structured JSON output.
type verificationResult struct {
	Valid       bool     `json:"valid"`
	PackDir     string   `json:"pack_dir"`
	PackName    string   `json:"pack_name,omitempty"`
	PackVersion string   `json:"pack_version,omitempty"`
	Policies    int      `json:"policies_checked"`
	Rules       int      `json:"rules_checked"`
	Errors      []string `json:"errors,omitempty"`
	Warnings    []string `json:"warnings,omitempty"`
}

func main() {
	os.Exit(run())
}

func run() int {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "usage: pack_verify <pack-dir>\n")
		return 2
	}

	packDir := os.Args[1]
	result := verify(packDir)

	out, _ := json.MarshalIndent(result, "", "  ")
	fmt.Println(string(out))

	if !result.Valid {
		return 1
	}
	return 0
}

func verify(packDir string) verificationResult {
	result := verificationResult{
		PackDir: packDir,
		Valid:   true,
	}

	// 1. Check pack.yaml exists and parses.
	packYAML := filepath.Join(packDir, "pack.yaml")
	data, err := os.ReadFile(packYAML)
	if err != nil {
		result.Valid = false
		result.Errors = append(result.Errors, fmt.Sprintf("pack.yaml not found: %v", err))
		return result // Cannot continue without pack.yaml
	}

	var manifest packManifest
	if err := yaml.Unmarshal(data, &manifest); err != nil {
		result.Valid = false
		result.Errors = append(result.Errors, fmt.Sprintf("pack.yaml parse error: %v", err))
		return result
	}

	// Required fields in pack.yaml.
	if manifest.Name == "" {
		result.Valid = false
		result.Errors = append(result.Errors, "pack.yaml: name is required")
	}
	if manifest.Version == "" {
		result.Valid = false
		result.Errors = append(result.Errors, "pack.yaml: version is required")
	}
	if manifest.Type == "" {
		result.Warnings = append(result.Warnings, "pack.yaml: type is not set")
	}

	result.PackName = manifest.Name
	result.PackVersion = manifest.Version

	// 2. Check policies/ directory exists.
	policiesDir := filepath.Join(packDir, "policies")
	info, err := os.Stat(policiesDir)
	if err != nil || !info.IsDir() {
		result.Valid = false
		result.Errors = append(result.Errors, fmt.Sprintf("policies/ directory not found under %q", packDir))
		return result
	}

	// 3. Validate each policy file.
	entries, err := os.ReadDir(policiesDir)
	if err != nil {
		result.Valid = false
		result.Errors = append(result.Errors, fmt.Sprintf("cannot read policies/ directory: %v", err))
		return result
	}

	seenRuleIDs := make(map[string]string) // ruleID -> policy file that defined it

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		ext := filepath.Ext(name)
		if ext != ".yaml" && ext != ".yml" {
			continue
		}

		policyPath := filepath.Join(policiesDir, name)
		policyData, err := os.ReadFile(policyPath)
		if err != nil {
			result.Valid = false
			result.Errors = append(result.Errors, fmt.Sprintf("cannot read policy file %q: %v", name, err))
			continue
		}

		var policy policyFile
		if err := yaml.Unmarshal(policyData, &policy); err != nil {
			result.Valid = false
			result.Errors = append(result.Errors, fmt.Sprintf("policy %q: parse error: %v", name, err))
			continue
		}

		// Required fields in each policy.
		if policy.Name == "" {
			result.Valid = false
			result.Errors = append(result.Errors, fmt.Sprintf("policy %q: name is required", name))
		}
		if len(policy.Rules) == 0 {
			result.Warnings = append(result.Warnings, fmt.Sprintf("policy %q: has no rules", name))
		}

		result.Policies++

		// Validate each rule and check for duplicate IDs.
		for i, rule := range policy.Rules {
			result.Rules++

			if rule.ID == "" {
				result.Valid = false
				result.Errors = append(result.Errors, fmt.Sprintf("policy %q: rule[%d] has no id", name, i))
				continue
			}
			if rule.Effect == "" {
				result.Valid = false
				result.Errors = append(result.Errors, fmt.Sprintf("policy %q: rule %q has no effect", name, rule.ID))
			} else {
				switch rule.Effect {
				case "ALLOW", "DENY", "AUDIT", "REQUIRE_APPROVAL", "EVALUATE", "OVERRIDE", "PASS_THROUGH":
					// valid
				default:
					result.Valid = false
					result.Errors = append(result.Errors, fmt.Sprintf(
						"policy %q: rule %q has unrecognised effect %q (must be one of: ALLOW, DENY, AUDIT, REQUIRE_APPROVAL, EVALUATE, OVERRIDE, PASS_THROUGH)",
						name, rule.ID, rule.Effect,
					))
				}
			}

			// Check for duplicate rule IDs across all policies (no circular dep proxy).
			if prev, exists := seenRuleIDs[rule.ID]; exists {
				result.Valid = false
				result.Errors = append(result.Errors, fmt.Sprintf(
					"duplicate rule id %q: defined in both %q and %q", rule.ID, prev, name,
				))
			} else {
				seenRuleIDs[rule.ID] = name
			}
		}
	}

	return result
}
