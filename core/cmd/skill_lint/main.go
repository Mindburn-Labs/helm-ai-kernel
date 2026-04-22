// Command skill_lint validates a skill bundle manifest against the schema.
//
// Usage: skill_lint <path-to-manifest.json>
//
// Exits 0 on valid, 1 on invalid with error details, 2 on usage error.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/registry/skills"
)

// validationResult is the structured JSON output.
type validationResult struct {
	Valid  bool     `json:"valid"`
	Errors []string `json:"errors,omitempty"`
	File   string   `json:"file"`
}

// knownCapabilities is the set of recognised SkillCapability values.
var knownCapabilities = map[skills.SkillCapability]struct{}{
	skills.CapReadFiles:       {},
	skills.CapWriteFiles:      {},
	skills.CapExecSandbox:     {},
	skills.CapNetworkOutbound: {},
	skills.CapChannelSend:     {},
	skills.CapMemoryReadLKS:   {},
	skills.CapMemoryReadCKS:   {},
	skills.CapMemoryPromote:   {},
	skills.CapApprovalRequest: {},
	skills.CapArtifactWrite:   {},
	skills.CapConnectorInvoke: {},
}

// validStates is the set of recognised SkillBundleState values.
var validStates = map[skills.SkillBundleState]struct{}{
	skills.SkillBundleStateCandidate:  {},
	skills.SkillBundleStateCertified:  {},
	skills.SkillBundleStateDeprecated: {},
	skills.SkillBundleStateRevoked:    {},
}

func main() {
	os.Exit(run())
}

func run() int {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "usage: skill_lint <manifest.json>\n")
		return 2
	}

	manifestPath := os.Args[1]

	data, err := os.ReadFile(manifestPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: cannot read %q: %v\n", manifestPath, err)
		return 2
	}

	var manifest skills.SkillManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		result := validationResult{
			Valid:  false,
			Errors: []string{fmt.Sprintf("invalid JSON: %v", err)},
			File:   manifestPath,
		}
		printResult(result)
		return 1
	}

	errs := validateManifest(manifest)
	result := validationResult{
		Valid:  len(errs) == 0,
		Errors: errs,
		File:   manifestPath,
	}
	printResult(result)

	if len(errs) > 0 {
		return 1
	}
	return 0
}

func validateManifest(m skills.SkillManifest) []string {
	var errs []string

	// Required string fields.
	if m.ID == "" {
		errs = append(errs, "id is required")
	}
	if m.Name == "" {
		errs = append(errs, "name is required")
	}
	if m.Version == "" {
		errs = append(errs, "version is required")
	}
	if m.EntryPoint == "" {
		errs = append(errs, "entry_point is required")
	}

	// State must be a recognised value.
	if m.State == "" {
		errs = append(errs, "state is required")
	} else if _, ok := validStates[m.State]; !ok {
		errs = append(errs, fmt.Sprintf("state %q is not valid (must be candidate, certified, deprecated, or revoked)", m.State))
	}

	// Capabilities must all be recognised.
	for _, cap := range m.Capabilities {
		if _, ok := knownCapabilities[cap]; !ok {
			errs = append(errs, fmt.Sprintf("capability %q is not recognised", cap))
		}
	}

	// BundleHash must be present and follow the sha256: prefix format.
	if m.BundleHash == "" {
		errs = append(errs, "bundle_hash is required")
	} else if !strings.HasPrefix(m.BundleHash, "sha256:") && len(m.BundleHash) != 64 {
		// Accept either a bare 64-char hex digest or a "sha256:<hex>" prefixed form.
		errs = append(errs, fmt.Sprintf("bundle_hash %q must be a sha256: prefixed digest or a 64-character hex string", m.BundleHash))
	}

	// SignatureRef must be non-empty.
	if m.SignatureRef == "" {
		errs = append(errs, "signature_ref is required")
	}

	// SelfModClass must be C0, C1, C2, or C3.
	if m.SelfModClass == "" {
		errs = append(errs, "self_mod_class is required")
	} else {
		switch m.SelfModClass {
		case "C0", "C1", "C2", "C3":
			// valid
		default:
			errs = append(errs, fmt.Sprintf("self_mod_class %q is not valid (must be C0, C1, C2, or C3)", m.SelfModClass))
		}
	}

	// RiskClass must be non-empty.
	if m.RiskClass == "" {
		errs = append(errs, "risk_class is required")
	}

	// At least one input or output contract must be declared.
	if len(m.Inputs) == 0 && len(m.Outputs) == 0 {
		errs = append(errs, "at least one input or output contract is required")
	}

	return errs
}

func printResult(r validationResult) {
	out, _ := json.MarshalIndent(r, "", "  ")
	fmt.Println(string(out))
}
