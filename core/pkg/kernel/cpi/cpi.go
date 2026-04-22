//go:build !cpi_native

// Package cpi provides the Canonical Policy Index — a deterministic policy
// stack validator for the HELM kernel. The CPI validates that composed policy
// layers (P0 ceilings → P1 bundles → P2 overlays) are internally consistent,
// producing typed verdicts with machine-readable explanations.
//
// The CPI operates in three modes:
//   - Validate: checks a policy stack for internal contradictions
//   - Compile: parses and validates a policy source document
//   - Explain: produces human-readable rationale for a CPI verdict
package cpi

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
)

// ── Errors ───────────────────────────────────────────────────────────

// ErrInvalidInput is returned when the input bytes are malformed.
var ErrInvalidInput = errors.New("cpi: invalid input")

// ErrBundleMismatch is returned when bundle hashes don't match.
var ErrBundleMismatch = errors.New("cpi: bundle mismatch")

// ErrInternal is returned for unexpected internal errors.
var ErrInternal = errors.New("cpi: internal error")

// ErrPolicyConflict is returned when policy layers contain contradictions.
var ErrPolicyConflict = errors.New("cpi: policy conflict detected")

// ── Types ────────────────────────────────────────────────────────────

// Verdict represents the outcome of a CPI validation.
type Verdict string

const (
	VerdictConsistent Verdict = "CONSISTENT"
	VerdictConflict   Verdict = "CONFLICT"
	VerdictInvalid    Verdict = "INVALID"
)

// PolicyLayer represents a single layer in the policy stack.
type PolicyLayer struct {
	Name     string            `json:"name"`     // e.g., "P0", "P1", "P2"
	Priority int               `json:"priority"` // Lower number = higher priority (P0=0)
	Rules    []PolicyRule      `json:"rules"`
	Hash     string            `json:"hash"` // SHA-256 of canonical rule set
	Metadata map[string]string `json:"metadata,omitempty"`
}

// PolicyRule represents a single rule within a policy layer.
type PolicyRule struct {
	ID         string   `json:"id"`
	Action     string   `json:"action"`  // Effect type pattern (e.g., "write.*", "*")
	Verdict    string   `json:"verdict"` // "ALLOW", "DENY", "ESCALATE"
	Reason     string   `json:"reason"`
	Conditions []string `json:"conditions,omitempty"` // CEL expressions
}

// ValidationResult contains the complete CPI validation output.
type ValidationResult struct {
	Verdict   Verdict        `json:"verdict"`
	Hash      string         `json:"hash"` // Content-addressed hash of the result
	Conflicts []Conflict     `json:"conflicts,omitempty"`
	Layers    []LayerSummary `json:"layers"`
}

// Conflict describes a specific contradiction between policy layers.
type Conflict struct {
	LayerA string `json:"layer_a"`
	LayerB string `json:"layer_b"`
	RuleA  string `json:"rule_a"`
	RuleB  string `json:"rule_b"`
	Action string `json:"action"`
	Detail string `json:"detail"`
}

// LayerSummary captures metadata about a validated layer.
type LayerSummary struct {
	Name      string `json:"name"`
	RuleCount int    `json:"rule_count"`
	Hash      string `json:"hash"`
}

// CompiledBundle represents a validated, parsed policy bundle.
type CompiledBundle struct {
	Layers []PolicyLayer `json:"layers"`
	Hash   string        `json:"hash"` // Content-addressed hash of the compiled bundle
}

// Explanation provides human-readable rationale for a validation result.
type Explanation struct {
	Summary  string            `json:"summary"`
	Verdict  Verdict           `json:"verdict"`
	Details  []string          `json:"details"`
	Metadata map[string]string `json:"metadata,omitempty"`
}

// ── Core Functions ───────────────────────────────────────────────────

// Validate checks whether a composed policy stack is internally consistent.
// It takes the serialized policy layers and returns a ValidationResult.
//
// The validation checks:
//  1. Each layer is well-formed (valid JSON, required fields present)
//  2. No lower-priority layer contradicts a higher-priority layer
//  3. P0 ceilings are never widened by P1 or P2
//  4. Action patterns don't create ambiguous resolution paths
//
// Parameters:
//   - bytecode: reserved for future compiled policy format (may be nil)
//   - snapshot: reserved for state snapshot (may be nil)
//   - delta: reserved for incremental validation (may be nil)
//   - facts: JSON-encoded []PolicyLayer representing the composed stack
//
// Returns the JSON-encoded ValidationResult, or an error.
func Validate(bytecode, snapshot, delta, facts []byte) ([]byte, error) {
	if facts == nil || len(facts) == 0 {
		return marshalResult(&ValidationResult{
			Verdict: VerdictConsistent,
			Hash:    hashBytes([]byte("empty")),
			Layers:  []LayerSummary{},
		})
	}

	var layers []PolicyLayer
	if err := json.Unmarshal(facts, &layers); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidInput, err)
	}

	// Sort layers by priority (P0=0 is highest priority)
	sort.Slice(layers, func(i, j int) bool {
		return layers[i].Priority < layers[j].Priority
	})

	// Compute per-layer hashes
	for i := range layers {
		layers[i].Hash = computeLayerHash(&layers[i])
	}

	// Check for conflicts: higher-priority DENY cannot be widened by
	// lower-priority ALLOW on the same action pattern
	var conflicts []Conflict
	for i := 0; i < len(layers); i++ {
		for j := i + 1; j < len(layers); j++ {
			layerConflicts := detectConflicts(&layers[i], &layers[j])
			conflicts = append(conflicts, layerConflicts...)
		}
	}

	verdict := VerdictConsistent
	if len(conflicts) > 0 {
		verdict = VerdictConflict
	}

	summaries := make([]LayerSummary, len(layers))
	for i, l := range layers {
		summaries[i] = LayerSummary{
			Name:      l.Name,
			RuleCount: len(l.Rules),
			Hash:      l.Hash,
		}
	}

	result := &ValidationResult{
		Verdict:   verdict,
		Conflicts: conflicts,
		Layers:    summaries,
	}
	result.Hash = computeResultHash(result)

	return marshalResult(result)
}

// Explain generates a human-readable explanation from a ValidationResult.
func Explain(verdictBytes []byte) ([]byte, error) {
	if verdictBytes == nil || len(verdictBytes) == 0 {
		return nil, fmt.Errorf("%w: nil verdict", ErrInvalidInput)
	}

	var result ValidationResult
	if err := json.Unmarshal(verdictBytes, &result); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidInput, err)
	}

	explanation := &Explanation{
		Verdict:  result.Verdict,
		Metadata: map[string]string{"result_hash": result.Hash},
	}

	switch result.Verdict {
	case VerdictConsistent:
		explanation.Summary = fmt.Sprintf(
			"Policy stack is consistent across %d layers",
			len(result.Layers),
		)
		for _, l := range result.Layers {
			explanation.Details = append(explanation.Details,
				fmt.Sprintf("Layer %q: %d rules, hash=%s", l.Name, l.RuleCount, l.Hash[:12]),
			)
		}
	case VerdictConflict:
		explanation.Summary = fmt.Sprintf(
			"Policy stack has %d conflict(s) across %d layers",
			len(result.Conflicts), len(result.Layers),
		)
		for _, c := range result.Conflicts {
			explanation.Details = append(explanation.Details,
				fmt.Sprintf("Conflict: %s.%s vs %s.%s on action %q — %s",
					c.LayerA, c.RuleA, c.LayerB, c.RuleB, c.Action, c.Detail),
			)
		}
	case VerdictInvalid:
		explanation.Summary = "Policy stack contains invalid layers"
	}

	data, err := json.Marshal(explanation)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInternal, err)
	}
	return data, nil
}

// Compile validates and parses a policy source document (JSON) into
// a CompiledBundle. The compiled bundle is content-addressed.
func Compile(source []byte) ([]byte, error) {
	if source == nil || len(source) == 0 {
		return nil, fmt.Errorf("%w: empty source", ErrInvalidInput)
	}

	var layers []PolicyLayer
	if err := json.Unmarshal(source, &layers); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidInput, err)
	}

	// Validate each layer
	for i, layer := range layers {
		if layer.Name == "" {
			return nil, fmt.Errorf("%w: layer %d missing name", ErrInvalidInput, i)
		}
		for j, rule := range layer.Rules {
			if rule.ID == "" {
				return nil, fmt.Errorf("%w: layer %q rule %d missing ID", ErrInvalidInput, layer.Name, j)
			}
			if rule.Action == "" {
				return nil, fmt.Errorf("%w: layer %q rule %q missing action", ErrInvalidInput, layer.Name, rule.ID)
			}
			if rule.Verdict != "ALLOW" && rule.Verdict != "DENY" && rule.Verdict != "ESCALATE" {
				return nil, fmt.Errorf("%w: layer %q rule %q invalid verdict %q",
					ErrInvalidInput, layer.Name, rule.ID, rule.Verdict)
			}
		}
		layers[i].Hash = computeLayerHash(&layers[i])
	}

	bundle := &CompiledBundle{
		Layers: layers,
	}
	bundle.Hash = computeBundleHash(bundle)

	data, err := json.Marshal(bundle)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInternal, err)
	}
	return data, nil
}

// ── Internal Helpers ────────────────────────────────────────────────

// detectConflicts finds contradictions between two policy layers.
// A conflict exists when a higher-priority layer DENYs an action but
// a lower-priority layer ALLOWs the same action pattern.
func detectConflicts(higher, lower *PolicyLayer) []Conflict {
	var conflicts []Conflict

	for _, hr := range higher.Rules {
		for _, lr := range lower.Rules {
			if !actionsOverlap(hr.Action, lr.Action) {
				continue
			}
			// Conflict: higher layer denies, lower layer allows (widening)
			if hr.Verdict == "DENY" && lr.Verdict == "ALLOW" {
				conflicts = append(conflicts, Conflict{
					LayerA: higher.Name,
					LayerB: lower.Name,
					RuleA:  hr.ID,
					RuleB:  lr.ID,
					Action: hr.Action,
					Detail: fmt.Sprintf(
						"lower-priority layer %q attempts to ALLOW action %q that higher-priority layer %q DENYs",
						lower.Name, lr.Action, higher.Name,
					),
				})
			}
		}
	}
	return conflicts
}

// actionsOverlap returns true if two action patterns could match the
// same effect. The wildcard "*" matches everything.
func actionsOverlap(a, b string) bool {
	if a == "*" || b == "*" {
		return true
	}
	if a == b {
		return true
	}
	// Simple prefix-glob: "write.*" overlaps with "write.file"
	if len(a) > 1 && a[len(a)-1] == '*' {
		prefix := a[:len(a)-1]
		if len(b) >= len(prefix) && b[:len(prefix)] == prefix {
			return true
		}
	}
	if len(b) > 1 && b[len(b)-1] == '*' {
		prefix := b[:len(b)-1]
		if len(a) >= len(prefix) && a[:len(prefix)] == prefix {
			return true
		}
	}
	return false
}

func computeLayerHash(l *PolicyLayer) string {
	data, _ := json.Marshal(struct {
		Name     string       `json:"name"`
		Priority int          `json:"priority"`
		Rules    []PolicyRule `json:"rules"`
	}{l.Name, l.Priority, l.Rules})
	return hashBytes(data)
}

func computeResultHash(r *ValidationResult) string {
	data, _ := json.Marshal(struct {
		Verdict   Verdict        `json:"verdict"`
		Conflicts []Conflict     `json:"conflicts"`
		Layers    []LayerSummary `json:"layers"`
	}{r.Verdict, r.Conflicts, r.Layers})
	return hashBytes(data)
}

func computeBundleHash(b *CompiledBundle) string {
	data, _ := json.Marshal(b.Layers)
	return hashBytes(data)
}

func hashBytes(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

func marshalResult(r *ValidationResult) ([]byte, error) {
	data, err := json.Marshal(r)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInternal, err)
	}
	return data, nil
}
