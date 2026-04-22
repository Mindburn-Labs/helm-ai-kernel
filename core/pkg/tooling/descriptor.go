// Package tooling provides canonical tool binding infrastructure.
// Per Section 4 - Tool binding layer with fingerprinting and normalization.
package tooling

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"sort"
)

// ToolDescriptor defines a canonical, hashable tool binding.
type ToolDescriptor struct {
	ToolID             string            `json:"tool_id"`
	Version            string            `json:"version"`
	Endpoint           string            `json:"endpoint"`
	AuthMethodClass    string            `json:"auth_method_class"`
	DeterministicFlags []string          `json:"deterministic_flags"`
	CostEnvelope       CostEnvelope      `json:"cost_envelope"`
	InputSchemaHash    string            `json:"input_schema_hash"`
	OutputSchemaHash   string            `json:"output_schema_hash"`
	Metadata           map[string]string `json:"metadata,omitempty"`
}

// CostEnvelope defines the expected cost/resource bounds for a tool.
type CostEnvelope struct {
	MaxLatencyMs int     `json:"max_latency_ms"`
	MaxCostUnits float64 `json:"max_cost_units"`
	MaxTokens    int     `json:"max_tokens,omitempty"`
	RateLimitRPS float64 `json:"rate_limit_rps,omitempty"`
	CostCurrency string  `json:"cost_currency,omitempty"`
	CostPerCall  float64 `json:"cost_per_call,omitempty"`
}

// Fingerprint computes a deterministic SHA-256 hash of the ToolDescriptor.
// This fingerprint becomes part of the receipt preimage.
func (t *ToolDescriptor) Fingerprint() string {
	// Create a canonical representation for hashing
	canonical := struct {
		ToolID             string       `json:"tool_id"`
		Version            string       `json:"version"`
		Endpoint           string       `json:"endpoint"`
		AuthMethodClass    string       `json:"auth_method_class"`
		DeterministicFlags []string     `json:"deterministic_flags"`
		CostEnvelope       CostEnvelope `json:"cost_envelope"`
		InputSchemaHash    string       `json:"input_schema_hash"`
		OutputSchemaHash   string       `json:"output_schema_hash"`
	}{
		ToolID:             t.ToolID,
		Version:            t.Version,
		Endpoint:           t.Endpoint,
		AuthMethodClass:    t.AuthMethodClass,
		DeterministicFlags: t.deterministicFlagsSorted(),
		CostEnvelope:       t.CostEnvelope,
		InputSchemaHash:    t.InputSchemaHash,
		OutputSchemaHash:   t.OutputSchemaHash,
	}

	data, err := CanonicalJSON(canonical)
	if err != nil {
		// Log degradation instead of silently falling back
		slog.Error("tooling: canonical JSON failed for fingerprint, using fallback",
			"tool_id", t.ToolID,
			"error", err,
		)
		data = []byte(fmt.Sprintf("%s:%s:%s:%s",
			t.ToolID, t.Version, t.Endpoint, t.InputSchemaHash))
	}

	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

// deterministicFlagsSorted returns a sorted copy of deterministic flags.
func (t *ToolDescriptor) deterministicFlagsSorted() []string {
	if t.DeterministicFlags == nil {
		return []string{}
	}
	sorted := make([]string, len(t.DeterministicFlags))
	copy(sorted, t.DeterministicFlags)
	sort.Strings(sorted)
	return sorted
}

// Validate checks if the ToolDescriptor is valid.
func (t *ToolDescriptor) Validate() error {
	if t.ToolID == "" {
		return fmt.Errorf("tool_id is required")
	}
	if t.Version == "" {
		return fmt.Errorf("version is required")
	}
	if t.Endpoint == "" {
		return fmt.Errorf("endpoint is required")
	}
	if t.InputSchemaHash == "" {
		return fmt.Errorf("input_schema_hash is required")
	}
	if t.OutputSchemaHash == "" {
		return fmt.Errorf("output_schema_hash is required")
	}
	return nil
}

// HasChanged compares two descriptors to detect if reevaluation is needed.
func (t *ToolDescriptor) HasChanged(other *ToolDescriptor) bool {
	return t.Fingerprint() != other.Fingerprint()
}

// ToolRegistry manages registered tool descriptors.
type ToolRegistry struct {
	tools      map[string]*ToolDescriptor
	byCategory map[string][]string
}

// NewToolRegistry creates a new tool registry.
func NewToolRegistry() *ToolRegistry {
	return &ToolRegistry{
		tools:      make(map[string]*ToolDescriptor),
		byCategory: make(map[string][]string),
	}
}

// Register adds or updates a tool in the registry.
func (r *ToolRegistry) Register(tool *ToolDescriptor) error {
	if err := tool.Validate(); err != nil {
		return fmt.Errorf("invalid tool descriptor: %w", err)
	}
	r.tools[tool.ToolID] = tool
	return nil
}

// Get retrieves a tool by ID.
func (r *ToolRegistry) Get(toolID string) (*ToolDescriptor, bool) {
	tool, ok := r.tools[toolID]
	return tool, ok
}

// GetFingerprint returns the fingerprint of a registered tool.
func (r *ToolRegistry) GetFingerprint(toolID string) (string, bool) {
	tool, ok := r.tools[toolID]
	if !ok {
		return "", false
	}
	return tool.Fingerprint(), true
}

// List returns all registered tool IDs.
func (r *ToolRegistry) List() []string {
	ids := make([]string, 0, len(r.tools))
	for id := range r.tools {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// ToolChangeDetector enforces policy reevaluation when tool fingerprints change.
// Per Section 4.3: "tool changed → policy reevaluation required"
type ToolChangeDetector struct {
	knownFingerprints    map[string]string // toolID -> last_known_fingerprint
	pendingReevaluations map[string]bool   // toolID -> needs_reevaluation
}

// NewToolChangeDetector creates a detector with empty baseline.
func NewToolChangeDetector() *ToolChangeDetector {
	return &ToolChangeDetector{
		knownFingerprints:    make(map[string]string),
		pendingReevaluations: make(map[string]bool),
	}
}

// RegisterBaseline records the current fingerprint as the known baseline.
func (d *ToolChangeDetector) RegisterBaseline(tool *ToolDescriptor) {
	d.knownFingerprints[tool.ToolID] = tool.Fingerprint()
	delete(d.pendingReevaluations, tool.ToolID)
}

// CheckForChange compares current tool fingerprint against baseline.
// If changed, marks tool as pending reevaluation and returns true.
func (d *ToolChangeDetector) CheckForChange(tool *ToolDescriptor) (bool, string) {
	fp := tool.Fingerprint()
	oldFP, known := d.knownFingerprints[tool.ToolID]

	if !known {
		// First time seeing this tool - register as baseline
		d.knownFingerprints[tool.ToolID] = fp
		return false, ""
	}

	if fp != oldFP {
		d.pendingReevaluations[tool.ToolID] = true
		return true, fmt.Sprintf("tool %s fingerprint changed: %s → %s", tool.ToolID, oldFP[:12], fp[:12])
	}

	return false, ""
}

// RequiresReevaluation returns true if the tool has changed and policy hasn't been reevaluated.
func (d *ToolChangeDetector) RequiresReevaluation(toolID string) bool {
	return d.pendingReevaluations[toolID]
}

// MarkReevaluated confirms policy reevaluation was completed, clearing the pending flag.
func (d *ToolChangeDetector) MarkReevaluated(tool *ToolDescriptor) {
	d.RegisterBaseline(tool) // Update baseline to new fingerprint
}

// ToolChangeError represents a blocked execution due to pending reevaluation.
type ToolChangeError struct {
	ToolID         string
	OldFingerprint string
	NewFingerprint string
	Message        string
}

func (e *ToolChangeError) Error() string {
	return fmt.Sprintf("tool_change_blocked: %s", e.Message)
}

// GateExecution blocks if tool requires reevaluation. Returns nil if safe to proceed.
// This is the fail-closed enforcement point.
func (d *ToolChangeDetector) GateExecution(tool *ToolDescriptor) error {
	if d.RequiresReevaluation(tool.ToolID) {
		oldFP := d.knownFingerprints[tool.ToolID]
		return &ToolChangeError{
			ToolID:         tool.ToolID,
			OldFingerprint: oldFP,
			NewFingerprint: tool.Fingerprint(),
			Message:        fmt.Sprintf("tool %s changed but policy not reevaluated", tool.ToolID),
		}
	}
	return nil
}
