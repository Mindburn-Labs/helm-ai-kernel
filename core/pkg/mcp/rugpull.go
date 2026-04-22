// rugpull.go implements rug-pull detection for MCP tool definitions.
// A rug-pull occurs when a tool's description, schema, or capabilities
// change between sessions without explicit version updates.
//
// Detection method: cryptographic fingerprinting of tool definitions.
// Each tool's (serverID, name, description, inputSchema) is SHA-256 hashed.
// Changes trigger a RugPullFinding with severity proportional to change scope.
//
// Design invariants:
//   - First-seen definitions establish the baseline (trust-on-first-use)
//   - Any change after first-seen produces a finding
//   - Findings are informational — Guardian/PDP makes the verdict
//   - Thread-safe for concurrent server connections
//   - Deterministic: same tool definition → same fingerprint
package mcp

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"
	"time"
)

// RugPullSeverity classifies the severity of a detected tool definition change.
type RugPullSeverity string

const (
	// RugPullSeverityLow indicates a minor change (reserved for future granularity).
	RugPullSeverityLow RugPullSeverity = "LOW"
	// RugPullSeverityMedium indicates a description-only change.
	RugPullSeverityMedium RugPullSeverity = "MEDIUM"
	// RugPullSeverityHigh indicates a schema-only change.
	RugPullSeverityHigh RugPullSeverity = "HIGH"
	// RugPullSeverityCritical indicates both description and schema changed.
	RugPullSeverityCritical RugPullSeverity = "CRITICAL"
)

// RugPullChange classifies the type of tool definition mutation detected.
type RugPullChange string

const (
	// RugPullChangeDescription indicates only the description changed.
	RugPullChangeDescription RugPullChange = "DESCRIPTION_CHANGED"
	// RugPullChangeSchema indicates only the input schema changed.
	RugPullChangeSchema RugPullChange = "SCHEMA_CHANGED"
	// RugPullChangeBoth indicates both description and schema changed.
	RugPullChangeBoth RugPullChange = "BOTH_CHANGED"
	// RugPullChangeNew indicates a new tool was seen for the first time.
	RugPullChangeNew RugPullChange = "NEW_TOOL"
	// RugPullChangeRemoved indicates a previously registered tool is no longer present.
	RugPullChangeRemoved RugPullChange = "TOOL_REMOVED"
)

// ToolFingerprint is the cryptographic fingerprint of a tool definition at a point in time.
type ToolFingerprint struct {
	ServerID        string    `json:"server_id"`
	ToolName        string    `json:"tool_name"`
	DescriptionHash string    `json:"description_hash"` // sha256 of description
	SchemaHash      string    `json:"schema_hash"`      // sha256 of canonical JSON schema
	CombinedHash    string    `json:"combined_hash"`    // sha256 of (descHash + schemaHash)
	Version         int       `json:"version"`          // Incremented on change
	FirstSeen       time.Time `json:"first_seen"`
	LastSeen        time.Time `json:"last_seen"`
	LastChanged     time.Time `json:"last_changed,omitempty"`
}

// RugPullFinding describes a detected tool definition mutation.
type RugPullFinding struct {
	ServerID        string          `json:"server_id"`
	ToolName        string          `json:"tool_name"`
	Severity        RugPullSeverity `json:"severity"`
	ChangeType      RugPullChange   `json:"change_type"`
	PreviousHash    string          `json:"previous_hash"`
	CurrentHash     string          `json:"current_hash"`
	PreviousVersion int             `json:"previous_version"`
	CurrentVersion  int             `json:"current_version"`
	DetectedAt      time.Time       `json:"detected_at"`
	Description     string          `json:"description"`
}

// ToolDefinition is the input representation of an MCP tool for rug-pull detection.
type ToolDefinition struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	InputSchema json.RawMessage `json:"input_schema,omitempty"`
}

// RugPullOption configures optional RugPullDetector settings.
type RugPullOption func(*RugPullDetector)

// RugPullDetector tracks tool definition fingerprints and detects mutations.
type RugPullDetector struct {
	mu           sync.RWMutex
	fingerprints map[string]*ToolFingerprint // key: serverID + ":" + toolName
	clock        func() time.Time
}

// NewRugPullDetector creates a new rug-pull detector with the given options.
func NewRugPullDetector(opts ...RugPullOption) *RugPullDetector {
	d := &RugPullDetector{
		fingerprints: make(map[string]*ToolFingerprint),
		clock:        time.Now,
	}
	for _, opt := range opts {
		opt(d)
	}
	return d
}

// WithDetectorClock injects a deterministic clock for testing.
func WithDetectorClock(clock func() time.Time) RugPullOption {
	return func(d *RugPullDetector) {
		d.clock = clock
	}
}

// RegisterTool registers or updates a tool definition fingerprint.
// On first registration (trust-on-first-use), it returns nil.
// If the definition matches the existing fingerprint, it returns nil.
// If the definition has changed, it returns a RugPullFinding describing the mutation.
func (d *RugPullDetector) RegisterTool(serverID, toolName, description string, schema json.RawMessage) (*RugPullFinding, error) {
	if serverID == "" {
		return nil, fmt.Errorf("rugpull: server ID is required")
	}
	if toolName == "" {
		return nil, fmt.Errorf("rugpull: tool name is required")
	}

	descHash := hashContent([]byte(description))
	schemaHash := canonicalSchemaHash(schema)
	combined := combineHashes(descHash, schemaHash)
	now := d.clock()
	key := fingerprintKey(serverID, toolName)

	d.mu.Lock()
	defer d.mu.Unlock()

	existing, found := d.fingerprints[key]
	if !found {
		// Trust-on-first-use: establish baseline.
		d.fingerprints[key] = &ToolFingerprint{
			ServerID:        serverID,
			ToolName:        toolName,
			DescriptionHash: descHash,
			SchemaHash:      schemaHash,
			CombinedHash:    combined,
			Version:         1,
			FirstSeen:       now,
			LastSeen:        now,
		}
		slog.Debug("rugpull: tool registered (first-seen)",
			"server_id", serverID,
			"tool", toolName,
			"combined_hash", combined,
		)
		return nil, nil
	}

	// Update last-seen timestamp regardless of change.
	existing.LastSeen = now

	// No change — fingerprint matches.
	if existing.CombinedHash == combined {
		return nil, nil
	}

	// Mutation detected — classify the change.
	descChanged := existing.DescriptionHash != descHash
	schemaChanged := existing.SchemaHash != schemaHash

	var changeType RugPullChange
	var severity RugPullSeverity
	switch {
	case descChanged && schemaChanged:
		changeType = RugPullChangeBoth
		severity = RugPullSeverityCritical
	case schemaChanged:
		changeType = RugPullChangeSchema
		severity = RugPullSeverityHigh
	case descChanged:
		changeType = RugPullChangeDescription
		severity = RugPullSeverityMedium
	}

	previousHash := existing.CombinedHash
	previousVersion := existing.Version
	newVersion := previousVersion + 1

	// Update the stored fingerprint to the new definition.
	existing.DescriptionHash = descHash
	existing.SchemaHash = schemaHash
	existing.CombinedHash = combined
	existing.Version = newVersion
	existing.LastChanged = now

	finding := &RugPullFinding{
		ServerID:        serverID,
		ToolName:        toolName,
		Severity:        severity,
		ChangeType:      changeType,
		PreviousHash:    previousHash,
		CurrentHash:     combined,
		PreviousVersion: previousVersion,
		CurrentVersion:  newVersion,
		DetectedAt:      now,
		Description:     fmt.Sprintf("tool %q on server %q: %s (v%d → v%d)", toolName, serverID, changeType, previousVersion, newVersion),
	}

	slog.Warn("rugpull: tool definition mutation detected",
		"server_id", serverID,
		"tool", toolName,
		"severity", severity,
		"change_type", changeType,
		"previous_version", previousVersion,
		"current_version", newVersion,
	)

	return finding, nil
}

// CheckServer checks all tools from a server against stored fingerprints.
// It detects new tools, changed tools, and tools that were previously registered
// but are now absent (TOOL_REMOVED). Returns all findings; an empty slice means
// no mutations were detected.
func (d *RugPullDetector) CheckServer(serverID string, tools []ToolDefinition) []RugPullFinding {
	var findings []RugPullFinding
	now := d.clock()

	// Track which tools are present in this check.
	presentTools := make(map[string]bool, len(tools))

	// Register/check each tool.
	for _, tool := range tools {
		presentTools[tool.Name] = true
		finding, err := d.RegisterTool(serverID, tool.Name, tool.Description, tool.InputSchema)
		if err != nil {
			slog.Error("rugpull: failed to register tool during server check",
				"server_id", serverID,
				"tool", tool.Name,
				"error", err,
			)
			continue
		}
		if finding != nil {
			findings = append(findings, *finding)
		}
	}

	// Detect removed tools: find fingerprints for this server that are
	// not in the current tool set.
	d.mu.RLock()
	var removedKeys []string
	for key, fp := range d.fingerprints {
		if fp.ServerID == serverID && !presentTools[fp.ToolName] {
			removedKeys = append(removedKeys, key)
		}
	}
	d.mu.RUnlock()

	for _, key := range removedKeys {
		d.mu.RLock()
		fp, ok := d.fingerprints[key]
		if !ok {
			d.mu.RUnlock()
			continue
		}
		finding := RugPullFinding{
			ServerID:        serverID,
			ToolName:        fp.ToolName,
			Severity:        RugPullSeverityHigh,
			ChangeType:      RugPullChangeRemoved,
			PreviousHash:    fp.CombinedHash,
			CurrentHash:     "",
			PreviousVersion: fp.Version,
			CurrentVersion:  fp.Version,
			DetectedAt:      now,
			Description:     fmt.Sprintf("tool %q on server %q: previously registered tool is no longer present", fp.ToolName, serverID),
		}
		d.mu.RUnlock()

		slog.Warn("rugpull: tool removed from server",
			"server_id", serverID,
			"tool", fp.ToolName,
			"previous_version", fp.Version,
		)

		findings = append(findings, finding)
	}

	return findings
}

// GetFingerprint returns the stored fingerprint for a server+tool combination.
// The second return value indicates whether the fingerprint was found.
func (d *RugPullDetector) GetFingerprint(serverID, toolName string) (*ToolFingerprint, bool) {
	key := fingerprintKey(serverID, toolName)

	d.mu.RLock()
	defer d.mu.RUnlock()

	fp, ok := d.fingerprints[key]
	if !ok {
		return nil, false
	}

	// Return a copy to prevent external mutation.
	copied := *fp
	return &copied, true
}

// AllFingerprints returns a snapshot of all stored fingerprints.
// The returned map is a shallow copy — callers may mutate the map itself
// but should not modify the ToolFingerprint values.
func (d *RugPullDetector) AllFingerprints() map[string]*ToolFingerprint {
	d.mu.RLock()
	defer d.mu.RUnlock()

	snapshot := make(map[string]*ToolFingerprint, len(d.fingerprints))
	for key, fp := range d.fingerprints {
		copied := *fp
		snapshot[key] = &copied
	}
	return snapshot
}

// Reset clears all stored fingerprints.
func (d *RugPullDetector) Reset() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.fingerprints = make(map[string]*ToolFingerprint)
}

// fingerprintKey builds the map key for a server+tool pair.
func fingerprintKey(serverID, toolName string) string {
	return serverID + ":" + toolName
}

// hashContent computes a SHA-256 hash of the given data and returns it
// in the format "sha256:<hex>".
func hashContent(data []byte) string {
	h := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(h[:])
}

// combineHashes concatenates the given hash strings and computes a
// SHA-256 hash of the concatenation, returning "sha256:<hex>".
func combineHashes(hashes ...string) string {
	h := sha256.New()
	for _, hash := range hashes {
		h.Write([]byte(hash))
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil))
}

// canonicalSchemaHash computes a SHA-256 hash of a JSON schema after
// canonical re-encoding. Null or empty schemas are hashed as the empty
// string to ensure deterministic fingerprints.
func canonicalSchemaHash(schema json.RawMessage) string {
	if len(schema) == 0 {
		return hashContent(nil)
	}

	// Re-marshal through any to get canonical (sorted-key) JSON output
	// from encoding/json, which sorts map keys deterministically.
	var canonical any
	if err := json.Unmarshal(schema, &canonical); err != nil {
		// If the schema is not valid JSON, hash it as-is.
		return hashContent(schema)
	}

	encoded, err := json.Marshal(canonical)
	if err != nil {
		return hashContent(schema)
	}
	return hashContent(encoded)
}
