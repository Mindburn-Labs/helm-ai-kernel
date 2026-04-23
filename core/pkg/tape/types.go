// Package tape provides the VCR Tape primitive per §5.
// During live execution, the recorder captures nondeterministic inputs.
// During replay, the replayer serves taped outputs and blocks external I/O.
package tape

import "time"

// EntryType classifies what kind of nondeterministic input was captured.
type EntryType string

const (
	EntryTypeTime       EntryType = "TIME"
	EntryTypeRNGSeed    EntryType = "RNG_SEED"
	EntryTypeNetwork    EntryType = "NETWORK"
	EntryTypeToolOutput EntryType = "TOOL_OUTPUT"
	EntryTypeDBRead     EntryType = "DB_READ"
	EntryTypeEnvVar     EntryType = "ENV_VAR"
	EntryTypeFileRead   EntryType = "FILE_READ"
)

// Entry is a single recorded nondeterministic input.
// Tape artifacts MUST declare data_class, residency_region, encryption,
// and retention_basis per §tape-residency so jurisdiction/data handling
// can be enforced. PASS condition: no taped payload that violates
// jurisdiction/data handling rules.
type Entry struct {
	Seq             uint64    `json:"seq"`
	Type            EntryType `json:"type"`
	ComponentID     string    `json:"component_id"`
	Key             string    `json:"key"`
	ValueHash       string    `json:"value_hash"`
	Value           []byte    `json:"value,omitempty"`
	Timestamp       time.Time `json:"timestamp"`
	DataClass       string    `json:"data_class"`       // REQUIRED: PII, CONFIDENTIAL, PUBLIC, etc.
	ResidencyRegion string    `json:"residency_region"` // REQUIRED: ISO 3166-1 alpha-2 code
	Encryption      string    `json:"encryption"`       // REQUIRED: AES-256-GCM, NONE, etc.
	RetentionBasis  string    `json:"retention_basis"`  // REQUIRED: legal basis for retention
}

// Manifest is the tape_manifest.json structure per §5.3.
type Manifest struct {
	RunID   string         `json:"run_id"`
	Entries []ManifestItem `json:"entries"`
}

// ManifestItem references a tape entry with its hash.
type ManifestItem struct {
	Seq       uint64    `json:"seq"`
	Type      EntryType `json:"type"`
	Key       string    `json:"key"`
	SHA256    string    `json:"sha256"`
	SizeBytes int64     `json:"size_bytes"`
}

// Ref is a reference to a tape entry, stored in receipt envelopes.
type Ref struct {
	Seq  uint64 `json:"seq"`
	Hash string `json:"hash"`
}
