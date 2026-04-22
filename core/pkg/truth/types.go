package truth

import "time"

// ── Truth Object ───────────────────────────────────────────────

// TruthType classifies what kind of truth object this is.
type TruthType string

const (
	TruthTypePolicy      TruthType = "POLICY"
	TruthTypeSchema      TruthType = "SCHEMA"
	TruthTypeRegulation  TruthType = "REGULATION"
	TruthTypeOrgGenome   TruthType = "ORG_GENOME"
	TruthTypePackABI     TruthType = "PACK_ABI"
	TruthTypeAttestation TruthType = "ATTESTATION"
)

// TruthObject is an immutable versioned governance artifact.
// Once registered, truth objects are never modified — new versions
// create new objects with monotonically increasing version numbers.
type TruthObject struct {
	ObjectID      string           `json:"object_id"`
	Type          TruthType        `json:"type"`
	Name          string           `json:"name"`
	Version       VersionScope     `json:"version"`
	Content       []byte           `json:"content"`
	ContentHash   string           `json:"content_hash"`
	Freshness     FreshnessInfo    `json:"freshness"`
	Compatibility CompatibilityInfo `json:"compatibility"`
	Provenance    ProvenanceInfo   `json:"provenance"`
	RegisteredAt  time.Time        `json:"registered_at"`
	Signature     string           `json:"signature,omitempty"`
}

// VersionScope defines the versioning semantics for a truth object.
type VersionScope struct {
	Major    int    `json:"major"`
	Minor    int    `json:"minor"`
	Patch    int    `json:"patch"`
	Epoch    string `json:"epoch"`
	Label    string `json:"label,omitempty"` // "stable", "rc", "draft"
}

// String returns the semver representation.
func (v VersionScope) String() string {
	s := ""
	if v.Epoch != "" {
		s = v.Epoch + ":"
	}
	s += string(rune('0'+v.Major)) + "." + string(rune('0'+v.Minor)) + "." + string(rune('0'+v.Patch))
	if v.Label != "" {
		s += "-" + v.Label
	}
	return s
}

// FreshnessInfo tracks when a truth object was last validated.
type FreshnessInfo struct {
	LastValidated time.Time `json:"last_validated"`
	ValidUntil    time.Time `json:"valid_until"`
	Stale         bool      `json:"stale"`
}

// CompatibilityInfo describes backward/forward compatibility.
type CompatibilityInfo struct {
	BreakingChange  bool     `json:"breaking_change"`
	DeprecatedSince string   `json:"deprecated_since,omitempty"`
	ReplacedBy      string   `json:"replaced_by,omitempty"`
	CompatibleWith  []string `json:"compatible_with,omitempty"`
}

// ProvenanceInfo records who created/signed the truth object.
type ProvenanceInfo struct {
	AuthorID  string `json:"author_id"`
	SourceRef string `json:"source_ref,omitempty"` // Git commit, document URI, etc.
	Tool      string `json:"tool,omitempty"`       // "orgdna-compiler", "manual", etc.
}

// ── Truth Registry Interface ───────────────────────────────────

// Registry is the canonical interface for the versioned truth store.
type Registry interface {
	// Register adds a new truth object. Returns error if the object ID
	// already exists (truth objects are immutable).
	Register(obj *TruthObject) error

	// Get returns a truth object by ID. Returns nil if not found.
	Get(objectID string) (*TruthObject, error)

	// GetLatest returns the latest version of a truth object by name and type.
	GetLatest(truthType TruthType, name string) (*TruthObject, error)

	// List returns all truth objects matching the given type.
	List(truthType TruthType) ([]*TruthObject, error)

	// GetAtEpoch returns the truth object that was active at a given epoch.
	GetAtEpoch(truthType TruthType, name string, epoch string) (*TruthObject, error)
}

// ── Annotation Lineage ─────────────────────────────────────────

// LineageEntry tracks how a truth object relates to others.
type LineageEntry struct {
	EntryID     string    `json:"entry_id"`
	ObjectID    string    `json:"object_id"`
	ParentID    string    `json:"parent_id,omitempty"`
	Relation    string    `json:"relation"` // "DERIVED_FROM", "SUPERSEDES", "AMENDS"
	Annotation  string    `json:"annotation,omitempty"`
	RecordedAt  time.Time `json:"recorded_at"`
	RecordedBy  string    `json:"recorded_by"`
}

// InMemoryRegistry is a simple in-memory truth registry for testing
// and single-node deployments.
type InMemoryRegistry struct {
	objects map[string]*TruthObject
}

// NewInMemoryRegistry creates a new in-memory truth registry.
func NewInMemoryRegistry() *InMemoryRegistry {
	return &InMemoryRegistry{objects: make(map[string]*TruthObject)}
}

// Register adds a truth object. Returns error if already exists.
func (r *InMemoryRegistry) Register(obj *TruthObject) error {
	if _, exists := r.objects[obj.ObjectID]; exists {
		return &DuplicateObjectError{ObjectID: obj.ObjectID}
	}
	r.objects[obj.ObjectID] = obj
	return nil
}

// Get returns a truth object by ID.
func (r *InMemoryRegistry) Get(objectID string) (*TruthObject, error) {
	obj, ok := r.objects[objectID]
	if !ok {
		return nil, nil
	}
	return obj, nil
}

// GetLatest returns the latest version by name and type (linear scan).
func (r *InMemoryRegistry) GetLatest(truthType TruthType, name string) (*TruthObject, error) {
	var latest *TruthObject
	for _, obj := range r.objects {
		if obj.Type == truthType && obj.Name == name {
			if latest == nil || obj.RegisteredAt.After(latest.RegisteredAt) {
				latest = obj
			}
		}
	}
	return latest, nil
}

// List returns all objects of a given type.
func (r *InMemoryRegistry) List(truthType TruthType) ([]*TruthObject, error) {
	var result []*TruthObject
	for _, obj := range r.objects {
		if obj.Type == truthType {
			result = append(result, obj)
		}
	}
	return result, nil
}

// GetAtEpoch returns the truth object active at the specified epoch.
func (r *InMemoryRegistry) GetAtEpoch(truthType TruthType, name string, epoch string) (*TruthObject, error) {
	for _, obj := range r.objects {
		if obj.Type == truthType && obj.Name == name && obj.Version.Epoch == epoch {
			return obj, nil
		}
	}
	return nil, nil
}

// DuplicateObjectError is returned when attempting to register a duplicate.
type DuplicateObjectError struct {
	ObjectID string
}

func (e *DuplicateObjectError) Error() string {
	return "truth object already exists: " + e.ObjectID
}
