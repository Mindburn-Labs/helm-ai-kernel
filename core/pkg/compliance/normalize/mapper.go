package normalize

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"
)

// ChangeType indicates what changed between two canonical snapshots.
type ChangeType string

const (
	ChangeAdded    ChangeType = "ADDED"
	ChangeModified ChangeType = "MODIFIED"
	ChangeRemoved  ChangeType = "REMOVED"
)

// Change represents a single detected change in a source.
type Change struct {
	ChangeType ChangeType      `json:"change_type"`
	RecordID   string          `json:"record_id"`
	SourceID   string          `json:"source_id"`
	Field      string          `json:"field,omitempty"` // Which field changed (for MODIFIED)
	OldHash    string          `json:"old_hash,omitempty"`
	NewHash    string          `json:"new_hash,omitempty"`
	DetectedAt time.Time       `json:"detected_at"`
	Diff       json.RawMessage `json:"diff,omitempty"` // Reviewable diff artifact
}

// ChangeSet is the typed output of change detection between two snapshots.
type ChangeSet struct {
	SourceID    string    `json:"source_id"`
	PriorHash   string    `json:"prior_hash"`
	CurrentHash string    `json:"current_hash"`
	Changes     []Change  `json:"changes"`
	DetectedAt  time.Time `json:"detected_at"`
	IsEmpty     bool      `json:"is_empty"`
}

// Mapper provides the source→canonical mapping pipeline.
type Mapper struct {
	mappingProfiles map[string]*MappingProfile
}

// MappingProfile defines how a source's raw data maps to canonical records.
type MappingProfile struct {
	SourceID        string            `json:"source_id"`
	TargetSchema    string            `json:"target_schema"`
	FieldMappings   map[string]string `json:"field_mappings"`
	Transformations []string          `json:"transformations"`
	ParserHints     map[string]string `json:"parser_hints,omitempty"`
}

// NewMapper creates a new normalization mapper.
func NewMapper() *Mapper {
	return &Mapper{
		mappingProfiles: make(map[string]*MappingProfile),
	}
}

// RegisterProfile registers a mapping profile for a source.
func (m *Mapper) RegisterProfile(profile *MappingProfile) error {
	if profile == nil || profile.SourceID == "" {
		return fmt.Errorf("invalid mapping profile")
	}
	m.mappingProfiles[profile.SourceID] = profile
	return nil
}

// GetProfile retrieves a mapping profile by source ID.
func (m *Mapper) GetProfile(sourceID string) (*MappingProfile, bool) {
	p, ok := m.mappingProfiles[sourceID]
	return p, ok
}

// HashContent produces a deterministic SHA-256 hash of content.
func HashContent(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

// DetectChanges compares two sets of canonical records and emits a ChangeSet.
func DetectChanges(sourceID string, prior, current map[string]string) *ChangeSet {
	cs := &ChangeSet{
		SourceID:    sourceID,
		PriorHash:   hashMap(prior),
		CurrentHash: hashMap(current),
		DetectedAt:  time.Now(),
	}

	// Detect additions and modifications
	for id, hash := range current {
		oldHash, exists := prior[id]
		if !exists {
			cs.Changes = append(cs.Changes, Change{
				ChangeType: ChangeAdded,
				RecordID:   id,
				SourceID:   sourceID,
				NewHash:    hash,
				DetectedAt: time.Now(),
			})
		} else if oldHash != hash {
			cs.Changes = append(cs.Changes, Change{
				ChangeType: ChangeModified,
				RecordID:   id,
				SourceID:   sourceID,
				OldHash:    oldHash,
				NewHash:    hash,
				DetectedAt: time.Now(),
			})
		}
	}

	// Detect removals
	for id, hash := range prior {
		if _, exists := current[id]; !exists {
			cs.Changes = append(cs.Changes, Change{
				ChangeType: ChangeRemoved,
				RecordID:   id,
				SourceID:   sourceID,
				OldHash:    hash,
				DetectedAt: time.Now(),
			})
		}
	}

	cs.IsEmpty = len(cs.Changes) == 0
	return cs
}

func hashMap(m map[string]string) string {
	data, _ := json.Marshal(m)
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}
