package normalize

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNewMapper(t *testing.T) {
	m := NewMapper()
	require.NotNil(t, m)
}

func TestRegisterProfile(t *testing.T) {
	m := NewMapper()
	profile := &MappingProfile{
		SourceID:     "eu-eurlex",
		TargetSchema: "helm://schemas/compliance/LegalSourceRecord.v1",
		FieldMappings: map[string]string{
			"celex_id":       "document_id",
			"title":          "title",
			"effective_date": "effective_date",
		},
		Transformations: []string{"normalize_dates", "extract_amendments"},
	}

	err := m.RegisterProfile(profile)
	require.NoError(t, err)

	retrieved, ok := m.GetProfile("eu-eurlex")
	require.True(t, ok)
	require.Equal(t, "helm://schemas/compliance/LegalSourceRecord.v1", retrieved.TargetSchema)
	require.Len(t, retrieved.FieldMappings, 3)
}

func TestRegisterProfile_Nil(t *testing.T) {
	m := NewMapper()
	err := m.RegisterProfile(nil)
	require.Error(t, err)
}

func TestRegisterProfile_EmptySourceID(t *testing.T) {
	m := NewMapper()
	err := m.RegisterProfile(&MappingProfile{})
	require.Error(t, err)
}

func TestGetProfile_NotFound(t *testing.T) {
	m := NewMapper()
	_, ok := m.GetProfile("nonexistent")
	require.False(t, ok)
}

func TestHashContent(t *testing.T) {
	hash1 := HashContent([]byte("hello world"))
	hash2 := HashContent([]byte("hello world"))
	hash3 := HashContent([]byte("different"))

	require.NotEmpty(t, hash1)
	require.Equal(t, hash1, hash2)    // Deterministic
	require.NotEqual(t, hash1, hash3) // Different input → different hash
	require.Len(t, hash1, 64)         // SHA-256 hex = 64 chars
}

func TestDetectChanges_Added(t *testing.T) {
	prior := map[string]string{}
	current := map[string]string{"doc-1": "hash-a"}

	cs := DetectChanges("eu-eurlex", prior, current)
	require.False(t, cs.IsEmpty)
	require.Len(t, cs.Changes, 1)
	require.Equal(t, ChangeAdded, cs.Changes[0].ChangeType)
	require.Equal(t, "doc-1", cs.Changes[0].RecordID)
}

func TestDetectChanges_Modified(t *testing.T) {
	prior := map[string]string{"doc-1": "hash-a"}
	current := map[string]string{"doc-1": "hash-b"}

	cs := DetectChanges("eu-eurlex", prior, current)
	require.False(t, cs.IsEmpty)
	require.Len(t, cs.Changes, 1)
	require.Equal(t, ChangeModified, cs.Changes[0].ChangeType)
	require.Equal(t, "hash-a", cs.Changes[0].OldHash)
	require.Equal(t, "hash-b", cs.Changes[0].NewHash)
}

func TestDetectChanges_Removed(t *testing.T) {
	prior := map[string]string{"doc-1": "hash-a"}
	current := map[string]string{}

	cs := DetectChanges("eu-eurlex", prior, current)
	require.False(t, cs.IsEmpty)
	require.Len(t, cs.Changes, 1)
	require.Equal(t, ChangeRemoved, cs.Changes[0].ChangeType)
}

func TestDetectChanges_NoChanges(t *testing.T) {
	data := map[string]string{"doc-1": "hash-a", "doc-2": "hash-b"}

	cs := DetectChanges("eu-eurlex", data, data)
	require.True(t, cs.IsEmpty)
	require.Empty(t, cs.Changes)
}

func TestDetectChanges_Mixed(t *testing.T) {
	prior := map[string]string{
		"doc-1": "hash-a",
		"doc-2": "hash-b",
		"doc-3": "hash-c",
	}
	current := map[string]string{
		"doc-1": "hash-a",  // unchanged
		"doc-2": "hash-bb", // modified
		"doc-4": "hash-d",  // added
		// doc-3 removed
	}

	cs := DetectChanges("eu-eurlex", prior, current)
	require.False(t, cs.IsEmpty)
	require.Len(t, cs.Changes, 3) // 1 modified + 1 added + 1 removed
	require.NotEqual(t, cs.PriorHash, cs.CurrentHash)
}

func TestChangeTypeConstants(t *testing.T) {
	require.Equal(t, ChangeType("ADDED"), ChangeAdded)
	require.Equal(t, ChangeType("MODIFIED"), ChangeModified)
	require.Equal(t, ChangeType("REMOVED"), ChangeRemoved)
}
