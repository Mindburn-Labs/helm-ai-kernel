package sources

import (
	"testing"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/researchruntime"
	"github.com/stretchr/testify/assert"
)

func TestRegistry_DeduplicatesByHash(t *testing.T) {
	reg := NewRegistry()
	s1 := researchruntime.SourceSnapshot{SourceID: "s1", ContentHash: "abc123", CanonicalURL: "https://example.com/a"}
	s2 := researchruntime.SourceSnapshot{SourceID: "s2", ContentHash: "abc123", CanonicalURL: "https://example.com/a"}
	assert.False(t, reg.IsDuplicate(s1))
	reg.Register(s1)
	assert.True(t, reg.IsDuplicate(s2))
	assert.Equal(t, 1, reg.Count())
}

func TestRegistry_DeduplicatesByURL(t *testing.T) {
	reg := NewRegistry()
	s1 := researchruntime.SourceSnapshot{SourceID: "s1", ContentHash: "hash1", CanonicalURL: "https://example.com/page"}
	s2 := researchruntime.SourceSnapshot{SourceID: "s2", ContentHash: "hash2", CanonicalURL: "https://example.com/page"}
	reg.Register(s1)
	assert.True(t, reg.IsDuplicate(s2))
}

func TestRegistry_AllReturnsCopy(t *testing.T) {
	reg := NewRegistry()
	reg.Register(researchruntime.SourceSnapshot{SourceID: "s1", ContentHash: "h1", CanonicalURL: "u1"})
	reg.Register(researchruntime.SourceSnapshot{SourceID: "s2", ContentHash: "h2", CanonicalURL: "u2"})
	all := reg.All()
	assert.Len(t, all, 2)
}
