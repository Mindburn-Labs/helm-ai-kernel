package sources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNormalizeURL(t *testing.T) {
	normalized, err := NormalizeURL("HTTPS://EXAMPLE.COM/Path?b=2&a=1#fragment")
	require.NoError(t, err)
	assert.Equal(t, "https://example.com/Path?b=2&a=1", normalized)
}

func TestContentHash(t *testing.T) {
	h := ContentHash([]byte("hello"))
	assert.Contains(t, h, "sha256:")
	assert.Len(t, h, 71) // "sha256:" + 64 hex chars
}
