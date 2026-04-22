package publish

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSlugify(t *testing.T) {
	assert.Equal(t, "hello-world", slugify("Hello World"))
	assert.Equal(t, "test-123", slugify("Test 123"))
	assert.Equal(t, "helm-ai-governance", slugify("HELM AI Governance"))
}

func TestTruncHash(t *testing.T) {
	assert.Equal(t, "abcdef123456", truncHash("abcdef123456789"))
	assert.Equal(t, "short", truncHash("short"))
	assert.Equal(t, "exactly12cha", truncHash("exactly12cha"))
}
