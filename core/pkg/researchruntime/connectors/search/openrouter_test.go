package search

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseSearchResults_ValidJSON(t *testing.T) {
	content := `Here are the results:
[{"url":"https://arxiv.org/abs/2401.00001","title":"HELM Paper","snippet":"A governance framework"},{"url":"https://github.com/helm","title":"HELM Repo","snippet":"Open source"}]`
	results, err := parseSearchResults(content, "test-model")
	require.NoError(t, err)
	assert.Len(t, results, 2)
	assert.Equal(t, "https://arxiv.org/abs/2401.00001", results[0].URL)
	assert.Equal(t, "HELM Paper", results[0].Title)
	assert.Equal(t, "test-model", results[0].Source)
}

func TestParseSearchResults_SkipsEmptyURL(t *testing.T) {
	content := `[{"url":"","title":"Bad"},{"url":"https://good.com","title":"Good","snippet":"ok"}]`
	results, err := parseSearchResults(content, "m")
	require.NoError(t, err)
	assert.Len(t, results, 1)
	assert.Equal(t, "https://good.com", results[0].URL)
}

func TestParseSearchResults_NoJSON(t *testing.T) {
	_, err := parseSearchResults("No results found", "m")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no JSON array")
}
