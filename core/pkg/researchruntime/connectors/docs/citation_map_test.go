package docs

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExtractCitationMap_ParsesLinks(t *testing.T) {
	h := `<html><body>
        <a href="https://arxiv.org/abs/2401.00001">Source A</a>
        <a href="/relative">Relative link</a>
        <a href="#anchor">Skip anchor</a>
        <a href="javascript:void(0)">Skip JS</a>
    </body></html>`
	cm, err := ExtractCitationMap(strings.NewReader(h), "https://example.com")
	require.NoError(t, err)
	assert.Len(t, cm.Links, 2)
	assert.Equal(t, "https://arxiv.org/abs/2401.00001", cm.Links[0].URL)
	assert.Equal(t, "Source A", cm.Links[0].Text)
	assert.Equal(t, "https://example.com/relative", cm.Links[1].URL)
}

func TestExtractCitationMap_EmptyPage(t *testing.T) {
	cm, err := ExtractCitationMap(strings.NewReader("<html><body></body></html>"), "https://example.com")
	require.NoError(t, err)
	assert.Empty(t, cm.Links)
}
