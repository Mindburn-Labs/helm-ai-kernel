package browser

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestExtractText_TitleAndBody(t *testing.T) {
	h := `<html><head><title>HELM Research</title></head><body>
        <nav>Navigation links</nav>
        <p>This is the main content of the research page.</p>
        <script>var x = 1;</script>
        <footer>Copyright 2025</footer>
    </body></html>`
	c := ExtractText(strings.NewReader(h))
	assert.Equal(t, "HELM Research", c.Title)
	assert.Contains(t, c.Text, "main content")
	assert.NotContains(t, c.Text, "var x = 1")
	assert.NotContains(t, c.Text, "Navigation links")
	assert.NotContains(t, c.Text, "Copyright 2025")
}

func TestExtractText_EmptyHTML(t *testing.T) {
	c := ExtractText(strings.NewReader(""))
	assert.Empty(t, c.Title)
	assert.Empty(t, c.Text)
}

func TestExtractText_NoTitle(t *testing.T) {
	c := ExtractText(strings.NewReader("<html><body><p>Content only</p></body></html>"))
	assert.Empty(t, c.Title)
	assert.Contains(t, c.Text, "Content only")
}
