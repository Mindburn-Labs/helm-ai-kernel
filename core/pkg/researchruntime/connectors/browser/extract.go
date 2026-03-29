package browser

import (
	"io"
	"strings"

	"golang.org/x/net/html"
)

// ExtractedContent holds the title and main body text from an HTML page.
type ExtractedContent struct {
	Title string
	Text  string
}

// ExtractText parses HTML and returns the page title + main body text.
// Skips script, style, nav, footer, noscript elements.
func ExtractText(r io.Reader) ExtractedContent {
	doc, err := html.Parse(r)
	if err != nil {
		return ExtractedContent{}
	}
	var c ExtractedContent
	var sb strings.Builder
	skipTags := map[string]bool{"script": true, "style": true, "nav": true, "footer": true, "noscript": true, "header": true}

	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode {
			if skipTags[n.Data] {
				return
			}
			if n.Data == "title" && c.Title == "" {
				if n.FirstChild != nil && n.FirstChild.Type == html.TextNode {
					c.Title = strings.TrimSpace(n.FirstChild.Data)
				}
			}
		}
		if n.Type == html.TextNode {
			t := strings.TrimSpace(n.Data)
			if len(t) > 0 {
				sb.WriteString(t)
				sb.WriteString("\n")
			}
		}
		for child := n.FirstChild; child != nil; child = child.NextSibling {
			walk(child)
		}
	}
	walk(doc)
	c.Text = sb.String()
	return c
}
