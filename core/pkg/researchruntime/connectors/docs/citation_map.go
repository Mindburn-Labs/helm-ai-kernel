package docs

import (
	"io"
	"net/url"
	"strings"

	"golang.org/x/net/html"
)

type CitationLink struct {
	URL  string
	Text string
}

type CitationMap struct {
	BaseURL string
	Links   []CitationLink
}

func ExtractCitationMap(r io.Reader, baseURL string) (*CitationMap, error) {
	base, err := url.Parse(baseURL)
	if err != nil {
		return nil, err
	}
	doc, err := html.Parse(r)
	if err != nil {
		return nil, err
	}
	cm := &CitationMap{BaseURL: baseURL}
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "a" {
			for _, a := range n.Attr {
				if a.Key == "href" && a.Val != "" && !strings.HasPrefix(a.Val, "#") && !strings.HasPrefix(a.Val, "javascript:") {
					ref, err := base.Parse(a.Val)
					if err != nil {
						continue
					}
					text := extractInnerText(n)
					cm.Links = append(cm.Links, CitationLink{URL: ref.String(), Text: text})
				}
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(doc)
	return cm, nil
}

func extractInnerText(n *html.Node) string {
	if n.Type == html.TextNode {
		return strings.TrimSpace(n.Data)
	}
	var sb strings.Builder
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		sb.WriteString(extractInnerText(c))
	}
	return strings.TrimSpace(sb.String())
}
