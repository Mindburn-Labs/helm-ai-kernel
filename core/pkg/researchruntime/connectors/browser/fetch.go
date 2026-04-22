package browser

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// FetchedPage holds the raw HTML and extracted content from fetching a URL.
type FetchedPage struct {
	URL         string
	Title       string
	Text        string
	RawHTML     []byte
	ContentHash string
	FetchedAt   time.Time
	StatusCode  int
}

// Fetcher performs HTTP GET requests and extracts page content.
type Fetcher struct {
	client   *http.Client
	maxBytes int64
}

// NewFetcher creates a Fetcher with the given timeout and max response size.
func NewFetcher(timeoutSec int, maxBytes int64) *Fetcher {
	return &Fetcher{
		client:   &http.Client{Timeout: time.Duration(timeoutSec) * time.Second},
		maxBytes: maxBytes,
	}
}

// Fetch retrieves a URL and extracts its title and body text.
func (f *Fetcher) Fetch(ctx context.Context, url string) (*FetchedPage, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "HELM-ResearchRuntime/1.0 (+https://github.com/Mindburn-Labs/helm-oss)")
	req.Header.Set("Accept", "text/html,application/xhtml+xml")

	resp, err := f.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch %s: %w", url, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, f.maxBytes))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", url, err)
	}

	h := sha256.Sum256(body)
	content := ExtractText(strings.NewReader(string(body)))

	return &FetchedPage{
		URL:         url,
		Title:       content.Title,
		Text:        content.Text,
		RawHTML:     body,
		ContentHash: fmt.Sprintf("%x", h),
		FetchedAt:   time.Now(),
		StatusCode:  resp.StatusCode,
	}, nil
}
