package browser

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFetcher_FetchAndExtract(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<html><head><title>Test Page</title></head><body><p>Hello world content here.</p></body></html>`))
	}))
	defer srv.Close()

	f := NewFetcher(10, 1<<20)
	page, err := f.Fetch(context.Background(), srv.URL)
	require.NoError(t, err)
	assert.Equal(t, "Test Page", page.Title)
	assert.Contains(t, page.Text, "Hello world content")
	assert.NotEmpty(t, page.ContentHash)
	assert.Equal(t, 200, page.StatusCode)
}

func TestFetcher_RespectsMaxBytes(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(make([]byte, 1024))
	}))
	defer srv.Close()

	f := NewFetcher(10, 100) // only 100 bytes
	page, err := f.Fetch(context.Background(), srv.URL)
	require.NoError(t, err)
	assert.LessOrEqual(t, len(page.RawHTML), 100)
}
