package webscout

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/researchruntime"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/researchruntime/connectors/browser"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/researchruntime/connectors/search"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/researchruntime/sources"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockSearchClient struct {
	results []search.Result
	err     error
}

func (m *mockSearchClient) Search(_ context.Context, _ search.Request) ([]search.Result, error) {
	return m.results, m.err
}

func newHTMLServer(body string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(body))
	}))
}

func TestWebScoutAgent_Role(t *testing.T) {
	a := New(nil, nil, nil)
	assert.Equal(t, researchruntime.WorkerWebScout, a.Role())
}

func TestWebScoutAgent_DiscoversSources(t *testing.T) {
	srv := newHTMLServer(`<html><head><title>Test</title></head><body><p>Research content here for analysis.</p></body></html>`)
	defer srv.Close()

	sc := &mockSearchClient{results: []search.Result{{URL: srv.URL, Title: "Test Source"}}}
	fetcher := browser.NewFetcher(10, 1<<20)
	registry := sources.NewRegistry()

	agent := New(sc, fetcher, registry)
	input, _ := json.Marshal(scoutInput{QuerySeeds: []string{"test query"}})

	out, err := agent.Execute(context.Background(), &researchruntime.TaskLease{MissionID: "m1"}, input)
	require.NoError(t, err)

	var snapshots []researchruntime.SourceSnapshot
	require.NoError(t, json.Unmarshal(out, &snapshots))
	assert.Len(t, snapshots, 1)
	assert.Equal(t, "Test Source", snapshots[0].Title)
	assert.Equal(t, "m1", snapshots[0].MissionID)
	assert.Equal(t, 1, registry.Count())
}

func TestWebScoutAgent_DeduplicatesSources(t *testing.T) {
	srv := newHTMLServer(`<html><body><p>Same content</p></body></html>`)
	defer srv.Close()

	sc := &mockSearchClient{
		results: []search.Result{
			{URL: srv.URL, Title: "Source A"},
			{URL: srv.URL, Title: "Source B"}, // same URL — should be deduped
		},
	}
	fetcher := browser.NewFetcher(10, 1<<20)
	registry := sources.NewRegistry()

	agent := New(sc, fetcher, registry)
	input, _ := json.Marshal(scoutInput{QuerySeeds: []string{"q"}})
	out, err := agent.Execute(context.Background(), &researchruntime.TaskLease{MissionID: "m1"}, input)
	require.NoError(t, err)

	var snapshots []researchruntime.SourceSnapshot
	require.NoError(t, json.Unmarshal(out, &snapshots))
	assert.Len(t, snapshots, 1, "second result should be deduped by canonical URL")
	assert.Equal(t, 1, registry.Count())
}

func TestWebScoutAgent_SearchErrorSkippedGracefully(t *testing.T) {
	sc := &mockSearchClient{err: errors.New("search unavailable")}
	fetcher := browser.NewFetcher(10, 1<<20)
	registry := sources.NewRegistry()

	agent := New(sc, fetcher, registry)
	input, _ := json.Marshal(scoutInput{QuerySeeds: []string{"q1", "q2"}})
	out, err := agent.Execute(context.Background(), &researchruntime.TaskLease{MissionID: "m1"}, input)
	require.NoError(t, err, "search errors should not fail the agent")

	var snapshots []researchruntime.SourceSnapshot
	require.NoError(t, json.Unmarshal(out, &snapshots))
	assert.Empty(t, snapshots)
}

func TestWebScoutAgent_UnreachableURLSkippedGracefully(t *testing.T) {
	sc := &mockSearchClient{
		results: []search.Result{{URL: "http://localhost:1", Title: "Dead Link"}},
	}
	fetcher := browser.NewFetcher(2, 1<<20)
	registry := sources.NewRegistry()

	agent := New(sc, fetcher, registry)
	input, _ := json.Marshal(scoutInput{QuerySeeds: []string{"q"}})
	out, err := agent.Execute(context.Background(), &researchruntime.TaskLease{MissionID: "m1"}, input)
	require.NoError(t, err, "fetch errors should not fail the agent")

	var snapshots []researchruntime.SourceSnapshot
	require.NoError(t, json.Unmarshal(out, &snapshots))
	assert.Empty(t, snapshots)
}

func TestWebScoutAgent_InvalidInputReturnsError(t *testing.T) {
	agent := New(nil, nil, nil)
	_, err := agent.Execute(context.Background(), &researchruntime.TaskLease{}, []byte("bad json"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unmarshal input")
}

func TestWebScoutAgent_MultipleQuerySeeds(t *testing.T) {
	srv1 := newHTMLServer(`<html><head><title>Page One</title></head><body><p>Content one</p></body></html>`)
	defer srv1.Close()
	srv2 := newHTMLServer(`<html><head><title>Page Two</title></head><body><p>Content two is different</p></body></html>`)
	defer srv2.Close()

	sc := &mockSearchClient{} // will be set per-call — use a custom impl
	_ = sc

	// Use a client that returns different results per query
	callCount := 0
	custom := &callCountingSearchClient{
		calls: [][]search.Result{
			{{URL: srv1.URL, Title: "Source One"}},
			{{URL: srv2.URL, Title: "Source Two"}},
		},
		count: &callCount,
	}

	fetcher := browser.NewFetcher(10, 1<<20)
	registry := sources.NewRegistry()
	agent := New(custom, fetcher, registry)
	input, _ := json.Marshal(scoutInput{QuerySeeds: []string{"q1", "q2"}})

	out, err := agent.Execute(context.Background(), &researchruntime.TaskLease{MissionID: "m2"}, input)
	require.NoError(t, err)

	var snapshots []researchruntime.SourceSnapshot
	require.NoError(t, json.Unmarshal(out, &snapshots))
	assert.Len(t, snapshots, 2)
	assert.Equal(t, 2, registry.Count())
}

type callCountingSearchClient struct {
	calls [][]search.Result
	count *int
}

func (c *callCountingSearchClient) Search(_ context.Context, _ search.Request) ([]search.Result, error) {
	i := *c.count
	*c.count++
	if i >= len(c.calls) {
		return nil, nil
	}
	return c.calls[i], nil
}
