package webscout

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/researchruntime"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/researchruntime/connectors/browser"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/researchruntime/connectors/search"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/researchruntime/sources"
)

// WebScoutAgent runs search queries and fetches pages to build the source corpus.
type WebScoutAgent struct {
	Search   search.Client
	Fetcher  *browser.Fetcher
	Registry *sources.Registry
}

// New creates a WebScoutAgent with the given search client, fetcher, and source registry.
func New(s search.Client, f *browser.Fetcher, r *sources.Registry) *WebScoutAgent {
	return &WebScoutAgent{Search: s, Fetcher: f, Registry: r}
}

// Role returns the worker role for this agent.
func (a *WebScoutAgent) Role() researchruntime.WorkerRole {
	return researchruntime.WorkerWebScout
}

// scoutInput is the JSON input shape for the WebScout agent.
type scoutInput struct {
	QuerySeeds []string `json:"query_seeds"`
}

// Execute unmarshals query seeds from input, runs searches, fetches and deduplicates
// pages, and returns a JSON array of SourceSnapshots.
func (a *WebScoutAgent) Execute(ctx context.Context, task *researchruntime.TaskLease, input []byte) ([]byte, error) {
	var in scoutInput
	if err := json.Unmarshal(input, &in); err != nil {
		return nil, fmt.Errorf("webscout: unmarshal input: %w", err)
	}

	var snapshots []researchruntime.SourceSnapshot
	for _, q := range in.QuerySeeds {
		results, err := a.Search.Search(ctx, search.Request{
			Query:      q,
			MaxResults: 10,
			MissionID:  task.MissionID,
		})
		if err != nil {
			// skip failed queries, don't halt the mission
			continue
		}

		for _, r := range results {
			// Check for duplicate by canonical URL before fetching
			candidate := researchruntime.SourceSnapshot{CanonicalURL: r.URL}
			if a.Registry.IsDuplicate(candidate) {
				continue
			}

			page, err := a.Fetcher.Fetch(ctx, r.URL)
			if err != nil {
				// skip unreachable pages
				continue
			}

			s := sources.FromPage(task.MissionID, page)
			s.Title = r.Title
			a.Registry.Register(s)
			snapshots = append(snapshots, s)
		}
	}

	return json.Marshal(snapshots)
}
