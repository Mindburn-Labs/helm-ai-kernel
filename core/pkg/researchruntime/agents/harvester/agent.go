package harvester

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/researchruntime"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/researchruntime/connectors/browser"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/researchruntime/store"
)

// HarvesterAgent fetches full page content for each SourceSnapshot and stores
// raw HTML to the blob store, enriching snapshots with blob and citation map refs.
type HarvesterAgent struct {
	Fetcher *browser.Fetcher
	Blobs   store.BlobStore
}

// New creates a HarvesterAgent with the given fetcher and blob store.
func New(fetcher *browser.Fetcher, blobs store.BlobStore) *HarvesterAgent {
	return &HarvesterAgent{Fetcher: fetcher, Blobs: blobs}
}

// Role returns the worker role for this agent.
func (a *HarvesterAgent) Role() researchruntime.WorkerRole {
	return researchruntime.WorkerSourceHarvester
}

// Execute fetches each source URL, stores raw HTML to the blob store, and returns
// an enriched JSON array of SourceSnapshots with SnapshotHash and Metadata blob refs populated.
func (a *HarvesterAgent) Execute(ctx context.Context, task *researchruntime.TaskLease, input []byte) ([]byte, error) {
	var snapshots []researchruntime.SourceSnapshot
	if err := json.Unmarshal(input, &snapshots); err != nil {
		return nil, fmt.Errorf("harvester: unmarshal snapshots: %w", err)
	}

	for i, s := range snapshots {
		page, err := a.Fetcher.Fetch(ctx, s.URL)
		if err != nil {
			// Non-fatal: skip unreachable pages, mark provenance as captured or leave as-is.
			continue
		}

		blobKey := store.SourceSnapshotKey(task.MissionID, s.SourceID)
		if putErr := a.Blobs.Put(ctx, blobKey, page.RawHTML, "text/html"); putErr != nil {
			// Non-fatal: log via error but continue enriching remaining snapshots.
			continue
		}

		snapshots[i].SnapshotHash = page.ContentHash
		snapshots[i].ContentHash = page.ContentHash
		if snapshots[i].Title == "" {
			snapshots[i].Title = page.Title
		}
		snapshots[i].ProvenanceStatus = researchruntime.ProvenanceCaptured

		// Build a minimal citation map: record the blob key and text excerpt refs.
		citationMapKey := store.CitationMapKey(task.MissionID, s.SourceID)
		citationMap := citationMap{
			SourceID:  s.SourceID,
			BlobKey:   blobKey,
			TextSnip:  truncate(page.Text, 500),
			WordCount: wordCount(page.Text),
		}
		citBytes, err := json.Marshal(citationMap)
		if err == nil {
			// Best-effort: ignore citation map storage errors.
			_ = a.Blobs.Put(ctx, citationMapKey, citBytes, "application/json")
		}

		if snapshots[i].Metadata == nil {
			snapshots[i].Metadata = make(map[string]any)
		}
		snapshots[i].Metadata["blob_ref"] = blobKey
		snapshots[i].Metadata["citation_map_ref"] = citationMapKey
	}

	return json.Marshal(snapshots)
}

// citationMap is a minimal citation index stored alongside the raw HTML blob.
type citationMap struct {
	SourceID  string `json:"source_id"`
	BlobKey   string `json:"blob_key"`
	TextSnip  string `json:"text_snip"`
	WordCount int    `json:"word_count"`
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max]
}

func wordCount(s string) int {
	count := 0
	inWord := false
	for _, r := range s {
		if r == ' ' || r == '\n' || r == '\t' {
			inWord = false
		} else if !inWord {
			inWord = true
			count++
		}
	}
	return count
}
