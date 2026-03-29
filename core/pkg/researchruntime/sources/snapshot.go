package sources

import (
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/researchruntime"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/researchruntime/connectors/browser"
	"github.com/google/uuid"
)

// FromPage creates a SourceSnapshot from a fetched web page.
func FromPage(missionID string, page *browser.FetchedPage) researchruntime.SourceSnapshot {
	return researchruntime.SourceSnapshot{
		SourceID:         uuid.NewString(),
		MissionID:        missionID,
		URL:              page.URL,
		CanonicalURL:     page.URL,
		Title:            page.Title,
		ContentHash:      page.ContentHash,
		SnapshotHash:     page.ContentHash,
		CapturedAt:       page.FetchedAt,
		FreshnessScore:   freshnessScore(page.FetchedAt),
		ProvenanceStatus: researchruntime.ProvenanceCaptured,
	}
}

func freshnessScore(fetchedAt time.Time) float64 {
	age := time.Since(fetchedAt)
	switch {
	case age < 24*time.Hour:
		return 1.0
	case age < 7*24*time.Hour:
		return 0.8
	case age < 30*24*time.Hour:
		return 0.5
	default:
		return 0.2
	}
}
