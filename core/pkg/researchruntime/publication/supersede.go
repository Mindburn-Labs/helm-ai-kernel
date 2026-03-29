package publication

import (
	"context"
	"fmt"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/researchruntime"
)

// Supersede marks oldPublicationID as superseded by newPublicationID in the
// publication store and appends a feed event for the mission that owns the old
// record.
func (s *Service) Supersede(ctx context.Context, oldPublicationID, newPublicationID string) error {
	if err := s.publications.SetSupersededBy(ctx, oldPublicationID, newPublicationID); err != nil {
		return fmt.Errorf("publication: supersede: %w", err)
	}

	// Best-effort: fetch the old record to resolve the mission ID for the feed.
	old, _ := s.publications.Get(ctx, oldPublicationID)
	if old != nil {
		_ = s.feed.Append(
			ctx,
			old.MissionID,
			"publisher",
			researchruntime.EventPublicationSuperseded,
			fmt.Sprintf("%s superseded by %s", oldPublicationID, newPublicationID),
		)
	}

	return nil
}
