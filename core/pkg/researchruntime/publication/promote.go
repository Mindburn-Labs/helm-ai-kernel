package publication

import (
	"context"
	"fmt"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/researchruntime"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/researchruntime/connectors/publish"
)

// Promote verifies a PromotionReceipt, fetches the named draft, and delegates
// to the RegistryPublisher to create a PublicationRecord. Feed events are
// appended for both success (promotion_allowed) and failure (promotion_denied).
func (s *Service) Promote(
	ctx context.Context,
	draftID string,
	receipt *researchruntime.PromotionReceipt,
) (*researchruntime.PublicationRecord, error) {
	if receipt == nil {
		return nil, publish.ErrMissingPromotionReceipt
	}

	// Verify receipt hash integrity before touching any store.
	if err := researchruntime.VerifyPromotionReceipt(*receipt); err != nil {
		return nil, fmt.Errorf("publication: invalid receipt: %w", err)
	}

	// Fetch the draft that is being promoted.
	draft, err := s.drafts.Get(ctx, draftID)
	if err != nil {
		return nil, fmt.Errorf("publication: get draft: %w", err)
	}

	// Promote via the registry publisher.
	rec, err := s.publisher.Publish(ctx, draft, receipt)
	if err != nil {
		_ = s.feed.Append(ctx, draft.MissionID, "publisher",
			researchruntime.EventPromotionDenied, err.Error())
		return nil, err
	}

	_ = s.feed.Append(ctx, draft.MissionID, "publisher",
		researchruntime.EventPromotionAllowed, rec.PublicationID)

	return rec, nil
}
