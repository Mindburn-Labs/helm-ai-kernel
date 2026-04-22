package publish

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/researchruntime"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/researchruntime/store"
)

// ErrMissingPromotionReceipt is returned when Publish is called without a signed PromotionReceipt.
var ErrMissingPromotionReceipt = errors.New("publication requires a signed PromotionReceipt")

// RegistryPublisher writes promoted artifacts to the internal HELM publication store.
type RegistryPublisher struct {
	publications store.PublicationStore
	blobs        store.BlobStore
}

// NewRegistryPublisher creates a RegistryPublisher backed by the given stores.
func NewRegistryPublisher(pubs store.PublicationStore, blobs store.BlobStore) *RegistryPublisher {
	return &RegistryPublisher{publications: pubs, blobs: blobs}
}

// Publish creates a PublicationRecord from the promoted draft and its PromotionReceipt,
// persists it to the PublicationStore, and returns the record. A non-nil receipt is required.
func (p *RegistryPublisher) Publish(
	ctx context.Context,
	draft *researchruntime.DraftManifest,
	receipt *researchruntime.PromotionReceipt,
) (*researchruntime.PublicationRecord, error) {
	if receipt == nil {
		return nil, ErrMissingPromotionReceipt
	}

	now := time.Now().UTC()

	rec := researchruntime.PublicationRecord{
		PublicationID:    uuid.NewString(),
		MissionID:        draft.MissionID,
		State:            researchruntime.PublicationStatePromoted,
		Title:            draft.Title,
		Version:          draft.Version,
		EvidencePackHash: receipt.EvidencePackHash,
		// Store the receipt ID so the record is traceable back to the authorising receipt.
		PromotionReceipt: receipt.ReceiptID,
		PublishedAt:      &now,
	}

	if err := p.publications.Save(ctx, rec); err != nil {
		return nil, fmt.Errorf("save publication: %w", err)
	}

	return &rec, nil
}
