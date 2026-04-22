package publication

import (
	"context"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/researchruntime"
)

// List returns all PublicationRecord entries from the store.
func (s *Service) List(ctx context.Context) ([]researchruntime.PublicationRecord, error) {
	return s.publications.List(ctx)
}

// Get returns the PublicationRecord with the given ID.
func (s *Service) Get(ctx context.Context, id string) (*researchruntime.PublicationRecord, error) {
	return s.publications.Get(ctx, id)
}
