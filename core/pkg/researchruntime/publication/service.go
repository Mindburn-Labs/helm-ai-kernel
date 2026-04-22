// Package publication is the terminal state coordinator for the research pipeline.
// It accepts promoted drafts with sealed evidence receipts, writes them to the
// internal registry, and handles version supersession.
package publication

import (
	"github.com/Mindburn-Labs/helm-oss/core/pkg/researchruntime/connectors/publish"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/researchruntime/store"
)

// Service coordinates the promote, publish, and supersede flows for research
// publications. It is the gatekeeper before any external publication (git
// markdown, CMS) in the downstream phase.
type Service struct {
	drafts       store.DraftStore
	publications store.PublicationStore
	feed         store.FeedStore
	publisher    *publish.RegistryPublisher
}

// New creates a Service wired to the provided stores and publisher.
func New(
	drafts store.DraftStore,
	pubs store.PublicationStore,
	feed store.FeedStore,
	pub *publish.RegistryPublisher,
) *Service {
	return &Service{
		drafts:       drafts,
		publications: pubs,
		feed:         feed,
		publisher:    pub,
	}
}
