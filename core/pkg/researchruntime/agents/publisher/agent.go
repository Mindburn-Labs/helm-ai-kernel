package publisher

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/researchruntime"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/researchruntime/connectors/publish"
)

// PublisherAgent creates a PublicationRecord from a promoted draft manifest and
// its PromotionReceipt via RegistryPublisher.
type PublisherAgent struct {
	Publisher *publish.RegistryPublisher
}

// New creates a PublisherAgent backed by the given RegistryPublisher.
func New(p *publish.RegistryPublisher) *PublisherAgent {
	return &PublisherAgent{Publisher: p}
}

// Role returns the worker role for this agent.
func (a *PublisherAgent) Role() researchruntime.WorkerRole {
	return researchruntime.WorkerPublisher
}

// publisherInput is the JSON input shape for the Publisher agent.
type publisherInput struct {
	Draft   researchruntime.DraftManifest   `json:"draft"`
	Receipt researchruntime.PromotionReceipt `json:"receipt"`
}

// Execute unmarshals the draft manifest and promotion receipt, creates a
// PublicationRecord, and returns it as JSON.
func (a *PublisherAgent) Execute(ctx context.Context, task *researchruntime.TaskLease, input []byte) ([]byte, error) {
	var in publisherInput
	if err := json.Unmarshal(input, &in); err != nil {
		return nil, fmt.Errorf("publisher: unmarshal input: %w", err)
	}

	rec, err := a.Publisher.Publish(ctx, &in.Draft, &in.Receipt)
	if err != nil {
		return nil, fmt.Errorf("publisher: publish: %w", err)
	}

	return json.Marshal(rec)
}
