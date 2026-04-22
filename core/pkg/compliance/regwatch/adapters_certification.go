package regwatch

import (
	"context"
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/compliance/jkg"
)

// FedRAMPAdapter monitors the FedRAMP authorization ecosystem.
type FedRAMPAdapter struct {
	BaseAdapter
}

// NewFedRAMPAdapter creates a FedRAMP adapter.
func NewFedRAMPAdapter() *FedRAMPAdapter {
	return &FedRAMPAdapter{
		BaseAdapter: BaseAdapter{
			sourceType:   SourceFedRAMP,
			jurisdiction: jkg.JurisdictionUS,
			feedURL:      "https://www.fedramp.gov",
			healthy:      true,
		},
	}
}

func (f *FedRAMPAdapter) FetchChanges(ctx context.Context, since time.Time) ([]*RegChange, error) {
	return []*RegChange{}, nil
}

func (f *FedRAMPAdapter) IsHealthy(ctx context.Context) bool {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.healthy
}

func (f *FedRAMPAdapter) SetHealthy(healthy bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.healthy = healthy
}

// CSASTARAdapter monitors the Cloud Security Alliance STAR registry.
type CSASTARAdapter struct {
	BaseAdapter
}

// NewCSASTARAdapter creates a CSA STAR adapter.
func NewCSASTARAdapter() *CSASTARAdapter {
	return &CSASTARAdapter{
		BaseAdapter: BaseAdapter{
			sourceType:   SourceCSASTAR,
			jurisdiction: jkg.JurisdictionGlobal,
			feedURL:      "https://cloudsecurityalliance.org/star",
			healthy:      true,
		},
	}
}

func (c *CSASTARAdapter) FetchChanges(ctx context.Context, since time.Time) ([]*RegChange, error) {
	return []*RegChange{}, nil
}

func (c *CSASTARAdapter) IsHealthy(ctx context.Context) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.healthy
}

func (c *CSASTARAdapter) SetHealthy(healthy bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.healthy = healthy
}
