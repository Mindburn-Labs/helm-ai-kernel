package regwatch

import (
	"context"
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/compliance/jkg"
)

// CISControlsAdapter monitors CIS Critical Security Controls.
type CISControlsAdapter struct{ BaseAdapter }

func NewCISControlsAdapter() *CISControlsAdapter {
	return &CISControlsAdapter{BaseAdapter: BaseAdapter{
		sourceType: SourceCIS, jurisdiction: jkg.JurisdictionGlobal,
		regulator: jkg.RegulatorID("CIS"), feedURL: "https://www.cisecurity.org/controls", healthy: true,
	}}
}
func (a *CISControlsAdapter) FetchChanges(ctx context.Context, since time.Time) ([]*RegChange, error) {
	return []*RegChange{}, nil
}
func (a *CISControlsAdapter) IsHealthy(ctx context.Context) bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.healthy
}
