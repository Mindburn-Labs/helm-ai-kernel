package regwatch

import (
	"context"
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/compliance/jkg"
)

// OECDAIAdapter monitors OECD AI Principles.
type OECDAIAdapter struct{ BaseAdapter }

func NewOECDAIAdapter() *OECDAIAdapter {
	return &OECDAIAdapter{BaseAdapter: BaseAdapter{
		sourceType: SourceOECDAI, jurisdiction: jkg.JurisdictionGlobal,
		regulator: jkg.RegulatorID("GLOBAL-OECD"), feedURL: "https://oecd.ai/en/ai-principles", healthy: true,
	}}
}
func (a *OECDAIAdapter) FetchChanges(ctx context.Context, since time.Time) ([]*RegChange, error) {
	return []*RegChange{}, nil
}
func (a *OECDAIAdapter) IsHealthy(ctx context.Context) bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.healthy
}
