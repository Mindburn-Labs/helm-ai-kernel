package regwatch

import (
	"context"
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/compliance/jkg"
)

// CTAppleAdapter monitors Apple Certificate Transparency log list.
type CTAppleAdapter struct{ BaseAdapter }

func NewCTAppleAdapter() *CTAppleAdapter {
	return &CTAppleAdapter{BaseAdapter: BaseAdapter{
		sourceType: SourceCTApple, jurisdiction: jkg.JurisdictionGlobal,
		regulator: jkg.RegulatorID("APPLE-CT"), feedURL: "https://support.apple.com/en-us/103214", healthy: true,
	}}
}
func (a *CTAppleAdapter) FetchChanges(ctx context.Context, since time.Time) ([]*RegChange, error) {
	return []*RegChange{}, nil
}
func (a *CTAppleAdapter) IsHealthy(ctx context.Context) bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.healthy
}
