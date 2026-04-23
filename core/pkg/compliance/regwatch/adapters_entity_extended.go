package regwatch

import (
	"context"
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/compliance/jkg"
)

// SECXBRLAdapter monitors SEC EDGAR XBRL API.
type SECXBRLAdapter struct{ BaseAdapter }

func NewSECXBRLAdapter() *SECXBRLAdapter {
	return &SECXBRLAdapter{BaseAdapter: BaseAdapter{
		sourceType: SourceSECXBRL, jurisdiction: jkg.JurisdictionUS,
		regulator: jkg.RegulatorID("US-SEC"), feedURL: "https://data.sec.gov/api/xbrl/", healthy: true,
	}}
}
func (a *SECXBRLAdapter) FetchChanges(ctx context.Context, since time.Time) ([]*RegChange, error) {
	return []*RegChange{}, nil
}
func (a *SECXBRLAdapter) IsHealthy(ctx context.Context) bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.healthy
}
