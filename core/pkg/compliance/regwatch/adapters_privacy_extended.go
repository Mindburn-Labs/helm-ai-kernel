package regwatch

import (
	"context"
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/compliance/jkg"
)

// CNILAdapter monitors France CNIL publications.
type CNILAdapter struct{ BaseAdapter }

func NewCNILAdapter() *CNILAdapter {
	return &CNILAdapter{BaseAdapter: BaseAdapter{
		sourceType: SourceCNIL, jurisdiction: jkg.JurisdictionCode("FR"),
		regulator: jkg.RegulatorID("EU-CNIL"), feedURL: "https://www.cnil.fr/", healthy: true,
	}}
}
func (a *CNILAdapter) FetchChanges(ctx context.Context, since time.Time) ([]*RegChange, error) {
	return []*RegChange{}, nil
}
func (a *CNILAdapter) IsHealthy(ctx context.Context) bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.healthy
}

// CPPAAdapter monitors California Privacy Protection Agency rulemaking.
type CPPAAdapter struct{ BaseAdapter }

func NewCPPAAdapter() *CPPAAdapter {
	return &CPPAAdapter{BaseAdapter: BaseAdapter{
		sourceType: SourceCPPA, jurisdiction: jkg.JurisdictionCode("US-CA"),
		regulator: jkg.RegulatorID("US-CA-CPPA"), feedURL: "https://cppa.ca.gov/regulations/", healthy: true,
	}}
}
func (a *CPPAAdapter) FetchChanges(ctx context.Context, since time.Time) ([]*RegChange, error) {
	return []*RegChange{}, nil
}
func (a *CPPAAdapter) IsHealthy(ctx context.Context) bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.healthy
}

// CACAdapter monitors Cyberspace Administration of China.
type CACAdapter struct{ BaseAdapter }

func NewCACAdapter() *CACAdapter {
	return &CACAdapter{BaseAdapter: BaseAdapter{
		sourceType: SourceCAC, jurisdiction: jkg.JurisdictionCN,
		regulator: jkg.RegulatorID("CN-CAC"), feedURL: "https://www.cac.gov.cn/", healthy: true,
	}}
}
func (a *CACAdapter) FetchChanges(ctx context.Context, since time.Time) ([]*RegChange, error) {
	return []*RegChange{}, nil
}
func (a *CACAdapter) IsHealthy(ctx context.Context) bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.healthy
}
