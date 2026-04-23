package regwatch

import (
	"context"
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/compliance/jkg"
)

// GLEIFAdapter monitors the GLEIF LEI API for global legal entity identity and ownership data.
// HELM normalizes these into an "EntityGraph" with cross-IDs.
type GLEIFAdapter struct {
	BaseAdapter
}

// NewGLEIFAdapter creates a GLEIF LEI adapter.
func NewGLEIFAdapter() *GLEIFAdapter {
	return &GLEIFAdapter{
		BaseAdapter: BaseAdapter{
			sourceType:   SourceGLEIF,
			jurisdiction: jkg.JurisdictionGlobal,
			regulator:    jkg.RegulatorGLEIF,
			feedURL:      "https://api.gleif.org/api/v1/lei-records",
			healthy:      true,
		},
	}
}

func (g *GLEIFAdapter) FetchChanges(ctx context.Context, since time.Time) ([]*RegChange, error) {
	return []*RegChange{}, nil
}

func (g *GLEIFAdapter) IsHealthy(ctx context.Context) bool {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.healthy
}

func (g *GLEIFAdapter) SetHealthy(healthy bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.healthy = healthy
}

// UKCompaniesHouseAdapter monitors UK Companies House public company and PSC data via API.
type UKCompaniesHouseAdapter struct {
	BaseAdapter
}

// NewUKCompaniesHouseAdapter creates a UK Companies House adapter.
func NewUKCompaniesHouseAdapter() *UKCompaniesHouseAdapter {
	return &UKCompaniesHouseAdapter{
		BaseAdapter: BaseAdapter{
			sourceType:   SourceUKCH,
			jurisdiction: jkg.JurisdictionGB,
			regulator:    jkg.RegulatorCompHouse,
			feedURL:      "https://api.company-information.service.gov.uk",
			healthy:      true,
		},
	}
}

func (u *UKCompaniesHouseAdapter) FetchChanges(ctx context.Context, since time.Time) ([]*RegChange, error) {
	return []*RegChange{}, nil
}

func (u *UKCompaniesHouseAdapter) IsHealthy(ctx context.Context) bool {
	u.mu.RLock()
	defer u.mu.RUnlock()
	return u.healthy
}

func (u *UKCompaniesHouseAdapter) SetHealthy(healthy bool) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.healthy = healthy
}

// SECEDGARAdapter monitors SEC EDGAR APIs for issuer filings and extracted data.
type SECEDGARAdapter struct {
	BaseAdapter
}

// NewSECEDGARAdapter creates an SEC EDGAR adapter.
func NewSECEDGARAdapter() *SECEDGARAdapter {
	return &SECEDGARAdapter{
		BaseAdapter: BaseAdapter{
			sourceType:   SourceSECEDGAR,
			jurisdiction: jkg.JurisdictionUS,
			regulator:    jkg.RegulatorSEC,
			feedURL:      "https://efts.sec.gov/LATEST/search-index",
			healthy:      true,
		},
	}
}

func (s *SECEDGARAdapter) FetchChanges(ctx context.Context, since time.Time) ([]*RegChange, error) {
	return []*RegChange{}, nil
}

func (s *SECEDGARAdapter) IsHealthy(ctx context.Context) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.healthy
}

func (s *SECEDGARAdapter) SetHealthy(healthy bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.healthy = healthy
}
