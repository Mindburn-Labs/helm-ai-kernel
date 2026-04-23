package regwatch

import (
	"context"
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/compliance/jkg"
)

// FederalRegisterAdapter monitors US Federal Register rules, proposed rules, and notices.
// Endpoint: https://www.federalregister.gov/api/v1
type FederalRegisterAdapter struct {
	BaseAdapter
	documentTypes []string // e.g., ["Rule", "Proposed Rule", "Notice", "Presidential Document"]
}

// NewFederalRegisterAdapter creates a Federal Register adapter.
func NewFederalRegisterAdapter() *FederalRegisterAdapter {
	return &FederalRegisterAdapter{
		BaseAdapter: BaseAdapter{
			sourceType:   SourceFedReg,
			jurisdiction: jkg.JurisdictionUS,
			regulator:    jkg.RegulatorSEC, // Federal Register covers multiple agencies
			feedURL:      "https://www.federalregister.gov/api/v1",
			healthy:      true,
		},
		documentTypes: []string{"Rule", "Proposed Rule", "Notice", "Presidential Document"},
	}
}

// FetchChanges retrieves changes from the Federal Register API.
func (f *FederalRegisterAdapter) FetchChanges(ctx context.Context, since time.Time) ([]*RegChange, error) {
	// Production: GET /documents.json?conditions[publication_date][gte]=YYYY-MM-DD
	// Supports filtering by type, agency, topic
	return []*RegChange{}, nil
}

// IsHealthy checks Federal Register API availability.
func (f *FederalRegisterAdapter) IsHealthy(ctx context.Context) bool {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.healthy
}

// SetHealthy sets health status.
func (f *FederalRegisterAdapter) SetHealthy(healthy bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.healthy = healthy
}

// LegislationGovUKAdapter monitors UK legislation via legislation.gov.uk.
// Endpoint: https://www.legislation.gov.uk (Atom/XML feeds + REST)
type LegislationGovUKAdapter struct {
	BaseAdapter
	categories []string // e.g., ["ukpga", "uksi", "euretained"]
}

// NewLegislationGovUKAdapter creates a legislation.gov.uk adapter.
func NewLegislationGovUKAdapter() *LegislationGovUKAdapter {
	return &LegislationGovUKAdapter{
		BaseAdapter: BaseAdapter{
			sourceType:   SourceLegGovUK,
			jurisdiction: jkg.JurisdictionGB,
			regulator:    jkg.RegulatorFCA,
			feedURL:      "https://www.legislation.gov.uk",
			healthy:      true,
		},
		categories: []string{"ukpga", "uksi", "euretained"},
	}
}

// FetchChanges retrieves changes from legislation.gov.uk.
func (l *LegislationGovUKAdapter) FetchChanges(ctx context.Context, since time.Time) ([]*RegChange, error) {
	// Production: GET /new/data.feed?start-date=YYYY-MM-DD
	// Supports Atom feeds for each legislation type
	return []*RegChange{}, nil
}

// IsHealthy checks legislation.gov.uk availability.
func (l *LegislationGovUKAdapter) IsHealthy(ctx context.Context) bool {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.healthy
}

// SetHealthy sets health status.
func (l *LegislationGovUKAdapter) SetHealthy(healthy bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.healthy = healthy
}

// ECFRAdapter monitors US eCFR — codified federal regulations.
// Endpoint: https://www.ecfr.gov/api/versioner/v1
// Complements FederalRegister (daily rules) with the consolidated regulatory text.
type ECFRAdapter struct {
	BaseAdapter
	titles []int // CFR titles to monitor (e.g., 12=Banks, 17=Securities)
}

// NewECFRAdapter creates an eCFR adapter.
func NewECFRAdapter(titles []int) *ECFRAdapter {
	return &ECFRAdapter{
		BaseAdapter: BaseAdapter{
			sourceType:   SourceECFR,
			jurisdiction: jkg.JurisdictionUS,
			regulator:    jkg.RegulatorSEC,
			feedURL:      "https://www.ecfr.gov/api/versioner/v1",
			healthy:      true,
		},
		titles: titles,
	}
}

// FetchChanges retrieves changes from the eCFR versioner API.
func (e *ECFRAdapter) FetchChanges(ctx context.Context, since time.Time) ([]*RegChange, error) {
	// Production: GET /versions/title-{N}.json?issue_date[gte]=YYYY-MM-DD
	// Returns amendment references per CFR title
	return []*RegChange{}, nil
}

// IsHealthy checks eCFR API availability.
func (e *ECFRAdapter) IsHealthy(ctx context.Context) bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.healthy
}

// SetHealthy sets health status.
func (e *ECFRAdapter) SetHealthy(healthy bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.healthy = healthy
}
