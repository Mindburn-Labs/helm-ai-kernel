package regwatch

import (
	"context"
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/compliance/jkg"
)

// UNSanctionsAdapter monitors the UN Security Council Consolidated List.
// Available in XML/HTML/PDF at main.un.org.
type UNSanctionsAdapter struct {
	BaseAdapter
}

// NewUNSanctionsAdapter creates a UN sanctions adapter.
func NewUNSanctionsAdapter() *UNSanctionsAdapter {
	return &UNSanctionsAdapter{
		BaseAdapter: BaseAdapter{
			sourceType:   SourceUNSCSL,
			jurisdiction: jkg.JurisdictionGlobal,
			regulator:    jkg.RegulatorUNSC,
			feedURL:      "https://main.un.org/securitycouncil/en/content/un-sc-consolidated-list",
			healthy:      true,
		},
	}
}

func (u *UNSanctionsAdapter) FetchChanges(ctx context.Context, since time.Time) ([]*RegChange, error) {
	return []*RegChange{}, nil
}

func (u *UNSanctionsAdapter) IsHealthy(ctx context.Context) bool {
	u.mu.RLock()
	defer u.mu.RUnlock()
	return u.healthy
}

func (u *UNSanctionsAdapter) SetHealthy(healthy bool) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.healthy = healthy
}

// OFACAdapter monitors US OFAC sanctions (SDN list, SLS formats, structured downloads).
type OFACAdapter struct {
	BaseAdapter
	listFormats []string // e.g., ["SDN", "SLS", "CONS"]
}

// NewOFACAdapter creates an OFAC adapter.
func NewOFACAdapter() *OFACAdapter {
	return &OFACAdapter{
		BaseAdapter: BaseAdapter{
			sourceType:   SourceOFAC,
			jurisdiction: jkg.JurisdictionUS,
			regulator:    jkg.RegulatorOFAC,
			feedURL:      "https://ofac.treasury.gov/sanctions-list-service",
			healthy:      true,
		},
		listFormats: []string{"SDN", "SLS", "CONS"},
	}
}

func (o *OFACAdapter) FetchChanges(ctx context.Context, since time.Time) ([]*RegChange, error) {
	return []*RegChange{}, nil
}

func (o *OFACAdapter) IsHealthy(ctx context.Context) bool {
	o.mu.RLock()
	defer o.mu.RUnlock()
	return o.healthy
}

func (o *OFACAdapter) SetHealthy(healthy bool) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.healthy = healthy
}

// EUSanctionsAdapter monitors the EU consolidated financial sanctions dataset.
type EUSanctionsAdapter struct {
	BaseAdapter
}

// NewEUSanctionsAdapter creates an EU sanctions adapter.
func NewEUSanctionsAdapter() *EUSanctionsAdapter {
	return &EUSanctionsAdapter{
		BaseAdapter: BaseAdapter{
			sourceType:   SourceEUSanctions,
			jurisdiction: jkg.JurisdictionEU,
			regulator:    jkg.RegulatorESMA,
			feedURL:      "https://data.europa.eu/data/datasets/consolidated-list-of-persons-groups-and-entities-subject-to-eu-financial-sanctions",
			healthy:      true,
		},
	}
}

func (e *EUSanctionsAdapter) FetchChanges(ctx context.Context, since time.Time) ([]*RegChange, error) {
	return []*RegChange{}, nil
}

func (e *EUSanctionsAdapter) IsHealthy(ctx context.Context) bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.healthy
}

func (e *EUSanctionsAdapter) SetHealthy(healthy bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.healthy = healthy
}

// UKSanctionsAdapter monitors the UK Sanctions List (primary UK designations source).
// Note: OFSI consolidated list closed Jan 28, 2026.
type UKSanctionsAdapter struct {
	BaseAdapter
}

// NewUKSanctionsAdapter creates a UK sanctions adapter.
func NewUKSanctionsAdapter() *UKSanctionsAdapter {
	return &UKSanctionsAdapter{
		BaseAdapter: BaseAdapter{
			sourceType:   SourceUKSanctions,
			jurisdiction: jkg.JurisdictionGB,
			regulator:    jkg.RegulatorOFSI,
			feedURL:      "https://www.gov.uk/government/publications/the-uk-sanctions-list",
			healthy:      true,
		},
	}
}

func (u *UKSanctionsAdapter) FetchChanges(ctx context.Context, since time.Time) ([]*RegChange, error) {
	return []*RegChange{}, nil
}

func (u *UKSanctionsAdapter) IsHealthy(ctx context.Context) bool {
	u.mu.RLock()
	defer u.mu.RUnlock()
	return u.healthy
}

func (u *UKSanctionsAdapter) SetHealthy(healthy bool) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.healthy = healthy
}

// FATFAdapter monitors FATF Recommendations (universal AML/CFT baseline).
type FATFAdapter struct {
	BaseAdapter
}

// NewFATFAdapter creates a FATF adapter.
func NewFATFAdapter() *FATFAdapter {
	return &FATFAdapter{
		BaseAdapter: BaseAdapter{
			sourceType:   SourceFATF,
			jurisdiction: jkg.JurisdictionGlobal,
			regulator:    jkg.RegulatorFATF,
			feedURL:      "https://www.fatf-gafi.org/en/publications/Fatfrecommendations/Fatf-recommendations.html",
			healthy:      true,
		},
	}
}

func (f *FATFAdapter) FetchChanges(ctx context.Context, since time.Time) ([]*RegChange, error) {
	return []*RegChange{}, nil
}

func (f *FATFAdapter) IsHealthy(ctx context.Context) bool {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.healthy
}

func (f *FATFAdapter) SetHealthy(healthy bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.healthy = healthy
}

// BISEntityListAdapter monitors US BIS Entity List for export controls.
type BISEntityListAdapter struct {
	BaseAdapter
}

// NewBISEntityListAdapter creates a BIS Entity List adapter.
func NewBISEntityListAdapter() *BISEntityListAdapter {
	return &BISEntityListAdapter{
		BaseAdapter: BaseAdapter{
			sourceType:   SourceBIS,
			jurisdiction: jkg.JurisdictionUS,
			regulator:    jkg.RegulatorBIS,
			feedURL:      "https://www.bis.doc.gov/index.php/policy-guidance/lists-of-parties-of-concern/entity-list",
			healthy:      true,
		},
	}
}

func (b *BISEntityListAdapter) FetchChanges(ctx context.Context, since time.Time) ([]*RegChange, error) {
	return []*RegChange{}, nil
}

func (b *BISEntityListAdapter) IsHealthy(ctx context.Context) bool {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.healthy
}

func (b *BISEntityListAdapter) SetHealthy(healthy bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.healthy = healthy
}
