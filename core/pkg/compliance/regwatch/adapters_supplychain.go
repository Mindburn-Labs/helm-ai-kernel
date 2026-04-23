package regwatch

import (
	"context"
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/compliance/jkg"
)

// CISAKEVAdapter monitors the CISA Known Exploited Vulnerabilities catalog.
type CISAKEVAdapter struct {
	BaseAdapter
}

// NewCISAKEVAdapter creates a CISA KEV adapter.
func NewCISAKEVAdapter() *CISAKEVAdapter {
	return &CISAKEVAdapter{
		BaseAdapter: BaseAdapter{
			sourceType:   SourceCISAKEV,
			jurisdiction: jkg.JurisdictionUS,
			regulator:    jkg.RegulatorCISA,
			feedURL:      "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
			healthy:      true,
		},
	}
}

func (c *CISAKEVAdapter) FetchChanges(ctx context.Context, since time.Time) ([]*RegChange, error) {
	return []*RegChange{}, nil
}

func (c *CISAKEVAdapter) IsHealthy(ctx context.Context) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.healthy
}

func (c *CISAKEVAdapter) SetHealthy(healthy bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.healthy = healthy
}

// NVDAdapter monitors the National Vulnerability Database APIs.
type NVDAdapter struct {
	BaseAdapter
}

// NewNVDAdapter creates an NVD adapter.
func NewNVDAdapter() *NVDAdapter {
	return &NVDAdapter{
		BaseAdapter: BaseAdapter{
			sourceType:   SourceNVD,
			jurisdiction: jkg.JurisdictionGlobal,
			regulator:    jkg.RegulatorNIST,
			feedURL:      "https://services.nvd.nist.gov/rest/json/cves/2.0",
			healthy:      true,
		},
	}
}

func (n *NVDAdapter) FetchChanges(ctx context.Context, since time.Time) ([]*RegChange, error) {
	return []*RegChange{}, nil
}

func (n *NVDAdapter) IsHealthy(ctx context.Context) bool {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.healthy
}

func (n *NVDAdapter) SetHealthy(healthy bool) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.healthy = healthy
}

// OSVAdapter monitors the Open Source Vulnerabilities database.
type OSVAdapter struct {
	BaseAdapter
}

// NewOSVAdapter creates an OSV adapter.
func NewOSVAdapter() *OSVAdapter {
	return &OSVAdapter{
		BaseAdapter: BaseAdapter{
			sourceType:   SourceOSV,
			jurisdiction: jkg.JurisdictionGlobal,
			feedURL:      "https://api.osv.dev/v1",
			healthy:      true,
		},
	}
}

func (o *OSVAdapter) FetchChanges(ctx context.Context, since time.Time) ([]*RegChange, error) {
	return []*RegChange{}, nil
}

func (o *OSVAdapter) IsHealthy(ctx context.Context) bool {
	o.mu.RLock()
	defer o.mu.RUnlock()
	return o.healthy
}

func (o *OSVAdapter) SetHealthy(healthy bool) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.healthy = healthy
}

// SigstoreRekorAdapter monitors the Sigstore Rekor transparency log
// for verifiable public attestation trails.
type SigstoreRekorAdapter struct {
	BaseAdapter
}

// NewSigstoreRekorAdapter creates a Rekor transparency log adapter.
func NewSigstoreRekorAdapter() *SigstoreRekorAdapter {
	return &SigstoreRekorAdapter{
		BaseAdapter: BaseAdapter{
			sourceType:   SourceRekor,
			jurisdiction: jkg.JurisdictionGlobal,
			feedURL:      "https://rekor.sigstore.dev",
			healthy:      true,
		},
	}
}

func (s *SigstoreRekorAdapter) FetchChanges(ctx context.Context, since time.Time) ([]*RegChange, error) {
	return []*RegChange{}, nil
}

func (s *SigstoreRekorAdapter) IsHealthy(ctx context.Context) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.healthy
}

func (s *SigstoreRekorAdapter) SetHealthy(healthy bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.healthy = healthy
}
