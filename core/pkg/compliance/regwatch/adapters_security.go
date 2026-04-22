package regwatch

import (
	"context"
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/compliance/jkg"
)

// NISTCSFAdapter monitors NIST Cybersecurity Framework 2.0 updates.
type NISTCSFAdapter struct {
	BaseAdapter
}

// NewNISTCSFAdapter creates a NIST CSF 2.0 adapter.
func NewNISTCSFAdapter() *NISTCSFAdapter {
	return &NISTCSFAdapter{
		BaseAdapter: BaseAdapter{
			sourceType:   SourceNISTCSF,
			jurisdiction: jkg.JurisdictionGlobal,
			regulator:    jkg.RegulatorNIST,
			feedURL:      "https://nvlpubs.nist.gov/nistpubs/CSWP/NIST.CSWP.29.pdf",
			healthy:      true,
		},
	}
}

func (n *NISTCSFAdapter) FetchChanges(ctx context.Context, since time.Time) ([]*RegChange, error) {
	return []*RegChange{}, nil
}

func (n *NISTCSFAdapter) IsHealthy(ctx context.Context) bool {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.healthy
}

func (n *NISTCSFAdapter) SetHealthy(healthy bool) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.healthy = healthy
}

// NIST80053Adapter monitors NIST SP 800-53 Rev. 5 control catalog.
type NIST80053Adapter struct {
	BaseAdapter
}

// NewNIST80053Adapter creates a NIST SP 800-53 adapter.
func NewNIST80053Adapter() *NIST80053Adapter {
	return &NIST80053Adapter{
		BaseAdapter: BaseAdapter{
			sourceType:   SourceNIST80053,
			jurisdiction: jkg.JurisdictionGlobal,
			regulator:    jkg.RegulatorNIST,
			feedURL:      "https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r5.pdf",
			healthy:      true,
		},
	}
}

func (n *NIST80053Adapter) FetchChanges(ctx context.Context, since time.Time) ([]*RegChange, error) {
	return []*RegChange{}, nil
}

func (n *NIST80053Adapter) IsHealthy(ctx context.Context) bool {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.healthy
}

func (n *NIST80053Adapter) SetHealthy(healthy bool) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.healthy = healthy
}

// PCIDSSAdapter monitors PCI Data Security Standard updates.
type PCIDSSAdapter struct {
	BaseAdapter
}

// NewPCIDSSAdapter creates a PCI DSS adapter.
func NewPCIDSSAdapter() *PCIDSSAdapter {
	return &PCIDSSAdapter{
		BaseAdapter: BaseAdapter{
			sourceType:   SourcePCIDSS,
			jurisdiction: jkg.JurisdictionGlobal,
			feedURL:      "https://www.pcisecuritystandards.org/document_library/",
			healthy:      true,
		},
	}
}

func (p *PCIDSSAdapter) FetchChanges(ctx context.Context, since time.Time) ([]*RegChange, error) {
	return []*RegChange{}, nil
}

func (p *PCIDSSAdapter) IsHealthy(ctx context.Context) bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.healthy
}

func (p *PCIDSSAdapter) SetHealthy(healthy bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.healthy = healthy
}

// ISO27001ManualImportAdapter handles ISO 27001 as a MANUAL_IMPORT source.
// ISO standards are paywalled — this adapter tracks edition metadata and
// a SHA-256 hash of the uploaded PDF for change detection.
type ISO27001ManualImportAdapter struct {
	BaseAdapter
	edition string // e.g., "2022" for ISO/IEC 27001:2022
	pdfHash string // SHA-256 of uploaded PDF
}

// NewISO27001ManualImportAdapter creates an ISO 27001 manual import adapter.
func NewISO27001ManualImportAdapter(edition, pdfHash string) *ISO27001ManualImportAdapter {
	return &ISO27001ManualImportAdapter{
		BaseAdapter: BaseAdapter{
			sourceType:   SourceISO27001MI,
			jurisdiction: jkg.JurisdictionGlobal,
			feedURL:      "manual://iso-27001",
			healthy:      true,
		},
		edition: edition,
		pdfHash: pdfHash,
	}
}

func (i *ISO27001ManualImportAdapter) FetchChanges(ctx context.Context, since time.Time) ([]*RegChange, error) {
	// Manual import: no network fetch. Change detection via PDF hash comparison.
	return []*RegChange{}, nil
}

func (i *ISO27001ManualImportAdapter) IsHealthy(ctx context.Context) bool {
	i.mu.RLock()
	defer i.mu.RUnlock()
	return i.healthy
}

func (i *ISO27001ManualImportAdapter) SetHealthy(healthy bool) {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.healthy = healthy
}
