package regwatch

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/compliance/jkg"
)

// BaseAdapter provides common functionality for source adapters.
type BaseAdapter struct {
	sourceType   SourceType
	jurisdiction jkg.JurisdictionCode
	regulator    jkg.RegulatorID
	feedURL      string
	healthy      bool
	mu           sync.RWMutex
}

// Type returns the source type.
func (b *BaseAdapter) Type() SourceType {
	return b.sourceType
}

// Jurisdiction returns the jurisdiction.
func (b *BaseAdapter) Jurisdiction() jkg.JurisdictionCode {
	return b.jurisdiction
}

// Regulator returns the regulator.
func (b *BaseAdapter) Regulator() jkg.RegulatorID {
	return b.regulator
}

// EURLexAdapter monitors EU official legislation.
type EURLexAdapter struct {
	BaseAdapter
	frameworks []string // e.g., ["MiCA", "EU AI Act", "AMLD"]
}

// NewEURLexAdapter creates an EUR-Lex adapter.
func NewEURLexAdapter(frameworks []string) *EURLexAdapter {
	return &EURLexAdapter{
		BaseAdapter: BaseAdapter{
			sourceType:   SourceEURLex,
			jurisdiction: jkg.JurisdictionEU,
			regulator:    jkg.RegulatorESMA,
			feedURL:      "https://eur-lex.europa.eu/eurlex-ws/rest/api",
			healthy:      true,
		},
		frameworks: frameworks,
	}
}

// FetchChanges retrieves legislative changes from EUR-Lex for the configured frameworks.
// In production the HTTP client queries the EUR-Lex REST/SPARQL API filtered by CELEX
// ranges per framework. Until network transport is wired, returns a deterministic seed
// set so downstream pipeline stages (normalize → compile → enforce) always have data.
func (e *EURLexAdapter) FetchChanges(ctx context.Context, since time.Time) ([]*RegChange, error) {
	var changes []*RegChange

	for _, fw := range e.frameworks {
		var celex, title string
		switch fw {
		case "MiCA":
			celex, title = "32023R1114", "Regulation (EU) 2023/1114 (MiCA)"
		case "EU AI Act":
			celex, title = "32024R1689", "Regulation (EU) 2024/1689 (AI Act)"
		case "AMLD":
			celex, title = "32015L0849", "Directive (EU) 2015/849 (AMLD)"
		case "DORA":
			celex, title = "32022R2554", "Regulation (EU) 2022/2554 (DORA)"
		default:
			continue
		}
		changes = append(changes, &RegChange{
			SourceType:       e.sourceType,
			JurisdictionCode: e.jurisdiction,
			Title:            title,
			PublishedAt:      time.Now(),
			EffectiveFrom:    time.Now(),
			Summary:          fmt.Sprintf("EUR-Lex seed: %s baseline reference", fw),
			SourceURL:        fmt.Sprintf("https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:%s", celex),
			Framework:        fw,
			Metadata:         map[string]interface{}{"celex": celex},
		})
	}
	return changes, nil
}

// IsHealthy checks EUR-Lex API availability.
func (e *EURLexAdapter) IsHealthy(ctx context.Context) bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.healthy
}

// SetHealthy sets health status (for testing).
func (e *EURLexAdapter) SetHealthy(healthy bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.healthy = healthy
}

// FinCENAdapter monitors US FinCEN bulletins.
type FinCENAdapter struct {
	BaseAdapter
}

// NewFinCENAdapter creates a FinCEN adapter.
func NewFinCENAdapter() *FinCENAdapter {
	return &FinCENAdapter{
		BaseAdapter: BaseAdapter{
			sourceType:   SourceFinCEN,
			jurisdiction: jkg.JurisdictionUS,
			regulator:    jkg.RegulatorFinCEN,
			feedURL:      "https://www.fincen.gov/rss",
			healthy:      true,
		},
	}
}

// FetchChanges retrieves changes from FinCEN.
func (f *FinCENAdapter) FetchChanges(ctx context.Context, since time.Time) ([]*RegChange, error) {
	// In production, this would parse FinCEN RSS feed
	return []*RegChange{}, nil
}

// IsHealthy checks FinCEN feed availability.
func (f *FinCENAdapter) IsHealthy(ctx context.Context) bool {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.healthy
}

// SetHealthy sets health status (for testing).
func (f *FinCENAdapter) SetHealthy(healthy bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.healthy = healthy
}

// FCAAdapter monitors UK FCA updates.
type FCAAdapter struct {
	BaseAdapter
}

// NewFCAAdapter creates an FCA adapter.
func NewFCAAdapter() *FCAAdapter {
	return &FCAAdapter{
		BaseAdapter: BaseAdapter{
			sourceType:   SourceFCA,
			jurisdiction: jkg.JurisdictionGB,
			regulator:    jkg.RegulatorFCA,
			feedURL:      "https://www.fca.org.uk/news-and-publications/rss-feeds",
			healthy:      true,
		},
	}
}

// FetchChanges retrieves changes from FCA.
func (f *FCAAdapter) FetchChanges(ctx context.Context, since time.Time) ([]*RegChange, error) {
	return []*RegChange{}, nil
}

// IsHealthy checks FCA feed availability.
func (f *FCAAdapter) IsHealthy(ctx context.Context) bool {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.healthy
}

// SetHealthy sets health status (for testing).
func (f *FCAAdapter) SetHealthy(healthy bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.healthy = healthy
}

// ESMAAdapter monitors EU ESMA publications.
type ESMAAdapter struct {
	BaseAdapter
}

// NewESMAAdapter creates an ESMA adapter.
func NewESMAAdapter() *ESMAAdapter {
	return &ESMAAdapter{
		BaseAdapter: BaseAdapter{
			sourceType:   SourceESMA,
			jurisdiction: jkg.JurisdictionEU,
			regulator:    jkg.RegulatorESMA,
			feedURL:      "https://www.esma.europa.eu/rss",
			healthy:      true,
		},
	}
}

// FetchChanges retrieves changes from ESMA.
func (e *ESMAAdapter) FetchChanges(ctx context.Context, since time.Time) ([]*RegChange, error) {
	return []*RegChange{}, nil
}

// IsHealthy checks ESMA feed availability.
func (e *ESMAAdapter) IsHealthy(ctx context.Context) bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.healthy
}

// SetHealthy sets health status (for testing).
func (e *ESMAAdapter) SetHealthy(healthy bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.healthy = healthy
}

// CreateDefaultAdapters returns a set of standard adapters.
func CreateDefaultAdapters() []SourceAdapter {
	return []SourceAdapter{
		NewEURLexAdapter([]string{"MiCA", "EU AI Act", "AMLD6"}),
		NewFinCENAdapter(),
		NewFCAAdapter(),
		NewESMAAdapter(),
	}
}

// CreateSwarmWithDefaults creates a swarm with all default adapters.
func CreateSwarmWithDefaults(graph *jkg.Graph) (*Swarm, error) {
	config := DefaultSwarmConfig()
	swarm := NewSwarm(config, graph)

	for _, adapter := range CreateDefaultAdapters() {
		if err := swarm.RegisterAdapter(adapter); err != nil {
			return nil, fmt.Errorf("failed to register adapter %s: %w", adapter.Type(), err)
		}
	}

	return swarm, nil
}

// CreateDefaultAdaptersAll returns ALL default adapters across 10 CSR classes.
// Use this for full CSR coverage. CreateDefaultAdapters() is kept for backward compat.
func CreateDefaultAdaptersAll() []SourceAdapter {
	return []SourceAdapter{
		// Class 1: Law
		NewEURLexAdapter([]string{"MiCA", "EU AI Act", "AMLD6"}),
		NewFederalRegisterAdapter(),
		NewLegislationGovUKAdapter(),
		NewECFRAdapter([]int{12, 17, 31}),
		NewSGSSOAdapter(),
		NewCNNPCAdapter(),
		// Class 2: Privacy
		NewEDPBAdapter(),
		NewCNILAdapter(),
		NewUKICOAdapter(),
		NewCPPAAdapter(),
		NewUSStatePrivacyAdapter("CA", "CCPA/CPRA", jkg.JurisdictionUS),
		NewCACAdapter(),
		NewLGPDAdapter(),
		NewPDPAAdapter(),
		NewAPPIAdapter(),
		NewPIPLAdapter(),
		// Class 3: AI
		NewEUAIActAdapter(),
		NewNISTAIRMFAdapter(),
		NewOECDAIAdapter(),
		// Class 4: Sanctions
		NewUNSanctionsAdapter(),
		NewOFACAdapter(),
		NewEUSanctionsAdapter(),
		NewUKSanctionsAdapter(),
		NewBISEntityListAdapter(),
		NewCSLTradeAdapter(),
		NewFATFAdapter(),
		NewWorldBankDebarredAdapter(),
		// Class 5: Security
		NewNISTCSFAdapter(),
		NewNIST80053Adapter(),
		NewPCIDSSAdapter(),
		NewCISControlsAdapter(),
		NewISO27001ManualImportAdapter("ISO/IEC 27001:2022", ""),
		// Class 6: Resilience
		NewNIS2Adapter(),
		NewDORAAdapter(),
		NewHIPAAAdapter(),
		// Class 7: Identity
		NewEIDASAdapter(),
		NewLOTLAdapter(),
		NewCABForumAdapter(),
		NewCTLogAdapter(),
		NewCTAppleAdapter(),
		NewETSISignatureStandardsAdapter(),
		// Class 8: Supply Chain
		NewCISAKEVAdapter(),
		NewNVDAdapter(),
		NewOSVAdapter(),
		NewSigstoreRekorAdapter(),
		// Class 9: Certification
		NewFedRAMPAdapter(),
		NewCSASTARAdapter(),
		// Class 10: Entity
		NewGLEIFAdapter(),
		NewUKCompaniesHouseAdapter(),
		NewSECEDGARAdapter(),
		NewSECXBRLAdapter(),
		// CSR Class 11: Commodity/derivatives
		NewCFTCAdapter(nil),
		// Legacy
		NewFinCENAdapter(),
		NewFCAAdapter(),
		NewESMAAdapter(),
	}
}
