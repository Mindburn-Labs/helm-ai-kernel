// Package regwatch implements K2.5-powered regulatory monitoring.
// Part of the Sovereign Compliance Oracle (SCO).
package regwatch

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/compliance/jkg"
)

// SourceType identifies the type of regulatory source.
type SourceType string

const (
	SourceEURLex  SourceType = "EUR-Lex" // European Union legislation
	SourceFinCEN  SourceType = "FinCEN"  // US Financial Crimes Enforcement
	SourceFCA     SourceType = "FCA"     // UK Financial Conduct Authority
	SourceSEC     SourceType = "SEC"     // US Securities and Exchange Commission
	SourceESMA    SourceType = "ESMA"    // European Securities and Markets Authority
	SourceFSC     SourceType = "FSC"     // Bulgarian Financial Supervision Commission
	SourceGeneric SourceType = "Generic" // Generic RSS/API source

	// CSR Class 1: Primary law feeds
	SourceFedReg   SourceType = "FederalRegister" // US Federal Register
	SourceECFR     SourceType = "eCFR"            // US eCFR (codified regulations)
	SourceLegGovUK SourceType = "LegGovUK"        // UK legislation.gov.uk
	SourceSGSSO    SourceType = "SG-SSO"          // Singapore Statutes Online
	SourceCNNPC    SourceType = "CN-NPC"          // China NPC Law Database

	// CSR Class 2: Privacy authorities
	SourceEDPB      SourceType = "EDPB"           // European Data Protection Board
	SourceUKICO     SourceType = "UK-ICO"         // UK Information Commissioner's Office
	SourcePIPL      SourceType = "PIPL"           // China Personal Information Protection Law
	SourceLGPD      SourceType = "LGPD"           // Brazil Lei Geral de Proteção de Dados
	SourcePDPA      SourceType = "PDPA"           // Singapore Personal Data Protection Act
	SourceAPPI      SourceType = "APPI"           // Japan Act on Protection of Personal Information
	SourceUSPrivacy SourceType = "USStatePrivacy" // US state privacy regimes
	SourceCNIL      SourceType = "CNIL"           // France CNIL
	SourceCPPA      SourceType = "CPPA"           // California Privacy Protection Agency
	SourceCAC       SourceType = "CAC"            // Cyberspace Administration of China

	// CSR Class 3: AI governance
	SourceNISTAIRMF SourceType = "NIST-AI-RMF" // NIST AI Risk Management Framework
	SourceEUAIAct   SourceType = "EU-AI-Act"   // EU Artificial Intelligence Act
	SourceOECDAI    SourceType = "OECD-AI"     // OECD AI Principles

	// CSR Class 4: Sanctions/AML/export controls
	SourceUNSCSL      SourceType = "UN-SCSL"      // UN Security Council Consolidated List
	SourceOFAC        SourceType = "OFAC"         // US OFAC sanctions
	SourceEUSanctions SourceType = "EU-Sanctions" // EU consolidated financial sanctions
	SourceUKSanctions SourceType = "UK-Sanctions" // UK Sanctions List
	SourceFATF        SourceType = "FATF"         // FATF Recommendations
	SourceBIS         SourceType = "BIS"          // US BIS Entity List
	SourceCSLTrade    SourceType = "CSL-Trade"    // US Consolidated Screening List (Trade.gov)
	SourceWorldBank   SourceType = "WorldBank"    // World Bank Debarred Firms

	// CSR Class 5: Security control catalogs
	SourceNISTCSF    SourceType = "NIST-CSF"         // NIST Cybersecurity Framework 2.0
	SourceNIST80053  SourceType = "NIST-800-53"      // NIST SP 800-53 Rev. 5
	SourcePCIDSS     SourceType = "PCI-DSS"          // PCI Data Security Standard
	SourceISO27001MI SourceType = "ISO-27001-Manual" // ISO 27001 manual import
	SourceCIS        SourceType = "CIS"              // CIS Critical Security Controls

	// CSR Class 6: Resilience
	SourceNIS2  SourceType = "NIS2"  // EU NIS2 Directive
	SourceDORA  SourceType = "DORA"  // EU DORA Regulation
	SourceHIPAA SourceType = "HIPAA" // US HIPAA Security Rule

	// CSR Class 7: Identity and trust
	SourceeIDAS    SourceType = "eIDAS"      // EU eIDAS Regulation
	SourceLOTL     SourceType = "LOTL"       // EU List of Trusted Lists
	SourceCABForum SourceType = "CABForum"   // CA/Browser Forum
	SourceCTLog    SourceType = "CT-RFC6962" // Certificate Transparency (Chrome)
	SourceCTApple  SourceType = "CT-Apple"   // Certificate Transparency (Apple)
	SourceETSI     SourceType = "ETSI"       // ETSI e-signature standards

	// CSR Class 8: Supply chain
	SourceCISAKEV SourceType = "CISA-KEV" // CISA Known Exploited Vulnerabilities
	SourceNVD     SourceType = "NVD"      // National Vulnerability Database
	SourceOSV     SourceType = "OSV"      // Open Source Vulnerabilities
	SourceRekor   SourceType = "Rekor"    // Sigstore Rekor transparency log

	// CSR Class 9: Certification
	SourceFedRAMP SourceType = "FedRAMP"  // FedRAMP
	SourceCSASTAR SourceType = "CSA-STAR" // Cloud Security Alliance STAR

	// CSR Class 10: Entity registries
	SourceGLEIF    SourceType = "GLEIF"     // GLEIF LEI
	SourceUKCH     SourceType = "UK-CH"     // UK Companies House
	SourceSECEDGAR SourceType = "SEC-EDGAR" // SEC EDGAR Submissions
	SourceSECXBRL  SourceType = "SEC-XBRL"  // SEC EDGAR XBRL

	// CSR Class 11: Commodity/derivatives regulators
	SourceCFTC SourceType = "CFTC" // US Commodity Futures Trading Commission
)

// ChangeType indicates the type of regulatory change.
type ChangeType string

const (
	ChangeNew       ChangeType = "NEW"       // New regulation
	ChangeAmendment ChangeType = "AMENDMENT" // Modification to existing
	ChangeGuidance  ChangeType = "GUIDANCE"  // Interpretive guidance
	ChangeRepeal    ChangeType = "REPEAL"    // Regulation removed
	ChangeDeadline  ChangeType = "DEADLINE"  // Upcoming deadline reminder
)

// RegChange represents a detected regulatory change.
type RegChange struct {
	ChangeID         string                 `json:"change_id"`
	SourceType       SourceType             `json:"source_type"`
	ChangeType       ChangeType             `json:"change_type"`
	JurisdictionCode jkg.JurisdictionCode   `json:"jurisdiction_code"`
	RegulatorID      jkg.RegulatorID        `json:"regulator_id"`
	Framework        string                 `json:"framework"`
	Title            string                 `json:"title"`
	Summary          string                 `json:"summary"`
	SourceURL        string                 `json:"source_url"`
	PublishedAt      time.Time              `json:"published_at"`
	EffectiveFrom    time.Time              `json:"effective_from,omitempty"`
	DetectedAt       time.Time              `json:"detected_at"`
	RawContent       string                 `json:"raw_content,omitempty"`
	Metadata         map[string]interface{} `json:"metadata,omitempty"`
	Processed        bool                   `json:"processed"`
	ObligationID     string                 `json:"obligation_id,omitempty"` // Link to JKG
}

// SourceAdapter defines the interface for regulatory source adapters.
type SourceAdapter interface {
	// Type returns the source type.
	Type() SourceType

	// Jurisdiction returns the primary jurisdiction.
	Jurisdiction() jkg.JurisdictionCode

	// Regulator returns the regulator ID.
	Regulator() jkg.RegulatorID

	// FetchChanges retrieves changes since the given timestamp.
	FetchChanges(ctx context.Context, since time.Time) ([]*RegChange, error)

	// IsHealthy checks if the source is accessible.
	IsHealthy(ctx context.Context) bool
}

// RawArtifact is the unprocessed output of a source fetch operation.
type RawArtifact struct {
	ContentType string    `json:"content_type"` // MIME type
	Body        []byte    `json:"-"`            // Raw bytes (not serialized)
	Size        int64     `json:"size"`
	FetchedAt   time.Time `json:"fetched_at"`
	ETag        string    `json:"etag,omitempty"`
	SourceURL   string    `json:"source_url"`
}

// SourceVersion tracks the version of a fetched source.
type SourceVersion struct {
	Version   string    `json:"version"`
	Hash      string    `json:"hash"` // SHA-256 of RawArtifact.Body
	Timestamp time.Time `json:"timestamp"`
	Sequence  int64     `json:"sequence,omitempty"`
}

// FetchTrace records the details of a single fetch operation.
type FetchTrace struct {
	StartTime   time.Time     `json:"start_time"`
	EndTime     time.Time     `json:"end_time"`
	Duration    time.Duration `json:"duration"`
	StatusCode  int           `json:"status_code"`
	RetryCount  int           `json:"retry_count"`
	BytesRead   int64         `json:"bytes_read"`
	CacheHit    bool          `json:"cache_hit"`
	Error       string        `json:"error,omitempty"`
	RateLimited bool          `json:"rate_limited"`
}

// NormalizedDoc is the output of processing a raw artifact into canonical form.
type NormalizedDoc struct {
	SchemaURI string                   `json:"schema_uri"` // e.g., "helm://schemas/compliance/SanctionsEntityRecord.v1"
	Records   []map[string]interface{} `json:"records"`
	Hash      string                   `json:"hash"` // SHA-256 of canonical JSON of records
}

// NormalizationTrace records how raw data was transformed.
type NormalizationTrace struct {
	FieldsMapped  int      `json:"fields_mapped"`
	FieldsDropped int      `json:"fields_dropped"`
	Warnings      []string `json:"warnings,omitempty"`
	SchemaVersion string   `json:"schema_version"`
}

// ChangeSet describes what changed between two versions of a source.
type ChangeSet struct {
	PreviousVersion SourceVersion            `json:"previous_version"`
	CurrentVersion  SourceVersion            `json:"current_version"`
	Added           []map[string]interface{} `json:"added,omitempty"`
	Removed         []map[string]interface{} `json:"removed,omitempty"`
	Modified        []map[string]interface{} `json:"modified,omitempty"`
	IsFullRefresh   bool                     `json:"is_full_refresh"`
}

// TrustReport summarizes the trust verification of a raw artifact.
type TrustReport struct {
	SignatureValid bool   `json:"signature_valid"`
	HashValid      bool   `json:"hash_valid"`
	ChainValid     bool   `json:"chain_valid"`
	TimestampValid bool   `json:"timestamp_valid"`
	OverallTrust   string `json:"overall_trust"` // "trusted", "degraded", "untrusted", "unknown"
	Details        string `json:"details,omitempty"`
}

// StructuredSourceAdapter extends SourceAdapter with structured fetch, normalize,
// diff, and trust verification operations. This is the CSR-grade adapter interface.
// Adapters that only implement SourceAdapter still work; StructuredSourceAdapter
// is an opt-in upgrade for full evidence-pack integration.
type StructuredSourceAdapter interface {
	SourceAdapter

	// Fetch retrieves a raw artifact from the source.
	Fetch(ctx context.Context) (*RawArtifact, *SourceVersion, *FetchTrace, error)

	// Normalize transforms a raw artifact into canonical records.
	Normalize(raw *RawArtifact) (*NormalizedDoc, *NormalizationTrace, error)

	// Diff computes the change set between old and new normalized documents.
	Diff(old, new *NormalizedDoc) (*ChangeSet, error)

	// VerifyTrust validates signatures, hashes, and chain of trust.
	VerifyTrust(raw *RawArtifact) (*TrustReport, error)
}

// AgentType identifies swarm agent roles.
type AgentType string

const (
	AgentSourceMonitor  AgentType = "SourceMonitor"  // Polls regulatory sources
	AgentDiffDetector   AgentType = "DiffDetector"   // Detects changes in documents
	AgentSemanticParser AgentType = "SemanticParser" // Extracts obligations from text
	AgentImpactAssessor AgentType = "ImpactAssessor" // Maps changes to entities
)

// SwarmAgent represents a K2.5-style monitoring agent.
type SwarmAgent struct {
	AgentID    string        `json:"agent_id"`
	Type       AgentType     `json:"type"`
	Adapter    SourceAdapter `json:"-"`
	LastRun    time.Time     `json:"last_run"`
	RunCount   int64         `json:"run_count"`
	ErrorCount int64         `json:"error_count"`
	LastError  string        `json:"last_error,omitempty"`
	IsHealthy  bool          `json:"is_healthy"`
}

// SwarmConfig configures the RegWatch swarm.
type SwarmConfig struct {
	PollInterval     time.Duration `json:"poll_interval"`      // How often to check sources
	MaxConcurrency   int           `json:"max_concurrency"`    // Parallel agent limit
	RetryAttempts    int           `json:"retry_attempts"`     // Retries on failure
	RetryDelay       time.Duration `json:"retry_delay"`        // Delay between retries
	ChangeBufferSize int           `json:"change_buffer_size"` // Channel buffer size
	EnabledSources   []SourceType  `json:"enabled_sources"`    // Active source types
}

// DefaultSwarmConfig returns sensible defaults.
func DefaultSwarmConfig() *SwarmConfig {
	return &SwarmConfig{
		PollInterval:     15 * time.Minute,
		MaxConcurrency:   10,
		RetryAttempts:    3,
		RetryDelay:       5 * time.Second,
		ChangeBufferSize: 100,
		EnabledSources:   []SourceType{SourceEURLex, SourceFinCEN, SourceFCA, SourceESMA},
	}
}

// Swarm orchestrates regulatory monitoring agents.
type Swarm struct {
	mu       sync.RWMutex
	config   *SwarmConfig
	agents   map[string]*SwarmAgent
	adapters map[SourceType]SourceAdapter
	graph    *jkg.Graph
	changes  chan *RegChange
	metrics  *SwarmMetrics
	running  bool
	stopCh   chan struct{}
}

// SwarmMetrics tracks swarm performance.
type SwarmMetrics struct {
	mu              sync.RWMutex
	TotalPolls      int64                `json:"total_polls"`
	TotalChanges    int64                `json:"total_changes"`
	ChangesBySource map[SourceType]int64 `json:"changes_by_source"`
	ChangesByType   map[ChangeType]int64 `json:"changes_by_type"`
	AvgPollDuration time.Duration        `json:"avg_poll_duration"`
	LastPollTime    time.Time            `json:"last_poll_time"`
	HealthyAgents   int                  `json:"healthy_agents"`
	UnhealthyAgents int                  `json:"unhealthy_agents"`
}

// NewSwarm creates a new RegWatch swarm.
func NewSwarm(config *SwarmConfig, graph *jkg.Graph) *Swarm {
	if config == nil {
		config = DefaultSwarmConfig()
	}

	return &Swarm{
		config:   config,
		agents:   make(map[string]*SwarmAgent),
		adapters: make(map[SourceType]SourceAdapter),
		graph:    graph,
		changes:  make(chan *RegChange, config.ChangeBufferSize),
		metrics:  newSwarmMetrics(),
		stopCh:   make(chan struct{}),
	}
}

func newSwarmMetrics() *SwarmMetrics {
	return &SwarmMetrics{
		ChangesBySource: make(map[SourceType]int64),
		ChangesByType:   make(map[ChangeType]int64),
	}
}

// RegisterAdapter registers a source adapter.
func (s *Swarm) RegisterAdapter(adapter SourceAdapter) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if adapter == nil {
		return fmt.Errorf("adapter is nil")
	}

	sourceType := adapter.Type()
	s.adapters[sourceType] = adapter

	// Create monitoring agent for this adapter
	agent := &SwarmAgent{
		AgentID:   fmt.Sprintf("agent-%s-%s", AgentSourceMonitor, sourceType),
		Type:      AgentSourceMonitor,
		Adapter:   adapter,
		IsHealthy: true,
	}
	s.agents[agent.AgentID] = agent

	return nil
}

// Start begins the monitoring loop.
func (s *Swarm) Start(ctx context.Context) error {
	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return fmt.Errorf("swarm already running")
	}
	s.running = true
	s.mu.Unlock()

	go s.pollLoop(ctx)
	return nil
}

// Stop halts the monitoring loop.
func (s *Swarm) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.running {
		return
	}

	close(s.stopCh)
	s.running = false
}

// Changes returns the channel for receiving detected changes.
func (s *Swarm) Changes() <-chan *RegChange {
	return s.changes
}

// pollLoop runs the continuous polling cycle.
func (s *Swarm) pollLoop(ctx context.Context) {
	ticker := time.NewTicker(s.config.PollInterval)
	defer ticker.Stop()

	// Initial poll
	s.pollAll(ctx)

	for {
		select {
		case <-ctx.Done():
			return
		case <-s.stopCh:
			return
		case <-ticker.C:
			s.pollAll(ctx)
		}
	}
}

// pollAll polls all registered adapters.
func (s *Swarm) pollAll(ctx context.Context) {
	s.mu.RLock()
	agents := make([]*SwarmAgent, 0, len(s.agents))
	for _, a := range s.agents {
		if a.Type == AgentSourceMonitor {
			agents = append(agents, a)
		}
	}
	s.mu.RUnlock()

	// Use semaphore for concurrency control
	sem := make(chan struct{}, s.config.MaxConcurrency)
	var wg sync.WaitGroup

	for _, agent := range agents {
		wg.Add(1)
		go func(a *SwarmAgent) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			s.pollAgent(ctx, a)
		}(agent)
	}

	wg.Wait()
	s.updateHealthMetrics()
}

// pollAgent polls a single agent's adapter.
func (s *Swarm) pollAgent(ctx context.Context, agent *SwarmAgent) {
	start := time.Now()

	// Check health first
	if !agent.Adapter.IsHealthy(ctx) {
		s.mu.Lock()
		agent.IsHealthy = false
		agent.LastError = "health check failed"
		s.mu.Unlock()
		return
	}

	// Determine since timestamp
	since := agent.LastRun
	if since.IsZero() {
		since = time.Now().Add(-24 * time.Hour) // Last 24h for first run
	}

	// Fetch changes with retry
	var changes []*RegChange
	var err error

	for attempt := 0; attempt <= s.config.RetryAttempts; attempt++ {
		changes, err = agent.Adapter.FetchChanges(ctx, since)
		if err == nil {
			break
		}
		time.Sleep(s.config.RetryDelay)
	}

	s.mu.Lock()
	agent.LastRun = time.Now()
	agent.RunCount++

	if err != nil {
		agent.ErrorCount++
		agent.LastError = err.Error()
		agent.IsHealthy = false
		s.mu.Unlock()
		return
	}

	agent.IsHealthy = true
	agent.LastError = ""
	s.mu.Unlock()

	// Process changes
	for _, change := range changes {
		change.DetectedAt = time.Now()
		change.ChangeID = generateChangeID(change)

		// Update metrics
		s.metrics.mu.Lock()
		s.metrics.TotalChanges++
		s.metrics.ChangesBySource[change.SourceType]++
		s.metrics.ChangesByType[change.ChangeType]++
		s.metrics.mu.Unlock()

		// Send to changes channel (non-blocking)
		select {
		case s.changes <- change:
		default:
			// Channel full, log warning in production
		}
	}

	// Update poll metrics
	s.metrics.mu.Lock()
	s.metrics.TotalPolls++
	s.metrics.LastPollTime = time.Now()
	pollDuration := time.Since(start)
	if s.metrics.AvgPollDuration == 0 {
		s.metrics.AvgPollDuration = pollDuration
	} else {
		s.metrics.AvgPollDuration = (s.metrics.AvgPollDuration + pollDuration) / 2
	}
	s.metrics.mu.Unlock()
}

// updateHealthMetrics updates agent health stats.
func (s *Swarm) updateHealthMetrics() {
	s.mu.RLock()
	defer s.mu.RUnlock()

	healthy := 0
	unhealthy := 0

	for _, agent := range s.agents {
		if agent.IsHealthy {
			healthy++
		} else {
			unhealthy++
		}
	}

	s.metrics.mu.Lock()
	s.metrics.HealthyAgents = healthy
	s.metrics.UnhealthyAgents = unhealthy
	s.metrics.mu.Unlock()
}

// GetMetrics returns current swarm metrics.
func (s *Swarm) GetMetrics() *SwarmMetrics {
	s.metrics.mu.RLock()
	defer s.metrics.mu.RUnlock()

	// Return a copy
	return &SwarmMetrics{
		TotalPolls:      s.metrics.TotalPolls,
		TotalChanges:    s.metrics.TotalChanges,
		ChangesBySource: copySourceMap(s.metrics.ChangesBySource),
		ChangesByType:   copyTypeMap(s.metrics.ChangesByType),
		AvgPollDuration: s.metrics.AvgPollDuration,
		LastPollTime:    s.metrics.LastPollTime,
		HealthyAgents:   s.metrics.HealthyAgents,
		UnhealthyAgents: s.metrics.UnhealthyAgents,
	}
}

// GetAgents returns all registered agents.
func (s *Swarm) GetAgents() []*SwarmAgent {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]*SwarmAgent, 0, len(s.agents))
	for _, a := range s.agents {
		result = append(result, a)
	}
	return result
}

// IsRunning returns whether the swarm is active.
func (s *Swarm) IsRunning() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.running
}

// PollNow triggers an immediate poll cycle.
func (s *Swarm) PollNow(ctx context.Context) {
	s.pollAll(ctx)
}

// generateChangeID creates a deterministic change ID.
func generateChangeID(c *RegChange) string {
	data := fmt.Sprintf("%s:%s:%s:%s:%s",
		c.SourceType, c.JurisdictionCode, c.Title, c.SourceURL, c.PublishedAt.Format(time.RFC3339))
	h := sha256.Sum256([]byte(data))
	return hex.EncodeToString(h[:])[:16]
}

func copySourceMap(m map[SourceType]int64) map[SourceType]int64 {
	result := make(map[SourceType]int64, len(m))
	for k, v := range m {
		result[k] = v
	}
	return result
}

func copyTypeMap(m map[ChangeType]int64) map[ChangeType]int64 {
	result := make(map[ChangeType]int64, len(m))
	for k, v := range m {
		result[k] = v
	}
	return result
}
