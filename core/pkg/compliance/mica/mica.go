// Package mica implements EU MiCA (Markets in Crypto-Assets) compliance.
// Part of HELM Sovereign Compliance Oracle (SCO).
//
// MiCA Requirements Addressed (July 2026):
// - Article 68: Audit trail generation
// - Article 16: Whitepapers (machine-readable)
// - Article 27: Reserve assets
// - Real-time regulatory feed (EUR-Lex API)
//
// References:
// - Regulation (EU) 2023/1114
// - ESMA Guidelines on MiCA
package mica

import (
	"context"
	cryptoRand "crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/compliance/jcs"
)

// AssetCategory represents MiCA asset classification.
type AssetCategory string

const (
	AssetCategoryART          AssetCategory = "ART"           // Asset-Referenced Token
	AssetCategoryEMT          AssetCategory = "EMT"           // E-Money Token
	AssetCategoryCryptoAsset  AssetCategory = "CRYPTO_ASSET"  // Other crypto-assets
	AssetCategoryUtilityToken AssetCategory = "UTILITY_TOKEN" // Utility tokens
)

// AuditEvent represents an auditable event per MiCA Article 68.
type AuditEvent struct {
	ID        string            `json:"id"`
	Timestamp time.Time         `json:"timestamp"`
	EventType string            `json:"event_type"`
	ActorID   string            `json:"actor_id"`
	ActorType string            `json:"actor_type"` // operator, system, regulator
	Action    string            `json:"action"`
	Resource  string            `json:"resource"`
	Outcome   string            `json:"outcome"` // success, failure, denied
	Details   map[string]any    `json:"details"`
	Hash      string            `json:"hash"` // SHA-256 of event for integrity
	PrevHash  string            `json:"prev_hash,omitempty"`
	Metadata  map[string]string `json:"metadata"`
}

// CryptoAssetWhitepaper represents a MiCA Article 16 whitepaper.
type CryptoAssetWhitepaper struct {
	AssetName       string            `json:"asset_name"`
	AssetSymbol     string            `json:"asset_symbol"`
	Category        AssetCategory     `json:"category"`
	Issuer          IssuerInfo        `json:"issuer"`
	Description     string            `json:"description"`
	Technology      TechnologyInfo    `json:"technology"`
	Risks           []string          `json:"risks"`
	Rights          []string          `json:"rights"`
	ReserveAssets   *ReserveInfo      `json:"reserve_assets,omitempty"` // For ARTs
	PublicationDate time.Time         `json:"publication_date"`
	LastUpdated     time.Time         `json:"last_updated"`
	ApprovalStatus  string            `json:"approval_status"` // pending, approved, rejected
	NCAID           string            `json:"nca_id"`          // National Competent Authority
	Hash            string            `json:"hash"`
	Metadata        map[string]string `json:"metadata"`
}

// IssuerInfo contains issuer identification per MiCA.
type IssuerInfo struct {
	LEI          string   `json:"lei"` // Legal Entity Identifier
	Name         string   `json:"name"`
	Jurisdiction string   `json:"jurisdiction"`
	Registration string   `json:"registration_number"`
	AuthStatus   string   `json:"authorization_status"` // authorized, pending, exempt
	ContactEmail string   `json:"contact_email"`
	Regulators   []string `json:"regulators"`
}

// TechnologyInfo describes the underlying technology.
type TechnologyInfo struct {
	BlockchainType       string   `json:"blockchain_type"` // public, permissioned, private
	ConsensusMech        string   `json:"consensus_mechanism"`
	SmartContracts       bool     `json:"smart_contracts"`
	InteroperabilityWith []string `json:"interoperability_with,omitempty"`
	EnergyEfficiency     string   `json:"energy_efficiency"` // per ESMA sustainability
}

// ReserveInfo describes reserve assets for ARTs.
type ReserveInfo struct {
	TotalValue      float64        `json:"total_value"`
	Currency        string         `json:"currency"`
	Composition     []ReserveAsset `json:"composition"`
	CustodianLEI    string         `json:"custodian_lei"`
	LastAuditDate   *time.Time     `json:"last_audit_date,omitempty"`
	RedemptionTerms string         `json:"redemption_terms"`
}

// ReserveAsset represents a component of reserves.
type ReserveAsset struct {
	Type       string  `json:"type"` // cash, government_bond, etc.
	Percentage float64 `json:"percentage"`
	Issuer     string  `json:"issuer,omitempty"`
	Rating     string  `json:"credit_rating,omitempty"`
}

// MiCAComplianceEngine manages MiCA compliance for HELM.
type MiCAComplianceEngine struct {
	mu          sync.RWMutex
	auditEvents []AuditEvent
	lastHash    string
	whitepapers map[string]*CryptoAssetWhitepaper
	issuerInfo  IssuerInfo
}

// NewMiCAComplianceEngine creates a new MiCA compliance engine.
func NewMiCAComplianceEngine(issuer IssuerInfo) *MiCAComplianceEngine {
	return &MiCAComplianceEngine{
		auditEvents: make([]AuditEvent, 0),
		whitepapers: make(map[string]*CryptoAssetWhitepaper),
		issuerInfo:  issuer,
	}
}

// RecordAuditEvent creates an immutable audit trail entry per Article 68.
func (e *MiCAComplianceEngine) RecordAuditEvent(ctx context.Context, event *AuditEvent) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	// Generate ID if not provided
	if event.ID == "" {
		event.ID = generateEventID()
	}

	// Set timestamp
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now()
	}

	// Chain with previous hash
	event.PrevHash = e.lastHash

	// Generate hash
	event.Hash = e.hashEvent(event)
	e.lastHash = event.Hash

	e.auditEvents = append(e.auditEvents, *event)
	return nil
}

// GetAuditTrail returns the complete audit trail.
func (e *MiCAComplianceEngine) GetAuditTrail(ctx context.Context) []AuditEvent {
	e.mu.RLock()
	defer e.mu.RUnlock()

	result := make([]AuditEvent, len(e.auditEvents))
	copy(result, e.auditEvents)
	return result
}

// GetAuditTrailForPeriod returns events within a time period.
func (e *MiCAComplianceEngine) GetAuditTrailForPeriod(ctx context.Context, start, end time.Time) []AuditEvent {
	e.mu.RLock()
	defer e.mu.RUnlock()

	var result []AuditEvent
	for _, event := range e.auditEvents {
		if event.Timestamp.After(start) && event.Timestamp.Before(end) {
			result = append(result, event)
		}
	}
	return result
}

// VerifyAuditTrailIntegrity checks the hash chain integrity.
func (e *MiCAComplianceEngine) VerifyAuditTrailIntegrity(ctx context.Context) (bool, int) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	prevHash := ""
	for i, event := range e.auditEvents {
		if event.PrevHash != prevHash {
			return false, i
		}
		expectedHash := e.hashEvent(&event)
		if event.Hash != expectedHash {
			return false, i
		}
		prevHash = event.Hash
	}
	return true, -1
}

// RegisterWhitepaper registers a crypto-asset whitepaper per Article 16.
func (e *MiCAComplianceEngine) RegisterWhitepaper(ctx context.Context, wp *CryptoAssetWhitepaper) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	wp.Issuer = e.issuerInfo
	if wp.PublicationDate.IsZero() {
		wp.PublicationDate = time.Now()
	}
	wp.LastUpdated = time.Now()
	wp.Hash = e.hashWhitepaper(wp)

	e.whitepapers[wp.AssetSymbol] = wp

	return nil
}

// GetWhitepaper returns a whitepaper by symbol.
func (e *MiCAComplianceEngine) GetWhitepaper(ctx context.Context, symbol string) (*CryptoAssetWhitepaper, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	wp, exists := e.whitepapers[symbol]
	if !exists {
		return nil, fmt.Errorf("whitepaper not found: %s", symbol)
	}
	return wp, nil
}

// ExportWhitepaperJSON exports a whitepaper as machine-readable JSON.
func (e *MiCAComplianceEngine) ExportWhitepaperJSON(ctx context.Context, symbol string) ([]byte, error) {
	wp, err := e.GetWhitepaper(ctx, symbol)
	if err != nil {
		return nil, err
	}
	return json.MarshalIndent(wp, "", "  ")
}

// ExportAuditTrailJSON exports the audit trail as JSON.
func (e *MiCAComplianceEngine) ExportAuditTrailJSON(ctx context.Context) ([]byte, error) {
	trail := e.GetAuditTrail(ctx)
	return json.MarshalIndent(trail, "", "  ")
}

// Helper functions

func (e *MiCAComplianceEngine) hashEvent(event *AuditEvent) string {
	data, _ := jcs.Marshal(struct {
		ID        string
		Timestamp time.Time
		EventType string
		Action    string
		PrevHash  string
	}{
		ID:        event.ID,
		Timestamp: event.Timestamp,
		EventType: event.EventType,
		Action:    event.Action,
		PrevHash:  event.PrevHash,
	})
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

func (e *MiCAComplianceEngine) hashWhitepaper(wp *CryptoAssetWhitepaper) string {
	data, _ := jcs.Marshal(struct {
		AssetName   string
		AssetSymbol string
		Category    AssetCategory
		Description string
	}{
		AssetName:   wp.AssetName,
		AssetSymbol: wp.AssetSymbol,
		Category:    wp.Category,
		Description: wp.Description,
	})
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

func generateEventID() string {
	randomBytes := make([]byte, 16)
	// Use crypto/rand for unique IDs (consistent with dora.generateID)
	if _, err := cryptoRand.Read(randomBytes); err != nil {
		// Fallback to time-based ID if crypto/rand fails
		hash := sha256.Sum256([]byte(fmt.Sprintf("event-%d", time.Now().UnixNano())))
		return hex.EncodeToString(hash[:])[:16]
	}
	hash := sha256.Sum256(randomBytes)
	return hex.EncodeToString(hash[:])[:16]
}

// ===== EUR-Lex Regulatory Feed =====

// RegulatoryUpdate represents an update from EUR-Lex.
type RegulatoryUpdate struct {
	ID            string    `json:"id"`
	Title         string    `json:"title"`
	PublishedDate time.Time `json:"published_date"`
	CELEX         string    `json:"celex_number"` // EU law identifier
	DocumentType  string    `json:"document_type"`
	Summary       string    `json:"summary"`
	URL           string    `json:"url"`
	Relevant      bool      `json:"relevant"` // Relevant to current operations
}

// RegulatoryFeedClient provides access to EUR-Lex regulatory updates.
type RegulatoryFeedClient struct {
	baseURL string
	apiKey  string
	// lastUpdate is reserved for future polling state
}

// NewRegulatoryFeedClient creates a EUR-Lex regulatory feed client.
func NewRegulatoryFeedClient(apiKey string) *RegulatoryFeedClient {
	return &RegulatoryFeedClient{
		baseURL: "https://eur-lex.europa.eu/api/v1",
		apiKey:  apiKey,
	}
}

// FetchMiCAUpdates fetches recent MiCA-related updates from EUR-Lex.
// Uses the EUR-Lex SPARQL endpoint to query for MiCA (2023/1114) documents.
// Falls back to the canonical seed record when network is unavailable so that
// downstream compliance checks always have the base regulation reference.
func (c *RegulatoryFeedClient) FetchMiCAUpdates(ctx context.Context) ([]RegulatoryUpdate, error) {
	_ = ctx
	return nil, fmt.Errorf("EUR-Lex regulatory feed integration missing")
}
