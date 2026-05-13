// Package jkg provides the Jurisdiction Knowledge Graph for compliance.
// Part of the Sovereign Compliance Oracle (SCO).
package jkg

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/compliance/jcs"
)

// JurisdictionCode represents an ISO 3166-1 alpha-2 code with extensions.
// Examples: "EU", "US", "GB", "BG", "EU-MiCA", "US-FinCEN"
type JurisdictionCode string

// Standard jurisdiction codes.
const (
	JurisdictionEU     JurisdictionCode = "EU"
	JurisdictionUS     JurisdictionCode = "US"
	JurisdictionGB     JurisdictionCode = "GB"
	JurisdictionBG     JurisdictionCode = "BG"
	JurisdictionCY     JurisdictionCode = "CY"
	JurisdictionGlobal JurisdictionCode = "GLOBAL"

	// CSR: Global coverage jurisdictions
	JurisdictionCN   JurisdictionCode = "CN"    // China
	JurisdictionIN   JurisdictionCode = "IN"    // India
	JurisdictionBR   JurisdictionCode = "BR"    // Brazil
	JurisdictionSG   JurisdictionCode = "SG"    // Singapore
	JurisdictionJP   JurisdictionCode = "JP"    // Japan
	JurisdictionUSCA JurisdictionCode = "US-CA" // California
	JurisdictionUSVA JurisdictionCode = "US-VA" // Virginia
	JurisdictionUSCO JurisdictionCode = "US-CO" // Colorado
	JurisdictionUSCT JurisdictionCode = "US-CT" // Connecticut
	JurisdictionUSUT JurisdictionCode = "US-UT" // Utah
)

// RegulatorID uniquely identifies a regulatory authority.
type RegulatorID string

// Standard regulators.
const (
	RegulatorESMA   RegulatorID = "EU-ESMA"   // European Securities and Markets Authority
	RegulatorEBA    RegulatorID = "EU-EBA"    // European Banking Authority
	RegulatorFinCEN RegulatorID = "US-FinCEN" // Financial Crimes Enforcement Network
	RegulatorSEC    RegulatorID = "US-SEC"    // Securities and Exchange Commission
	RegulatorFCA    RegulatorID = "GB-FCA"    // Financial Conduct Authority
	RegulatorPRA    RegulatorID = "GB-PRA"    // Prudential Regulation Authority
	RegulatorFSC    RegulatorID = "BG-FSC"    // Financial Supervision Commission
	RegulatorNRA    RegulatorID = "BG-NRA"    // National Revenue Agency
	RegulatorCySEC  RegulatorID = "CY-CySEC"  // Cyprus Securities and Exchange Commission

	// CSR: Privacy authorities
	RegulatorEDPB RegulatorID = "EU-EDPB" // European Data Protection Board
	RegulatorCNIL RegulatorID = "FR-CNIL" // Commission Nationale de l'Informatique et des Libertés
	RegulatorCAC  RegulatorID = "CN-CAC"  // Cyberspace Administration of China
	RegulatorDPA  RegulatorID = "IN-DPA"  // India Data Protection Authority
	RegulatorANPD RegulatorID = "BR-ANPD" // Autoridade Nacional de Proteção de Dados
	RegulatorPDPC RegulatorID = "SG-PDPC" // Personal Data Protection Commission
	RegulatorPPC  RegulatorID = "JP-PPC"  // Personal Information Protection Commission

	// CSR: Sanctions and AML
	RegulatorOFAC RegulatorID = "US-OFAC"     // Office of Foreign Assets Control
	RegulatorBIS  RegulatorID = "US-BIS"      // Bureau of Industry and Security
	RegulatorFATF RegulatorID = "GLOBAL-FATF" // Financial Action Task Force
	RegulatorUNSC RegulatorID = "GLOBAL-UNSC" // UN Security Council
	RegulatorOFSI RegulatorID = "GB-OFSI"     // Office of Financial Sanctions Implementation

	// CSR: Security and resilience
	RegulatorNIST  RegulatorID = "US-NIST"  // National Institute of Standards and Technology
	RegulatorCISA  RegulatorID = "US-CISA"  // Cybersecurity and Infrastructure Security Agency
	RegulatorENISA RegulatorID = "EU-ENISA" // European Union Agency for Cybersecurity
	RegulatorHHS   RegulatorID = "US-HHS"   // Department of Health and Human Services

	// CSR: Entity registries
	RegulatorGLEIF     RegulatorID = "GLOBAL-GLEIF" // Global Legal Entity Identifier Foundation
	RegulatorCompHouse RegulatorID = "GB-CH"        // UK Companies House
	RegulatorEURLex    RegulatorID = "EU-EURLEX"    // EUR-Lex legislative database

	// CSR: Commodity/derivatives regulators
	RegulatorCFTC RegulatorID = "US-CFTC" // Commodity Futures Trading Commission
)

// JurisdictionScope classifies the level of a jurisdiction.
type JurisdictionScope string

const (
	ScopeCountry       JurisdictionScope = "COUNTRY"
	ScopeState         JurisdictionScope = "STATE"
	ScopeSupranational JurisdictionScope = "SUPRANATIONAL"
)

// LegalSystemHint classifies the legal tradition for overlay selection.
type LegalSystemHint string

const (
	LegalSystemCommonLaw LegalSystemHint = "COMMON_LAW"
	LegalSystemCivilLaw  LegalSystemHint = "CIVIL_LAW"
	LegalSystemMixed     LegalSystemHint = "MIXED"
)

// Jurisdiction represents a legal jurisdiction with regulatory scope.
type Jurisdiction struct {
	Code        JurisdictionCode  `json:"code"`
	Name        string            `json:"name"`
	Regulators  []RegulatorID     `json:"regulators"`
	ParentCode  JurisdictionCode  `json:"parent_code,omitempty"` // e.g., BG → EU
	Treaties    []string          `json:"treaties,omitempty"`    // Mutual recognition
	TimeZone    string            `json:"timezone"`
	Scope       JurisdictionScope `json:"scope,omitempty"`        // CSR: COUNTRY, STATE, SUPRANATIONAL
	LegalSystem LegalSystemHint   `json:"legal_system,omitempty"` // CSR: for overlay selection
	LastUpdated time.Time         `json:"last_updated"`
}

// Regulator represents a regulatory authority.
type Regulator struct {
	ID                RegulatorID      `json:"id"`
	Name              string           `json:"name"`
	Jurisdiction      JurisdictionCode `json:"jurisdiction"`
	Scope             []string         `json:"scope"` // e.g., ["banking", "securities", "crypto"]
	Website           string           `json:"website"`
	FeedURL           string           `json:"feed_url,omitempty"` // RSS/API for updates
	EnforcementPowers []string         `json:"enforcement_powers"`
	LastUpdated       time.Time        `json:"last_updated"`
}

// ObligationType defines the nature of a regulatory obligation.
type ObligationType string

const (
	ObligationProhibition  ObligationType = "PROHIBITION"  // Must not do
	ObligationRequirement  ObligationType = "REQUIREMENT"  // Must do
	ObligationPermission   ObligationType = "PERMISSION"   // May do
	ObligationReporting    ObligationType = "REPORTING"    // Must report
	ObligationRegistration ObligationType = "REGISTRATION" // Must register

	// CSR: Extended obligation types for global coverage
	ObligationPrivacy            ObligationType = "PRIVACY"             // Data protection obligations
	ObligationAIGovernance       ObligationType = "AI_GOVERNANCE"       // AI/algorithmic accountability
	ObligationSanctionsScreening ObligationType = "SANCTIONS_SCREENING" // Sanctions/AML screening
	ObligationExportControls     ObligationType = "EXPORT_CONTROLS"     // Export control compliance
	ObligationResilience         ObligationType = "RESILIENCE"          // Operational resilience
	ObligationSecurityControls   ObligationType = "SECURITY_CONTROLS"   // Security framework compliance
	ObligationIdentityTrust      ObligationType = "IDENTITY_TRUST"      // Trust services/e-signature
	ObligationSupplyChain        ObligationType = "SUPPLY_CHAIN"        // Supply chain security
	ObligationCertification      ObligationType = "CERTIFICATION"       // Certification requirements
	ObligationEntityIdentity     ObligationType = "ENTITY_IDENTITY"     // Entity identification
	ObligationConsumerProtection ObligationType = "CONSUMER_PROTECTION" // Consumer protection
	ObligationFinancialReporting ObligationType = "FINANCIAL_REPORTING" // Financial reporting/disclosure
)

// RiskLevel indicates the compliance risk level.
type RiskLevel string

const (
	RiskCritical RiskLevel = "CRITICAL" // Immediate action required
	RiskHigh     RiskLevel = "HIGH"     // Significant exposure
	RiskMedium   RiskLevel = "MEDIUM"   // Moderate concern
	RiskLow      RiskLevel = "LOW"      // Minor issue
	RiskInfo     RiskLevel = "INFO"     // Informational only
)

// Obligation represents a regulatory requirement.
type Obligation struct {
	ObligationID     string           `json:"obligation_id"`
	JurisdictionCode JurisdictionCode `json:"jurisdiction_code"`
	RegulatorID      RegulatorID      `json:"regulator_id"`
	Framework        string           `json:"framework"`   // e.g., "MiCA", "EU AI Act", "AML5"
	ArticleRef       string           `json:"article_ref"` // e.g., "Article 15(3)"
	Type             ObligationType   `json:"type"`
	Title            string           `json:"title"`
	Description      string           `json:"description"`
	SubjectCriteria  string           `json:"subject_criteria"` // CEL expression for who it applies to
	ObjectCriteria   string           `json:"object_criteria"`  // CEL expression for what it restricts
	EffectiveFrom    time.Time        `json:"effective_from"`
	SunsetAt         time.Time        `json:"sunset_at,omitempty"`
	RiskLevel        RiskLevel        `json:"risk_level"`
	PenaltyMax       string           `json:"penalty_max,omitempty"` // e.g., "€35M or 7% turnover"
	EvidenceReqs     []string         `json:"evidence_requirements"`
	SourceURL        string           `json:"source_url"`
	Version          int              `json:"version"`
	SupersededBy     string           `json:"superseded_by,omitempty"`
	LastUpdated      time.Time        `json:"last_updated"`
}

// EdgeType defines relationship types in the knowledge graph.
type EdgeType string

const (
	EdgeAppliesIn     EdgeType = "APPLIES_IN"         // Obligation → Jurisdiction
	EdgeRegulates     EdgeType = "REGULATES"          // Regulator → Obligation
	EdgeSupersedes    EdgeType = "SUPERSEDES"         // New regulation → Old regulation
	EdgeConflictsWith EdgeType = "CONFLICTS_WITH"     // Cross-jurisdiction conflict
	EdgeRequires      EdgeType = "REQUIRES"           // License → Obligation
	EdgeMemberOf      EdgeType = "MEMBER_OF"          // Jurisdiction → Union (e.g., BG → EU)
	EdgeMutualRecog   EdgeType = "MUTUAL_RECOGNITION" // Between jurisdictions
)

// Edge represents a relationship in the knowledge graph.
type Edge struct {
	EdgeID     string                 `json:"edge_id"`
	Type       EdgeType               `json:"type"`
	FromID     string                 `json:"from_id"`
	FromType   string                 `json:"from_type"` // "jurisdiction", "regulator", "obligation"
	ToID       string                 `json:"to_id"`
	ToType     string                 `json:"to_type"`
	Properties map[string]interface{} `json:"properties,omitempty"`
	CreatedAt  time.Time              `json:"created_at"`
}

// Graph is the main Jurisdiction Knowledge Graph structure.
type Graph struct {
	mu            sync.RWMutex
	jurisdictions map[JurisdictionCode]*Jurisdiction
	regulators    map[RegulatorID]*Regulator
	obligations   map[string]*Obligation
	edges         map[string]*Edge
	metrics       *GraphMetrics
}

// GraphMetrics tracks graph statistics.
type GraphMetrics struct {
	mu                 sync.RWMutex
	TotalJurisdictions int       `json:"total_jurisdictions"`
	TotalRegulators    int       `json:"total_regulators"`
	TotalObligations   int       `json:"total_obligations"`
	TotalEdges         int       `json:"total_edges"`
	ConflictCount      int       `json:"conflict_count"`
	LastUpdated        time.Time `json:"last_updated"`
}

// NewGraph creates a new Jurisdiction Knowledge Graph.
func NewGraph() *Graph {
	return &Graph{
		jurisdictions: make(map[JurisdictionCode]*Jurisdiction),
		regulators:    make(map[RegulatorID]*Regulator),
		obligations:   make(map[string]*Obligation),
		edges:         make(map[string]*Edge),
		metrics:       &GraphMetrics{},
	}
}

// AddJurisdiction adds a jurisdiction to the graph.
func (g *Graph) AddJurisdiction(j *Jurisdiction) error {
	g.mu.Lock()
	defer g.mu.Unlock()

	if j.Code == "" {
		return fmt.Errorf("jurisdiction code is required")
	}

	j.LastUpdated = time.Now()
	g.jurisdictions[j.Code] = j
	g.updateMetrics()

	return nil
}

// AddRegulator adds a regulator to the graph.
func (g *Graph) AddRegulator(r *Regulator) error {
	g.mu.Lock()
	defer g.mu.Unlock()

	if r.ID == "" {
		return fmt.Errorf("regulator ID is required")
	}

	r.LastUpdated = time.Now()
	g.regulators[r.ID] = r
	g.updateMetrics()

	return nil
}

// AddObligation adds an obligation to the graph.
func (g *Graph) AddObligation(o *Obligation) error {
	g.mu.Lock()
	defer g.mu.Unlock()

	if o.ObligationID == "" {
		return fmt.Errorf("obligation ID is required")
	}

	o.LastUpdated = time.Now()
	g.obligations[o.ObligationID] = o

	// Auto-create edges
	g.createObligationEdges(o)
	g.updateMetrics()

	return nil
}

// AddEdge adds an edge to the graph.
func (g *Graph) AddEdge(e *Edge) error {
	g.mu.Lock()
	defer g.mu.Unlock()

	if e.EdgeID == "" {
		e.EdgeID = generateEdgeID(e)
	}

	e.CreatedAt = time.Now()
	g.edges[e.EdgeID] = e

	if e.Type == EdgeConflictsWith {
		g.metrics.ConflictCount++
	}

	g.updateMetrics()
	return nil
}

// GetJurisdiction retrieves a jurisdiction by code.
func (g *Graph) GetJurisdiction(code JurisdictionCode) (*Jurisdiction, bool) {
	g.mu.RLock()
	defer g.mu.RUnlock()
	j, ok := g.jurisdictions[code]
	return j, ok
}

// GetRegulator retrieves a regulator by ID.
func (g *Graph) GetRegulator(id RegulatorID) (*Regulator, bool) {
	g.mu.RLock()
	defer g.mu.RUnlock()
	r, ok := g.regulators[id]
	return r, ok
}

// GetObligation retrieves an obligation by ID.
func (g *Graph) GetObligation(id string) (*Obligation, bool) {
	g.mu.RLock()
	defer g.mu.RUnlock()
	o, ok := g.obligations[id]
	return o, ok
}

// GetObligationsForJurisdiction returns all obligations for a jurisdiction.
func (g *Graph) GetObligationsForJurisdiction(code JurisdictionCode) []*Obligation {
	g.mu.RLock()
	defer g.mu.RUnlock()

	result := make([]*Obligation, 0)
	for _, o := range g.obligations {
		if o.JurisdictionCode == code && !o.isExpired() {
			result = append(result, o)
		}
	}

	// Include parent jurisdiction obligations (e.g., EU → BG)
	if j, ok := g.jurisdictions[code]; ok && j.ParentCode != "" {
		for _, o := range g.obligations {
			if o.JurisdictionCode == j.ParentCode && !o.isExpired() {
				result = append(result, o)
			}
		}
	}

	return result
}

// GetConflicts returns all conflict edges in the graph.
func (g *Graph) GetConflicts() []*Edge {
	g.mu.RLock()
	defer g.mu.RUnlock()

	result := make([]*Edge, 0)
	for _, e := range g.edges {
		if e.Type == EdgeConflictsWith {
			result = append(result, e)
		}
	}
	return result
}

// FindApplicableObligations finds obligations applicable to an entity.
func (g *Graph) FindApplicableObligations(jurisdictions []JurisdictionCode, entityType string) []*Obligation {
	g.mu.RLock()
	defer g.mu.RUnlock()

	seen := make(map[string]bool)
	result := make([]*Obligation, 0)

	for _, code := range jurisdictions {
		for _, o := range g.GetObligationsForJurisdiction(code) {
			if !seen[o.ObligationID] && o.appliesToEntityType(entityType) {
				seen[o.ObligationID] = true
				result = append(result, o)
			}
		}
	}

	return result
}

// GetMetrics returns the current graph metrics.
func (g *Graph) GetMetrics() *GraphMetrics {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.metrics
}

// Hash returns a deterministic hash of the graph state including all content.
func (g *Graph) Hash() string {
	g.mu.RLock()
	defer g.mu.RUnlock()

	// 1. Hash Jurisdictions
	jKeys := make([]string, 0, len(g.jurisdictions))
	for k := range g.jurisdictions {
		jKeys = append(jKeys, string(k))
	}
	sort.Strings(jKeys)
	jHashes := make([]string, 0, len(jKeys))
	for _, k := range jKeys {
		data, _ := jcs.Marshal(g.jurisdictions[JurisdictionCode(k)])
		sum := sha256.Sum256(data)
		jHashes = append(jHashes, hex.EncodeToString(sum[:]))
	}

	// 2. Hash Regulators
	rKeys := make([]string, 0, len(g.regulators))
	for k := range g.regulators {
		rKeys = append(rKeys, string(k))
	}
	sort.Strings(rKeys)
	rHashes := make([]string, 0, len(rKeys))
	for _, k := range rKeys {
		data, _ := jcs.Marshal(g.regulators[RegulatorID(k)])
		sum := sha256.Sum256(data)
		rHashes = append(rHashes, hex.EncodeToString(sum[:]))
	}

	// 3. Hash Obligations
	oKeys := make([]string, 0, len(g.obligations))
	for k := range g.obligations {
		oKeys = append(oKeys, k)
	}
	sort.Strings(oKeys)
	oHashes := make([]string, 0, len(oKeys))
	for _, k := range oKeys {
		data, _ := jcs.Marshal(g.obligations[k])
		sum := sha256.Sum256(data)
		oHashes = append(oHashes, hex.EncodeToString(sum[:]))
	}

	// 4. Hash Edges
	eKeys := make([]string, 0, len(g.edges))
	for k := range g.edges {
		eKeys = append(eKeys, k)
	}
	sort.Strings(eKeys)
	eHashes := make([]string, 0, len(eKeys))
	for _, k := range eKeys {
		data, _ := jcs.Marshal(g.edges[k])
		sum := sha256.Sum256(data)
		eHashes = append(eHashes, hex.EncodeToString(sum[:]))
	}

	// 5. Combined Hash
	finalStructure := struct {
		Jurisdictions []string
		Regulators    []string
		Obligations   []string
		Edges         []string
	}{
		Jurisdictions: jHashes,
		Regulators:    rHashes,
		Obligations:   oHashes,
		Edges:         eHashes,
	}

	finalData, _ := jcs.Marshal(finalStructure)
	h := sha256.Sum256(finalData)
	return hex.EncodeToString(h[:])
}

// createObligationEdges auto-creates edges for a new obligation.
func (g *Graph) createObligationEdges(o *Obligation) {
	// APPLIES_IN edge
	applyEdge := &Edge{
		Type:     EdgeAppliesIn,
		FromID:   o.ObligationID,
		FromType: "obligation",
		ToID:     string(o.JurisdictionCode),
		ToType:   "jurisdiction",
	}
	applyEdge.EdgeID = generateEdgeID(applyEdge)
	g.edges[applyEdge.EdgeID] = applyEdge

	// REGULATES edge
	regEdge := &Edge{
		Type:     EdgeRegulates,
		FromID:   string(o.RegulatorID),
		FromType: "regulator",
		ToID:     o.ObligationID,
		ToType:   "obligation",
	}
	regEdge.EdgeID = generateEdgeID(regEdge)
	g.edges[regEdge.EdgeID] = regEdge
}

// updateMetrics updates internal metrics.
func (g *Graph) updateMetrics() {
	g.metrics.mu.Lock()
	defer g.metrics.mu.Unlock()

	g.metrics.TotalJurisdictions = len(g.jurisdictions)
	g.metrics.TotalRegulators = len(g.regulators)
	g.metrics.TotalObligations = len(g.obligations)
	g.metrics.TotalEdges = len(g.edges)
	g.metrics.LastUpdated = time.Now()
}

// isExpired checks if an obligation has expired.
func (o *Obligation) isExpired() bool {
	if o.SunsetAt.IsZero() {
		return false
	}
	return time.Now().After(o.SunsetAt)
}

// appliesToEntityType checks if obligation applies to entity type.
// Evaluates SubjectCriteria expressions. Supports:
//   - ""            → applies to all
//   - "*"           → applies to all
//   - "true"        → applies to all
//   - "type == \"X\""  → exact match
//   - "type != \"X\""  → exclusion
//   - "type in [\"X\",\"Y\"]" → set membership
func (o *Obligation) appliesToEntityType(entityType string) bool {
	expr := strings.TrimSpace(o.SubjectCriteria)
	if expr == "" || expr == "*" || expr == "true" {
		return true
	}

	// type == "X"
	if strings.HasPrefix(expr, "type == ") {
		val := strings.Trim(strings.TrimPrefix(expr, "type == "), "\"")
		return entityType == val
	}

	// type != "X"
	if strings.HasPrefix(expr, "type != ") {
		val := strings.Trim(strings.TrimPrefix(expr, "type != "), "\"")
		return entityType != val
	}

	// type in ["X","Y","Z"]
	if strings.HasPrefix(expr, "type in ") {
		setStr := strings.TrimPrefix(expr, "type in ")
		setStr = strings.Trim(setStr, "[] ")
		for _, item := range strings.Split(setStr, ",") {
			item = strings.Trim(strings.TrimSpace(item), "\"")
			if item == entityType {
				return true
			}
		}
		return false
	}

	// Unknown expression → conservative: applies to all
	return true
}

// generateEdgeID creates a deterministic edge ID.
func generateEdgeID(e *Edge) string {
	data := fmt.Sprintf("%s:%s:%s:%s:%s", e.Type, e.FromType, e.FromID, e.ToType, e.ToID)
	h := sha256.Sum256([]byte(data))
	return hex.EncodeToString(h[:])[:16]
}
