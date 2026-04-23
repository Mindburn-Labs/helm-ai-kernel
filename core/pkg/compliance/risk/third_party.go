// Package risk provides automated third-party risk assessment for compliance.
package risk

import (
	"context"
	cryptoRand "crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"sync"
	"time"
)

// RiskLevel represents the severity of a risk.
type RiskLevel int

const (
	RiskLevelLow RiskLevel = iota + 1
	RiskLevelMedium
	RiskLevelHigh
	RiskLevelCritical
)

func (r RiskLevel) String() string {
	names := map[RiskLevel]string{
		RiskLevelLow:      "LOW",
		RiskLevelMedium:   "MEDIUM",
		RiskLevelHigh:     "HIGH",
		RiskLevelCritical: "CRITICAL",
	}
	if name, ok := names[r]; ok {
		return name
	}
	return "UNKNOWN"
}

// ThirdParty represents an external vendor or service provider.
type ThirdParty struct {
	ID               string            `json:"id"`
	Name             string            `json:"name"`
	Type             ThirdPartyType    `json:"type"`
	Description      string            `json:"description"`
	ContractStart    time.Time         `json:"contract_start"`
	ContractEnd      *time.Time        `json:"contract_end,omitempty"`
	DataAccess       []DataCategory    `json:"data_access"`
	Certifications   []string          `json:"certifications"`
	Jurisdiction     string            `json:"jurisdiction"`
	CriticalityLevel RiskLevel         `json:"criticality_level"`
	LastAssessment   *time.Time        `json:"last_assessment,omitempty"`
	RiskScore        float64           `json:"risk_score"`
	Metadata         map[string]string `json:"metadata,omitempty"`
}

// ThirdPartyType categorizes the third party.
type ThirdPartyType string

const (
	TypeCloudProvider   ThirdPartyType = "CLOUD_PROVIDER"
	TypeSaaSVendor      ThirdPartyType = "SAAS_VENDOR"
	TypePaymentProvider ThirdPartyType = "PAYMENT_PROVIDER"
	TypeDataProcessor   ThirdPartyType = "DATA_PROCESSOR"
	TypeAuditFirm       ThirdPartyType = "AUDIT_FIRM"
	TypeConsultant      ThirdPartyType = "CONSULTANT"
	TypeSubcontractor   ThirdPartyType = "SUBCONTRACTOR"
)

// DataCategory represents types of data accessed.
type DataCategory string

const (
	DataPersonal    DataCategory = "PERSONAL_DATA"
	DataFinancial   DataCategory = "FINANCIAL_DATA"
	DataHealth      DataCategory = "HEALTH_DATA"
	DataCredentials DataCategory = "CREDENTIALS"
	DataProprietary DataCategory = "PROPRIETARY"
	DataPublic      DataCategory = "PUBLIC"
)

// RiskAssessment represents a point-in-time risk evaluation.
type RiskAssessment struct {
	ID              string         `json:"id"`
	ThirdPartyID    string         `json:"third_party_id"`
	AssessedAt      time.Time      `json:"assessed_at"`
	Assessor        string         `json:"assessor"`
	OverallScore    float64        `json:"overall_score"`
	RiskLevel       RiskLevel      `json:"risk_level"`
	Findings        []Finding      `json:"findings"`
	Mitigations     []Mitigation   `json:"mitigations"`
	NextReviewDate  time.Time      `json:"next_review_date"`
	ApprovalStatus  ApprovalStatus `json:"approval_status"`
	ComplianceFlags []string       `json:"compliance_flags"`
}

// Finding represents a discovered risk or issue.
type Finding struct {
	ID          string     `json:"id"`
	Category    string     `json:"category"`
	Title       string     `json:"title"`
	Description string     `json:"description"`
	RiskLevel   RiskLevel  `json:"risk_level"`
	Evidence    string     `json:"evidence,omitempty"`
	Remediation string     `json:"remediation"`
	DueDate     *time.Time `json:"due_date,omitempty"`
	Status      string     `json:"status"`
}

// Mitigation represents a risk mitigation control.
type Mitigation struct {
	ID            string    `json:"id"`
	FindingID     string    `json:"finding_id"`
	Description   string    `json:"description"`
	ControlType   string    `json:"control_type"` // PREVENTIVE, DETECTIVE, CORRECTIVE
	ImplementedAt time.Time `json:"implemented_at"`
	Effectiveness float64   `json:"effectiveness"` // 0.0 - 1.0
	Owner         string    `json:"owner"`
}

// ApprovalStatus represents the approval state.
type ApprovalStatus string

const (
	ApprovalPending  ApprovalStatus = "PENDING"
	ApprovalApproved ApprovalStatus = "APPROVED"
	ApprovalRejected ApprovalStatus = "REJECTED"
	ApprovalExpired  ApprovalStatus = "EXPIRED"
)

// ThirdPartyRiskAssessor provides automated risk assessment.
type ThirdPartyRiskAssessor struct {
	thirdParties map[string]*ThirdParty
	assessments  map[string][]*RiskAssessment
	rules        []AssessmentRule
	config       AssessorConfig
	mu           sync.RWMutex
}

// AssessorConfig configures the risk assessor.
type AssessorConfig struct {
	DefaultReviewPeriod    time.Duration
	CriticalReviewPeriod   time.Duration
	AutoApprovalThreshold  float64 // Score below which auto-approval is allowed
	RequiredCertifications []string
	BlockedJurisdictions   []string
	MaxDataCategories      int
}

// DefaultAssessorConfig returns sensible defaults.
func DefaultAssessorConfig() AssessorConfig {
	return AssessorConfig{
		DefaultReviewPeriod:    365 * 24 * time.Hour, // 1 year
		CriticalReviewPeriod:   90 * 24 * time.Hour,  // 90 days
		AutoApprovalThreshold:  3.0,
		RequiredCertifications: []string{"SOC2", "ISO27001"},
		BlockedJurisdictions:   []string{},
		MaxDataCategories:      3,
	}
}

// AssessmentRule defines an automated assessment rule.
type AssessmentRule struct {
	Name        string
	Description string
	Category    string
	Evaluate    func(*ThirdParty) *Finding
}

// NewThirdPartyRiskAssessor creates a new risk assessor.
func NewThirdPartyRiskAssessor(config AssessorConfig) *ThirdPartyRiskAssessor {
	assessor := &ThirdPartyRiskAssessor{
		thirdParties: make(map[string]*ThirdParty),
		assessments:  make(map[string][]*RiskAssessment),
		config:       config,
	}
	assessor.registerDefaultRules()
	return assessor
}

// registerDefaultRules adds built-in assessment rules.
//
//nolint:gocognit // complexity acceptable
func (a *ThirdPartyRiskAssessor) registerDefaultRules() {
	a.rules = []AssessmentRule{
		{
			Name:        "DataAccessCheck",
			Description: "Verify data access is appropriate",
			Category:    "DATA_GOVERNANCE",
			Evaluate: func(tp *ThirdParty) *Finding {
				if len(tp.DataAccess) > a.config.MaxDataCategories {
					return &Finding{
						ID:       generateFindingID(),
						Category: "DATA_GOVERNANCE",
						Title:    "Excessive Data Access",
						Description: fmt.Sprintf("Third party has access to %d data categories, exceeding limit of %d",
							len(tp.DataAccess), a.config.MaxDataCategories),
						RiskLevel:   RiskLevelMedium,
						Remediation: "Review and minimize data access scope",
						Status:      "OPEN",
					}
				}
				return nil
			},
		},
		{
			Name:        "CertificationCheck",
			Description: "Verify required certifications",
			Category:    "COMPLIANCE",
			Evaluate: func(tp *ThirdParty) *Finding {
				missing := make([]string, 0)
				for _, required := range a.config.RequiredCertifications {
					found := false
					for _, cert := range tp.Certifications {
						if cert == required {
							found = true
							break
						}
					}
					if !found {
						missing = append(missing, required)
					}
				}
				if len(missing) > 0 {
					return &Finding{
						ID:          generateFindingID(),
						Category:    "COMPLIANCE",
						Title:       "Missing Certifications",
						Description: fmt.Sprintf("Third party is missing required certifications: %v", missing),
						RiskLevel:   RiskLevelHigh,
						Remediation: "Request certification evidence or select alternative vendor",
						Status:      "OPEN",
					}
				}
				return nil
			},
		},
		{
			Name:        "JurisdictionCheck",
			Description: "Verify jurisdiction is allowed",
			Category:    "COMPLIANCE",
			Evaluate: func(tp *ThirdParty) *Finding {
				for _, blocked := range a.config.BlockedJurisdictions {
					if tp.Jurisdiction == blocked {
						return &Finding{
							ID:          generateFindingID(),
							Category:    "COMPLIANCE",
							Title:       "Blocked Jurisdiction",
							Description: fmt.Sprintf("Third party operates in blocked jurisdiction: %s", tp.Jurisdiction),
							RiskLevel:   RiskLevelCritical,
							Remediation: "Terminate relationship or obtain regulatory exemption",
							Status:      "OPEN",
						}
					}
				}
				return nil
			},
		},
		{
			Name:        "ContractValidityCheck",
			Description: "Verify contract is valid",
			Category:    "CONTRACT",
			Evaluate: func(tp *ThirdParty) *Finding {
				if tp.ContractEnd != nil && tp.ContractEnd.Before(time.Now()) {
					return &Finding{
						ID:          generateFindingID(),
						Category:    "CONTRACT",
						Title:       "Expired Contract",
						Description: "Contract has expired, third party relationship may be unregulated",
						RiskLevel:   RiskLevelHigh,
						Remediation: "Renew contract or terminate relationship",
						Status:      "OPEN",
					}
				}
				if tp.ContractEnd != nil && tp.ContractEnd.Before(time.Now().Add(30*24*time.Hour)) {
					return &Finding{
						ID:          generateFindingID(),
						Category:    "CONTRACT",
						Title:       "Contract Expiring Soon",
						Description: "Contract expires within 30 days",
						RiskLevel:   RiskLevelMedium,
						Remediation: "Initiate contract renewal process",
						Status:      "OPEN",
					}
				}
				return nil
			},
		},
		{
			Name:        "SensitiveDataCheck",
			Description: "Check for sensitive data access",
			Category:    "DATA_GOVERNANCE",
			Evaluate: func(tp *ThirdParty) *Finding {
				sensitiveData := []DataCategory{DataPersonal, DataFinancial, DataHealth, DataCredentials}
				for _, access := range tp.DataAccess {
					for _, sensitive := range sensitiveData {
						if access == sensitive {
							return &Finding{
								ID:          generateFindingID(),
								Category:    "DATA_GOVERNANCE",
								Title:       "Sensitive Data Access",
								Description: fmt.Sprintf("Third party has access to sensitive data category: %s", access),
								RiskLevel:   RiskLevelHigh,
								Remediation: "Ensure appropriate data protection agreements and controls",
								Status:      "OPEN",
							}
						}
					}
				}
				return nil
			},
		},
	}
}

// RegisterThirdParty registers a new third party for assessment.
func (a *ThirdPartyRiskAssessor) RegisterThirdParty(tp *ThirdParty) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if tp.ID == "" {
		tp.ID = generateThirdPartyID(tp.Name)
	}

	a.thirdParties[tp.ID] = tp
	return nil
}

// AssessThirdParty performs an automated risk assessment.
func (a *ThirdPartyRiskAssessor) AssessThirdParty(ctx context.Context, thirdPartyID, assessor string) (*RiskAssessment, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	tp, exists := a.thirdParties[thirdPartyID]
	if !exists {
		return nil, fmt.Errorf("third party not found: %s", thirdPartyID)
	}

	// Run all assessment rules
	findings := make([]Finding, 0)
	for _, rule := range a.rules {
		if finding := rule.Evaluate(tp); finding != nil {
			findings = append(findings, *finding)
		}
	}

	// Calculate overall score (higher = more risky)
	score := a.calculateRiskScore(findings, tp.CriticalityLevel)

	// Determine risk level
	riskLevel := a.scoreToRiskLevel(score)

	// Calculate next review date
	reviewPeriod := a.config.DefaultReviewPeriod
	if riskLevel >= RiskLevelHigh {
		reviewPeriod = a.config.CriticalReviewPeriod
	}

	assessment := &RiskAssessment{
		ID:             generateAssessmentID(),
		ThirdPartyID:   thirdPartyID,
		AssessedAt:     time.Now(),
		Assessor:       assessor,
		OverallScore:   score,
		RiskLevel:      riskLevel,
		Findings:       findings,
		Mitigations:    make([]Mitigation, 0),
		NextReviewDate: time.Now().Add(reviewPeriod),
		ApprovalStatus: ApprovalPending,
	}

	// Auto-approve if below threshold and no critical findings
	if score <= a.config.AutoApprovalThreshold && !hasCriticalFindings(findings) {
		assessment.ApprovalStatus = ApprovalApproved
	}

	// Store assessment
	if a.assessments[thirdPartyID] == nil {
		a.assessments[thirdPartyID] = make([]*RiskAssessment, 0)
	}
	a.assessments[thirdPartyID] = append(a.assessments[thirdPartyID], assessment)

	// Update third party
	now := time.Now()
	tp.LastAssessment = &now
	tp.RiskScore = score

	return assessment, nil
}

// GetAssessmentHistory returns assessment history for a third party.
func (a *ThirdPartyRiskAssessor) GetAssessmentHistory(thirdPartyID string) ([]*RiskAssessment, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	assessments, exists := a.assessments[thirdPartyID]
	if !exists {
		return nil, fmt.Errorf("no assessments found for: %s", thirdPartyID)
	}

	return assessments, nil
}

// GetDueAssessments returns third parties due for reassessment.
func (a *ThirdPartyRiskAssessor) GetDueAssessments() []*ThirdParty {
	a.mu.RLock()
	defer a.mu.RUnlock()

	var due []*ThirdParty
	now := time.Now()

	for _, tp := range a.thirdParties {
		assessments := a.assessments[tp.ID]
		if len(assessments) == 0 {
			due = append(due, tp)
			continue
		}

		latest := assessments[len(assessments)-1]
		if now.After(latest.NextReviewDate) {
			due = append(due, tp)
		}
	}

	return due
}

// GenerateRiskReport generates a comprehensive risk report.
func (a *ThirdPartyRiskAssessor) GenerateRiskReport() (*RiskReport, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	report := &RiskReport{
		GeneratedAt:       time.Now(),
		TotalThirdParties: len(a.thirdParties),
		RiskDistribution:  make(map[string]int),
		HighRiskVendors:   make([]*ThirdParty, 0),
		OpenFindings:      0,
		OverdueReviews:    0,
	}

	for _, tp := range a.thirdParties {
		// Risk distribution
		level := a.scoreToRiskLevel(tp.RiskScore)
		report.RiskDistribution[level.String()]++

		// High risk vendors
		if level >= RiskLevelHigh {
			report.HighRiskVendors = append(report.HighRiskVendors, tp)
		}

		// Count open findings
		if assessments := a.assessments[tp.ID]; len(assessments) > 0 {
			latest := assessments[len(assessments)-1]
			for _, finding := range latest.Findings {
				if finding.Status == "OPEN" {
					report.OpenFindings++
				}
			}

			// Check overdue reviews
			if time.Now().After(latest.NextReviewDate) {
				report.OverdueReviews++
			}
		}
	}

	// Sort high risk vendors by score
	sort.Slice(report.HighRiskVendors, func(i, j int) bool {
		return report.HighRiskVendors[i].RiskScore > report.HighRiskVendors[j].RiskScore
	})

	return report, nil
}

// RiskReport provides a summary of third-party risks.
type RiskReport struct {
	GeneratedAt       time.Time      `json:"generated_at"`
	TotalThirdParties int            `json:"total_third_parties"`
	RiskDistribution  map[string]int `json:"risk_distribution"`
	HighRiskVendors   []*ThirdParty  `json:"high_risk_vendors"`
	OpenFindings      int            `json:"open_findings"`
	OverdueReviews    int            `json:"overdue_reviews"`
}

// ToJSON exports the report as JSON.
func (r *RiskReport) ToJSON() ([]byte, error) {
	return json.MarshalIndent(r, "", "  ")
}

// ===== Helper Functions =====

func (a *ThirdPartyRiskAssessor) calculateRiskScore(findings []Finding, criticality RiskLevel) float64 {
	if len(findings) == 0 {
		return 1.0 // Base score
	}

	score := 1.0
	for _, finding := range findings {
		switch finding.RiskLevel {
		case RiskLevelCritical:
			score += 4.0
		case RiskLevelHigh:
			score += 2.0
		case RiskLevelMedium:
			score += 1.0
		case RiskLevelLow:
			score += 0.5
		}
	}

	// Apply criticality multiplier
	multiplier := 1.0
	switch criticality {
	case RiskLevelCritical:
		multiplier = 2.0
	case RiskLevelHigh:
		multiplier = 1.5
	case RiskLevelMedium:
		multiplier = 1.2
	}

	return score * multiplier
}

func (a *ThirdPartyRiskAssessor) scoreToRiskLevel(score float64) RiskLevel {
	switch {
	case score >= 8.0:
		return RiskLevelCritical
	case score >= 5.0:
		return RiskLevelHigh
	case score >= 3.0:
		return RiskLevelMedium
	default:
		return RiskLevelLow
	}
}

func hasCriticalFindings(findings []Finding) bool {
	for _, f := range findings {
		if f.RiskLevel == RiskLevelCritical {
			return true
		}
	}
	return false
}

func generateThirdPartyID(name string) string {
	hash := sha256.Sum256([]byte(name + time.Now().String()))
	return "TP-" + hex.EncodeToString(hash[:8])
}

func generateAssessmentID() string {
	randomBytes := make([]byte, 16)
	if _, err := cryptoRand.Read(randomBytes); err != nil {
		hash := sha256.Sum256([]byte(time.Now().String()))
		return "RA-" + hex.EncodeToString(hash[:8])
	}
	hash := sha256.Sum256(randomBytes)
	return "RA-" + hex.EncodeToString(hash[:8])
}

func generateFindingID() string {
	randomBytes := make([]byte, 16)
	if _, err := cryptoRand.Read(randomBytes); err != nil {
		hash := sha256.Sum256([]byte(time.Now().String()))
		return "FND-" + hex.EncodeToString(hash[:6])
	}
	hash := sha256.Sum256(randomBytes)
	return "FND-" + hex.EncodeToString(hash[:6])
}
