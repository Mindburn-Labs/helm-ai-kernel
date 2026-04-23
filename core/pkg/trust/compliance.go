// Package trust provides trust infrastructure for HELM.
// Per Section 6 - compliance evidence, adversarial testing, and trust scoring.
package trust

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/google/uuid"
)

// ComplianceMatrix tracks compliance evidence across frameworks.
type ComplianceMatrix struct {
	MatrixID   string                   `json:"matrix_id"`
	CreatedAt  time.Time                `json:"created_at"`
	UpdatedAt  time.Time                `json:"updated_at"`
	Frameworks map[string]*Framework    `json:"frameworks"`
	Controls   map[string]*Control      `json:"controls"`
	Evidence   map[string]*EvidenceItem `json:"evidence"`
	mu         sync.RWMutex
}

// NewComplianceMatrix creates a new compliance matrix.
func NewComplianceMatrix() *ComplianceMatrix {
	return &ComplianceMatrix{
		MatrixID:   uuid.New().String(),
		CreatedAt:  time.Now(),
		UpdatedAt:  time.Now(),
		Frameworks: make(map[string]*Framework),
		Controls:   make(map[string]*Control),
		Evidence:   make(map[string]*EvidenceItem),
	}
}

// Framework represents a compliance framework.
type Framework struct {
	FrameworkID string    `json:"framework_id"`
	Name        string    `json:"name"`
	Version     string    `json:"version"`
	Description string    `json:"description"`
	Authority   string    `json:"authority"`
	ControlIDs  []string  `json:"control_ids"`
	CreatedAt   time.Time `json:"created_at"`
}

// Control is a compliance control requirement.
type Control struct {
	ControlID   string        `json:"control_id"`
	FrameworkID string        `json:"framework_id"`
	Title       string        `json:"title"`
	Description string        `json:"description"`
	Category    string        `json:"category"`
	Severity    Severity      `json:"severity"`
	Status      ControlStatus `json:"status"`
	EvidenceIDs []string      `json:"evidence_ids"`
	LastChecked time.Time     `json:"last_checked"`
}

// Severity levels for controls.
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
)

// ControlStatus represents control compliance status.
type ControlStatus string

const (
	ControlCompliant    ControlStatus = "compliant"
	ControlNonCompliant ControlStatus = "non_compliant"
	ControlPartial      ControlStatus = "partial"
	ControlNotAssessed  ControlStatus = "not_assessed"
)

// EvidenceItem is a piece of compliance evidence.
type EvidenceItem struct {
	EvidenceID   string                 `json:"evidence_id"`
	ControlID    string                 `json:"control_id"`
	Type         EvidenceType           `json:"type"`
	Title        string                 `json:"title"`
	Description  string                 `json:"description"`
	ArtifactHash string                 `json:"artifact_hash"`
	CollectedAt  time.Time              `json:"collected_at"`
	CollectedBy  string                 `json:"collected_by"`
	Verified     bool                   `json:"verified"`
	Metadata     map[string]interface{} `json:"metadata,omitempty"`
}

// EvidenceType categorizes evidence.
type EvidenceType string

const (
	EvidenceDocument    EvidenceType = "document"
	EvidenceLog         EvidenceType = "log"
	EvidenceScreenshot  EvidenceType = "screenshot"
	EvidenceTestResult  EvidenceType = "test_result"
	EvidenceConfig      EvidenceType = "config"
	EvidenceAttestation EvidenceType = "attestation"
)

// AddFramework adds a compliance framework.
func (m *ComplianceMatrix) AddFramework(fw *Framework) {
	m.mu.Lock()
	defer m.mu.Unlock()

	fw.CreatedAt = time.Now()
	m.Frameworks[fw.FrameworkID] = fw
	m.UpdatedAt = time.Now()
}

// AddControl adds a control to a framework.
func (m *ComplianceMatrix) AddControl(ctrl *Control) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, ok := m.Frameworks[ctrl.FrameworkID]; !ok {
		return fmt.Errorf("framework not found: %s", ctrl.FrameworkID)
	}

	ctrl.Status = ControlNotAssessed
	ctrl.LastChecked = time.Now()
	m.Controls[ctrl.ControlID] = ctrl

	// Link to framework
	m.Frameworks[ctrl.FrameworkID].ControlIDs = append(
		m.Frameworks[ctrl.FrameworkID].ControlIDs,
		ctrl.ControlID,
	)

	m.UpdatedAt = time.Now()
	return nil
}

// AddEvidence adds evidence for a control.
func (m *ComplianceMatrix) AddEvidence(evidence *EvidenceItem) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	ctrl, ok := m.Controls[evidence.ControlID]
	if !ok {
		return fmt.Errorf("control not found: %s", evidence.ControlID)
	}

	evidence.EvidenceID = uuid.New().String()
	evidence.CollectedAt = time.Now()
	m.Evidence[evidence.EvidenceID] = evidence

	// Link to control
	ctrl.EvidenceIDs = append(ctrl.EvidenceIDs, evidence.EvidenceID)

	m.UpdatedAt = time.Now()
	return nil
}

// AssessControl updates the compliance status of a control.
func (m *ComplianceMatrix) AssessControl(controlID string, status ControlStatus) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	ctrl, ok := m.Controls[controlID]
	if !ok {
		return fmt.Errorf("control not found: %s", controlID)
	}

	ctrl.Status = status
	ctrl.LastChecked = time.Now()
	m.UpdatedAt = time.Now()

	return nil
}

// GetFrameworkCompliance calculates compliance for a framework.
func (m *ComplianceMatrix) GetFrameworkCompliance(frameworkID string) (*FrameworkCompliance, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	fw, ok := m.Frameworks[frameworkID]
	if !ok {
		return nil, fmt.Errorf("framework not found: %s", frameworkID)
	}

	result := &FrameworkCompliance{
		FrameworkID:   frameworkID,
		FrameworkName: fw.Name,
		TotalControls: len(fw.ControlIDs),
	}

	for _, ctrlID := range fw.ControlIDs {
		ctrl := m.Controls[ctrlID]
		switch ctrl.Status {
		case ControlCompliant:
			result.CompliantControls++
		case ControlNonCompliant:
			result.NonCompliantControls++
		case ControlPartial:
			result.PartialControls++
		default:
			result.NotAssessedControls++
		}
	}

	if result.TotalControls > 0 {
		result.ComplianceScore = float64(result.CompliantControls) / float64(result.TotalControls)
	}

	return result, nil
}

// FrameworkCompliance is the compliance status of a framework.
type FrameworkCompliance struct {
	FrameworkID          string  `json:"framework_id"`
	FrameworkName        string  `json:"framework_name"`
	TotalControls        int     `json:"total_controls"`
	CompliantControls    int     `json:"compliant_controls"`
	NonCompliantControls int     `json:"non_compliant_controls"`
	PartialControls      int     `json:"partial_controls"`
	NotAssessedControls  int     `json:"not_assessed_controls"`
	ComplianceScore      float64 `json:"compliance_score"`
}

// Hash computes a deterministic hash of the matrix state.
func (m *ComplianceMatrix) Hash() string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Sort framework IDs for determinism
	fwIDs := make([]string, 0, len(m.Frameworks))
	for id := range m.Frameworks {
		fwIDs = append(fwIDs, id)
	}
	sort.Strings(fwIDs)

	data, _ := json.Marshal(map[string]interface{}{
		"matrix_id":  m.MatrixID,
		"frameworks": fwIDs,
		"controls":   len(m.Controls),
		"evidence":   len(m.Evidence),
	})

	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

// AdversarialLab runs security test suites.
type AdversarialLab struct {
	LabID      string       `json:"lab_id"`
	TestSuites []*TestSuite `json:"test_suites"`
	Results    []TestRun    `json:"results"`
	mu         sync.RWMutex
}

// NewAdversarialLab creates a new adversarial lab.
func NewAdversarialLab() *AdversarialLab {
	return &AdversarialLab{
		LabID:      uuid.New().String(),
		TestSuites: []*TestSuite{},
		Results:    []TestRun{},
	}
}

// TestSuite is a collection of security tests.
type TestSuite struct {
	SuiteID     string     `json:"suite_id"`
	Name        string     `json:"name"`
	Description string     `json:"description"`
	Category    string     `json:"category"`
	Tests       []TestCase `json:"tests"`
}

// TestCase is an individual security test.
type TestCase struct {
	TestID      string     `json:"test_id"`
	Name        string     `json:"name"`
	Description string     `json:"description"`
	Severity    Severity   `json:"severity"`
	Runner      TestRunner `json:"-"`
}

// TestRunner executes a test case.
type TestRunner func() TestResult

// TestResult is the outcome of a test.
type TestResult struct {
	Passed   bool          `json:"passed"`
	Message  string        `json:"message"`
	Duration time.Duration `json:"duration"`
	Evidence string        `json:"evidence,omitempty"`
}

// TestRun records a test suite execution.
type TestRun struct {
	RunID       string                `json:"run_id"`
	SuiteID     string                `json:"suite_id"`
	StartedAt   time.Time             `json:"started_at"`
	CompletedAt time.Time             `json:"completed_at"`
	Results     map[string]TestResult `json:"results"`
	PassCount   int                   `json:"pass_count"`
	FailCount   int                   `json:"fail_count"`
	Status      string                `json:"status"`
}

// RegisterSuite adds a test suite.
func (l *AdversarialLab) RegisterSuite(suite *TestSuite) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.TestSuites = append(l.TestSuites, suite)
}

// RunSuite executes all tests in a suite.
func (l *AdversarialLab) RunSuite(suiteID string) (*TestRun, error) {
	l.mu.Lock()

	var suite *TestSuite
	for _, s := range l.TestSuites {
		if s.SuiteID == suiteID {
			suite = s
			break
		}
	}

	if suite == nil {
		l.mu.Unlock()
		return nil, fmt.Errorf("suite not found: %s", suiteID)
	}

	l.mu.Unlock()

	run := &TestRun{
		RunID:     uuid.New().String(),
		SuiteID:   suiteID,
		StartedAt: time.Now(),
		Results:   make(map[string]TestResult),
	}

	for _, test := range suite.Tests {
		if test.Runner == nil {
			run.Results[test.TestID] = TestResult{
				Passed:  true,
				Message: "No runner (skipped)",
			}
			run.PassCount++
			continue
		}

		result := test.Runner()
		run.Results[test.TestID] = result

		if result.Passed {
			run.PassCount++
		} else {
			run.FailCount++
		}
	}

	run.CompletedAt = time.Now()
	if run.FailCount == 0 {
		run.Status = "passed"
	} else {
		run.Status = "failed"
	}

	l.mu.Lock()
	l.Results = append(l.Results, *run)
	l.mu.Unlock()

	return run, nil
}

// GetSuites returns all registered suites.
func (l *AdversarialLab) GetSuites() []*TestSuite {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.TestSuites
}

// TrustScore computes an overall trust score.
type TrustScore struct {
	ScoreID         string             `json:"score_id"`
	ComputedAt      time.Time          `json:"computed_at"`
	OverallScore    float64            `json:"overall_score"`
	ComplianceScore float64            `json:"compliance_score"`
	SecurityScore   float64            `json:"security_score"`
	IntegrityScore  float64            `json:"integrity_score"`
	PackScore       float64            `json:"pack_score"`
	Breakdown       map[string]float64 `json:"breakdown"`
}

// ComputeTrustScore calculates an overall trust score for an organization/system.
func ComputeTrustScore(matrix *ComplianceMatrix, lab *AdversarialLab) *TrustScore {
	score := &TrustScore{
		ScoreID:    uuid.New().String(),
		ComputedAt: time.Now(),
		Breakdown:  make(map[string]float64),
	}

	// Compliance component (40%)
	totalCompliant := 0
	totalControls := 0
	for _, ctrl := range matrix.Controls {
		totalControls++
		if ctrl.Status == ControlCompliant {
			totalCompliant++
		}
	}
	if totalControls > 0 {
		score.ComplianceScore = float64(totalCompliant) / float64(totalControls)
	}
	score.Breakdown["compliance"] = score.ComplianceScore

	// Security tests component (40%)
	totalPassed := 0
	totalTests := 0
	for _, run := range lab.Results {
		totalPassed += run.PassCount
		totalTests += run.PassCount + run.FailCount
	}
	if totalTests > 0 {
		score.SecurityScore = float64(totalPassed) / float64(totalTests)
	}
	score.Breakdown["security"] = score.SecurityScore

	// Integrity component (20%) - evidence coverage
	totalEvidence := len(matrix.Evidence)
	controlsWithEvidence := 0
	for _, ctrl := range matrix.Controls {
		if len(ctrl.EvidenceIDs) > 0 {
			controlsWithEvidence++
		}
	}
	if totalControls > 0 {
		score.IntegrityScore = float64(controlsWithEvidence) / float64(totalControls)
	}
	score.Breakdown["integrity"] = score.IntegrityScore
	score.Breakdown["evidence_count"] = float64(totalEvidence)

	// Weighted overall
	score.OverallScore = score.ComplianceScore*0.4 + score.SecurityScore*0.4 + score.IntegrityScore*0.2

	return score
}

// PackMetrics represents inputs for pack trust scoring.
type PackMetrics struct {
	AttestationCompleteness float64 `json:"attestation_completeness"` // 0-1
	ReplayDeterminism       float64 `json:"replay_determinism"`       // 0-1
	InjectionResilience     float64 `json:"injection_resilience"`     // 0-1
	SLOAdherence            float64 `json:"slo_adherence"`            // 0-1
}

// ComputePackTrustScore calculates a trust score for a specific pack.
func ComputePackTrustScore(metrics PackMetrics) *TrustScore {
	score := &TrustScore{
		ScoreID:    uuid.New().String(),
		ComputedAt: time.Now(),
		Breakdown:  make(map[string]float64),
	}

	// Pack Score Calculation
	// Weights:
	// - Attestation: 30%
	// - Determinism: 30%
	// - Security (Injection): 20%
	// - Reliability (SLO): 20%

	score.PackScore = metrics.AttestationCompleteness*0.3 +
		metrics.ReplayDeterminism*0.3 +
		metrics.InjectionResilience*0.2 +
		metrics.SLOAdherence*0.2

	score.OverallScore = score.PackScore
	score.Breakdown["pack_score"] = score.PackScore
	score.Breakdown["attestation"] = metrics.AttestationCompleteness
	score.Breakdown["determinism"] = metrics.ReplayDeterminism
	score.Breakdown["injection"] = metrics.InjectionResilience
	score.Breakdown["slo"] = metrics.SLOAdherence

	return score
}
