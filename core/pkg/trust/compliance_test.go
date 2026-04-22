package trust

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestComplianceMatrix_AddFramework(t *testing.T) {
	matrix := NewComplianceMatrix()

	fw := &Framework{
		FrameworkID: "soc2",
		Name:        "SOC 2 Type II",
		Version:     "2023",
		Authority:   "AICPA",
	}

	matrix.AddFramework(fw)

	assert.Len(t, matrix.Frameworks, 1)
	assert.Equal(t, "SOC 2 Type II", matrix.Frameworks["soc2"].Name)
}

func TestComplianceMatrix_AddControl(t *testing.T) {
	matrix := NewComplianceMatrix()

	matrix.AddFramework(&Framework{FrameworkID: "soc2", Name: "SOC 2"})

	ctrl := &Control{
		ControlID:   "CC6.1",
		FrameworkID: "soc2",
		Title:       "Logical Access Controls",
		Category:    "access",
		Severity:    SeverityHigh,
	}

	err := matrix.AddControl(ctrl)
	require.NoError(t, err)

	assert.Len(t, matrix.Controls, 1)
	assert.Equal(t, ControlNotAssessed, matrix.Controls["CC6.1"].Status)
	assert.Contains(t, matrix.Frameworks["soc2"].ControlIDs, "CC6.1")
}

func TestComplianceMatrix_AddControl_UnknownFramework(t *testing.T) {
	matrix := NewComplianceMatrix()

	ctrl := &Control{
		ControlID:   "TEST",
		FrameworkID: "unknown",
	}

	err := matrix.AddControl(ctrl)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "framework not found")
}

func TestComplianceMatrix_AddEvidence(t *testing.T) {
	matrix := NewComplianceMatrix()

	matrix.AddFramework(&Framework{FrameworkID: "iso27001"})
	_ = matrix.AddControl(&Control{
		ControlID:   "A.9.1",
		FrameworkID: "iso27001",
		Title:       "Access Control Policy",
	})

	evidence := &EvidenceItem{
		ControlID:   "A.9.1",
		Type:        EvidenceDocument,
		Title:       "Access Control Policy Document",
		Description: "Version 2.0 of the policy",
		CollectedBy: "auditor@example.com",
	}

	err := matrix.AddEvidence(evidence)
	require.NoError(t, err)

	assert.Len(t, matrix.Evidence, 1)
	assert.NotEmpty(t, evidence.EvidenceID)
	assert.Contains(t, matrix.Controls["A.9.1"].EvidenceIDs, evidence.EvidenceID)
}

func TestComplianceMatrix_AssessControl(t *testing.T) {
	matrix := NewComplianceMatrix()

	matrix.AddFramework(&Framework{FrameworkID: "pci"})
	_ = matrix.AddControl(&Control{
		ControlID:   "1.1",
		FrameworkID: "pci",
	})

	err := matrix.AssessControl("1.1", ControlCompliant)
	require.NoError(t, err)

	assert.Equal(t, ControlCompliant, matrix.Controls["1.1"].Status)
}

func TestComplianceMatrix_GetFrameworkCompliance(t *testing.T) {
	matrix := NewComplianceMatrix()

	matrix.AddFramework(&Framework{FrameworkID: "gdpr", Name: "GDPR"})

	// Add 4 controls with different statuses
	for i, status := range []ControlStatus{
		ControlCompliant, ControlCompliant, ControlNonCompliant, ControlPartial,
	} {
		ctrl := &Control{
			ControlID:   fmt.Sprintf("art%d", i),
			FrameworkID: "gdpr",
		}
		_ = matrix.AddControl(ctrl)
		_ = matrix.AssessControl(ctrl.ControlID, status)
	}

	compliance, err := matrix.GetFrameworkCompliance("gdpr")
	require.NoError(t, err)

	assert.Equal(t, 4, compliance.TotalControls)
	assert.Equal(t, 2, compliance.CompliantControls)
	assert.Equal(t, 1, compliance.NonCompliantControls)
	assert.Equal(t, 1, compliance.PartialControls)
	assert.Equal(t, 0.5, compliance.ComplianceScore)
}

func TestComplianceMatrix_Hash(t *testing.T) {
	matrix := NewComplianceMatrix()

	matrix.AddFramework(&Framework{FrameworkID: "test"})

	hash1 := matrix.Hash()
	hash2 := matrix.Hash()

	assert.Equal(t, hash1, hash2) // Deterministic
	assert.Len(t, hash1, 64)      // SHA256 hex
}

func TestAdversarialLab_RegisterSuite(t *testing.T) {
	lab := NewAdversarialLab()

	suite := &TestSuite{
		SuiteID:     "injection-tests",
		Name:        "Injection Attack Tests",
		Description: "Tests for SQL, Command, and XSS injection",
		Category:    "security",
		Tests: []TestCase{
			{TestID: "sqli-1", Name: "SQL Injection Basic", Severity: SeverityCritical},
		},
	}

	lab.RegisterSuite(suite)

	suites := lab.GetSuites()
	assert.Len(t, suites, 1)
	assert.Equal(t, "Injection Attack Tests", suites[0].Name)
}

func TestAdversarialLab_RunSuite(t *testing.T) {
	lab := NewAdversarialLab()

	suite := &TestSuite{
		SuiteID: "auth-tests",
		Name:    "Authentication Tests",
		Tests: []TestCase{
			{
				TestID: "auth-1",
				Name:   "Password Policy",
				Runner: func() TestResult {
					return TestResult{Passed: true, Message: "Policy enforced"}
				},
			},
			{
				TestID: "auth-2",
				Name:   "Brute Force Protection",
				Runner: func() TestResult {
					return TestResult{Passed: false, Message: "Rate limiting not detected"}
				},
			},
		},
	}

	lab.RegisterSuite(suite)

	run, err := lab.RunSuite("auth-tests")
	require.NoError(t, err)

	assert.Equal(t, 1, run.PassCount)
	assert.Equal(t, 1, run.FailCount)
	assert.Equal(t, "failed", run.Status)
	assert.Len(t, run.Results, 2)
}

func TestAdversarialLab_RunSuite_NotFound(t *testing.T) {
	lab := NewAdversarialLab()

	_, err := lab.RunSuite("nonexistent")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "suite not found")
}

func TestAdversarialLab_AllTestsPass(t *testing.T) {
	lab := NewAdversarialLab()

	suite := &TestSuite{
		SuiteID: "passing-suite",
		Tests: []TestCase{
			{TestID: "t1", Runner: func() TestResult { return TestResult{Passed: true} }},
			{TestID: "t2", Runner: func() TestResult { return TestResult{Passed: true} }},
		},
	}

	lab.RegisterSuite(suite)

	run, _ := lab.RunSuite("passing-suite")

	assert.Equal(t, "passed", run.Status)
	assert.Equal(t, 2, run.PassCount)
	assert.Equal(t, 0, run.FailCount)
}

func TestComputeTrustScore(t *testing.T) {
	matrix := NewComplianceMatrix()
	lab := NewAdversarialLab()

	// Setup matrix with 50% compliance
	matrix.AddFramework(&Framework{FrameworkID: "test"})
	_ = matrix.AddControl(&Control{ControlID: "c1", FrameworkID: "test"})
	_ = matrix.AddControl(&Control{ControlID: "c2", FrameworkID: "test"})
	_ = matrix.AssessControl("c1", ControlCompliant)
	_ = matrix.AssessControl("c2", ControlNonCompliant)

	// Add evidence to one control
	_ = matrix.AddEvidence(&EvidenceItem{ControlID: "c1", Type: EvidenceDocument})

	// Setup lab with 100% passing tests
	lab.RegisterSuite(&TestSuite{
		SuiteID: "test-suite",
		Tests: []TestCase{
			{TestID: "t1", Runner: func() TestResult { return TestResult{Passed: true} }},
		},
	})
	_, _ = lab.RunSuite("test-suite")

	score := ComputeTrustScore(matrix, lab)

	assert.NotEmpty(t, score.ScoreID)
	assert.Equal(t, 0.5, score.ComplianceScore)
	assert.Equal(t, 1.0, score.SecurityScore)
	assert.Equal(t, 0.5, score.IntegrityScore) // 1/2 controls have evidence

	// Weighted: 0.5*0.4 + 1.0*0.4 + 0.5*0.2 = 0.2 + 0.4 + 0.1 = 0.7
	assert.InDelta(t, 0.7, score.OverallScore, 0.001)
}

func TestTrustScore_EmptyData(t *testing.T) {
	matrix := NewComplianceMatrix()
	lab := NewAdversarialLab()

	score := ComputeTrustScore(matrix, lab)

	assert.Equal(t, 0.0, score.OverallScore)
	assert.Equal(t, 0.0, score.ComplianceScore)
	assert.Equal(t, 0.0, score.SecurityScore)
}
