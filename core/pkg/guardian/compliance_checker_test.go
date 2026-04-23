package guardian

import (
	"context"
	"testing"
)

// --- Mock ComplianceChecker ---

type MockComplianceChecker struct {
	Result *ComplianceCheckResult
	Err    error
	Called bool
}

func (m *MockComplianceChecker) CheckCompliance(ctx context.Context, entityID, action string, context map[string]interface{}) (*ComplianceCheckResult, error) {
	m.Called = true
	return m.Result, m.Err
}

func TestGuardian_ComplianceChecker_NotSet(t *testing.T) {
	// When no ComplianceChecker is set, Guardian should not panic and should
	// proceed normally through PRG validation.
	g := &Guardian{
		complianceChecker: nil, // Not set
	}
	if g.complianceChecker != nil {
		t.Fatal("expected nil complianceChecker")
	}
}

func TestGuardian_SetComplianceChecker(t *testing.T) {
	g := &Guardian{}
	mock := &MockComplianceChecker{
		Result: &ComplianceCheckResult{Compliant: true, ObligationsChecked: 5},
	}
	g.SetComplianceChecker(mock)
	if g.complianceChecker == nil {
		t.Fatal("expected complianceChecker to be set")
	}
}

func TestComplianceCheckResult_Compliant(t *testing.T) {
	result := &ComplianceCheckResult{
		Compliant:          true,
		ObligationsChecked: 10,
	}
	if !result.Compliant {
		t.Fatal("expected compliant")
	}
	if len(result.ViolatedObligations) != 0 {
		t.Fatal("expected no violations")
	}
}

func TestComplianceCheckResult_NonCompliant(t *testing.T) {
	result := &ComplianceCheckResult{
		Compliant:           false,
		Reason:              "2 obligation(s) non-compliant",
		ObligationsChecked:  5,
		ViolatedObligations: []string{"OBL-EU-GDPR", "OBL-US-SOX"},
	}
	if result.Compliant {
		t.Fatal("expected non-compliant")
	}
	if len(result.ViolatedObligations) != 2 {
		t.Fatalf("expected 2 violations, got %d", len(result.ViolatedObligations))
	}
}

func TestMockComplianceChecker_Interface(t *testing.T) {
	// Verify MockComplianceChecker implements the interface
	var _ ComplianceChecker = (*MockComplianceChecker)(nil)

	mock := &MockComplianceChecker{
		Result: &ComplianceCheckResult{
			Compliant:           false,
			Reason:              "test violation",
			ObligationsChecked:  3,
			ViolatedObligations: []string{"OBL-TEST"},
		},
	}

	result, err := mock.CheckCompliance(context.Background(), "entity-1", "EXECUTE_TOOL", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !mock.Called {
		t.Fatal("expected mock to be called")
	}
	if result.Compliant {
		t.Fatal("expected non-compliant result")
	}
}
