package intent

import (
	"context"
	"testing"
)

func TestNewStudioNotNil(t *testing.T) {
	s := NewStudio()
	if s == nil {
		t.Fatal("expected non-nil studio")
	}
}

func TestStartSessionReturnsActive(t *testing.T) {
	s := NewStudio()
	sess := s.StartSession(context.Background())
	if sess.Status != "active" {
		t.Fatalf("expected active, got %s", sess.Status)
	}
}

func TestStartSessionHasCards(t *testing.T) {
	s := NewStudio()
	sess := s.StartSession(context.Background())
	if len(sess.Cards) < 4 {
		t.Fatalf("expected >= 4 cards, got %d", len(sess.Cards))
	}
}

func TestStartSessionUniqueIDs(t *testing.T) {
	s := NewStudio()
	s1 := s.StartSession(context.Background())
	s2 := s.StartSession(context.Background())
	if s1.SessionID == s2.SessionID {
		t.Fatal("session IDs should be unique")
	}
}

func TestCaptureDecisionValidOption(t *testing.T) {
	s := NewStudio()
	sess := s.StartSession(context.Background())
	err := s.CaptureDecision(sess, "risk_tolerance", &CardAnswer{SelectedOptions: []string{"low"}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestCaptureDecisionInvalidCard(t *testing.T) {
	s := NewStudio()
	sess := s.StartSession(context.Background())
	err := s.CaptureDecision(sess, "nonexistent", &CardAnswer{})
	if err == nil {
		t.Fatal("expected error for invalid card")
	}
}

func TestCaptureDecisionInvalidOption(t *testing.T) {
	s := NewStudio()
	sess := s.StartSession(context.Background())
	err := s.CaptureDecision(sess, "risk_tolerance", &CardAnswer{SelectedOptions: []string{"extreme"}})
	if err == nil {
		t.Fatal("expected error for invalid option")
	}
}

func TestCaptureDecisionRecordsDiff(t *testing.T) {
	s := NewStudio()
	sess := s.StartSession(context.Background())
	s.CaptureDecision(sess, "risk_tolerance", &CardAnswer{SelectedOptions: []string{"high"}})
	if len(sess.Diffs) != 1 || sess.Diffs[0].ChangeType != "answered" {
		t.Fatal("expected answered diff")
	}
}

func TestCaptureDecisionModifyRecordsDiff(t *testing.T) {
	s := NewStudio()
	sess := s.StartSession(context.Background())
	s.CaptureDecision(sess, "risk_tolerance", &CardAnswer{SelectedOptions: []string{"high"}})
	s.CaptureDecision(sess, "risk_tolerance", &CardAnswer{SelectedOptions: []string{"low"}})
	if len(sess.Diffs) != 2 || sess.Diffs[1].ChangeType != "modified" {
		t.Fatal("expected modified diff")
	}
}

func TestCompileFailsMissingRequired(t *testing.T) {
	s := NewStudio()
	sess := s.StartSession(context.Background())
	_, err := s.Compile(sess)
	if err == nil {
		t.Fatal("expected error for missing required")
	}
}

func TestCompileSuccess(t *testing.T) {
	s := NewStudio()
	sess := s.StartSession(context.Background())
	s.CaptureDecision(sess, "budget", &CardAnswer{StructuredValue: map[string]interface{}{"max_monthly": 1000.0}})
	s.CaptureDecision(sess, "risk_tolerance", &CardAnswer{SelectedOptions: []string{"medium"}})
	s.CaptureDecision(sess, "jurisdiction", &CardAnswer{SelectedOptions: []string{"US"}})
	s.CaptureDecision(sess, "industry", &CardAnswer{SelectedOptions: []string{"saas"}})
	ticket, err := s.Compile(sess)
	if err != nil {
		t.Fatalf("compile failed: %v", err)
	}
	if ticket.Hash == "" {
		t.Fatal("expected hash")
	}
}

func TestCompileSetsStatusCompleted(t *testing.T) {
	s := NewStudio()
	sess := s.StartSession(context.Background())
	s.CaptureDecision(sess, "budget", &CardAnswer{StructuredValue: map[string]interface{}{"max_monthly": 1000.0}})
	s.CaptureDecision(sess, "risk_tolerance", &CardAnswer{SelectedOptions: []string{"high"}})
	s.CaptureDecision(sess, "jurisdiction", &CardAnswer{SelectedOptions: []string{"DE"}})
	s.CaptureDecision(sess, "industry", &CardAnswer{SelectedOptions: []string{"fintech"}})
	s.Compile(sess)
	if sess.Status != "completed" {
		t.Fatalf("expected completed, got %s", sess.Status)
	}
}

func TestCompileExtractsBudgetConstraint(t *testing.T) {
	s := NewStudio()
	sess := s.StartSession(context.Background())
	s.CaptureDecision(sess, "budget", &CardAnswer{StructuredValue: map[string]interface{}{"max_monthly": 5000.0, "currency": "EUR"}})
	s.CaptureDecision(sess, "risk_tolerance", &CardAnswer{SelectedOptions: []string{"medium"}})
	s.CaptureDecision(sess, "jurisdiction", &CardAnswer{SelectedOptions: []string{"US"}})
	s.CaptureDecision(sess, "industry", &CardAnswer{SelectedOptions: []string{"saas"}})
	ticket, _ := s.Compile(sess)
	if ticket.Constraints.Budget == nil || ticket.Constraints.Budget.Currency != "EUR" {
		t.Fatal("expected EUR budget constraint")
	}
}

func TestCompileExtractsRiskLevel(t *testing.T) {
	s := NewStudio()
	sess := s.StartSession(context.Background())
	s.CaptureDecision(sess, "budget", &CardAnswer{StructuredValue: map[string]interface{}{"max_monthly": 100.0}})
	s.CaptureDecision(sess, "risk_tolerance", &CardAnswer{SelectedOptions: []string{"low"}})
	s.CaptureDecision(sess, "jurisdiction", &CardAnswer{SelectedOptions: []string{"US"}})
	s.CaptureDecision(sess, "industry", &CardAnswer{SelectedOptions: []string{"saas"}})
	ticket, _ := s.Compile(sess)
	if ticket.Constraints.Risk == nil || ticket.Constraints.Risk.Level != "low" {
		t.Fatal("expected low risk")
	}
}

func TestCompileApprovalForLowRisk(t *testing.T) {
	s := NewStudio()
	sess := s.StartSession(context.Background())
	s.CaptureDecision(sess, "budget", &CardAnswer{StructuredValue: map[string]interface{}{"max_monthly": 100.0}})
	s.CaptureDecision(sess, "risk_tolerance", &CardAnswer{SelectedOptions: []string{"low"}})
	s.CaptureDecision(sess, "jurisdiction", &CardAnswer{SelectedOptions: []string{"US"}})
	s.CaptureDecision(sess, "industry", &CardAnswer{SelectedOptions: []string{"saas"}})
	ticket, _ := s.Compile(sess)
	if len(ticket.ApprovalRequired) == 0 {
		t.Fatal("low risk should require approvals")
	}
}

func TestValidatorRequiredNilAnswer(t *testing.T) {
	v := NewIntentValidator()
	card := &DecisionCard{Required: true}
	if err := v.ValidateAnswer(card, nil); err == nil {
		t.Fatal("expected error for nil answer on required card")
	}
}

func TestValidatorMinConstraint(t *testing.T) {
	v := NewIntentValidator()
	card := &DecisionCard{Constraints: []Constraint{{Type: "min", Field: "amount", Value: 10, Message: "too low"}}}
	ans := &CardAnswer{StructuredValue: map[string]interface{}{"amount": 5.0}}
	if err := v.ValidateAnswer(card, ans); err == nil {
		t.Fatal("expected min constraint error")
	}
}

func TestValidatorMaxConstraint(t *testing.T) {
	v := NewIntentValidator()
	card := &DecisionCard{Constraints: []Constraint{{Type: "max", Field: "amount", Value: 100, Message: "too high"}}}
	ans := &CardAnswer{StructuredValue: map[string]interface{}{"amount": 200.0}}
	if err := v.ValidateAnswer(card, ans); err == nil {
		t.Fatal("expected max constraint error")
	}
}

func TestGetFloatDefault(t *testing.T) {
	m := map[string]interface{}{}
	if getFloat(m, "missing", 42.0) != 42.0 {
		t.Fatal("expected default")
	}
}

func TestGetStringDefault(t *testing.T) {
	m := map[string]interface{}{}
	if getString(m, "missing", "USD") != "USD" {
		t.Fatal("expected default")
	}
}

func TestToFloatTypes(t *testing.T) {
	if toFloat(3.14) != 3.14 {
		t.Fatal("float64 conversion failed")
	}
	if toFloat(42) != 42.0 {
		t.Fatal("int conversion failed")
	}
	if toFloat("str") != 0 {
		t.Fatal("unsupported type should return 0")
	}
}
