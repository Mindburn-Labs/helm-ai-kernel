package intent

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStudio_StartSession(t *testing.T) {
	studio := NewStudio()
	session := studio.StartSession(context.Background())

	assert.NotEmpty(t, session.SessionID)
	assert.Equal(t, "active", session.Status)
	assert.GreaterOrEqual(t, len(session.Cards), 4, "Should have at least 4 decision cards")
}

func TestStudio_CaptureDecision(t *testing.T) {
	studio := NewStudio()
	session := studio.StartSession(context.Background())

	t.Run("Valid answer is captured", func(t *testing.T) {
		answer := &CardAnswer{
			SelectedOptions: []string{"medium"},
		}
		err := studio.CaptureDecision(session, "risk_tolerance", answer)
		require.NoError(t, err)

		assert.NotNil(t, session.Decisions["risk_tolerance"])
		assert.Len(t, session.Diffs, 1)
		assert.Equal(t, "answered", session.Diffs[0].ChangeType)
	})

	t.Run("Invalid card ID fails", func(t *testing.T) {
		answer := &CardAnswer{SelectedOptions: []string{"test"}}
		err := studio.CaptureDecision(session, "nonexistent", answer)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "card not found")
	})

	t.Run("Invalid option fails", func(t *testing.T) {
		answer := &CardAnswer{SelectedOptions: []string{"invalid_risk_level"}}
		err := studio.CaptureDecision(session, "risk_tolerance", answer)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid option")
	})
}

func TestStudio_Compile(t *testing.T) {
	studio := NewStudio()
	session := studio.StartSession(context.Background())

	// Answer all required cards
	err := studio.CaptureDecision(session, "budget", &CardAnswer{
		StructuredValue: map[string]interface{}{
			"max_monthly":    5000.0,
			"max_per_effect": 500.0,
			"currency":       "USD",
		},
	})
	require.NoError(t, err)

	err = studio.CaptureDecision(session, "risk_tolerance", &CardAnswer{
		SelectedOptions: []string{"medium"},
	})
	require.NoError(t, err)

	err = studio.CaptureDecision(session, "jurisdiction", &CardAnswer{
		SelectedOptions: []string{"US"},
	})
	require.NoError(t, err)

	err = studio.CaptureDecision(session, "industry", &CardAnswer{
		SelectedOptions: []string{"fintech"},
	})
	require.NoError(t, err)

	t.Run("Compiles successfully with all required answers", func(t *testing.T) {
		ticket, err := studio.Compile(session)
		require.NoError(t, err)

		assert.NotEmpty(t, ticket.TicketID)
		assert.Equal(t, "1.0.0", ticket.Version)
		assert.Equal(t, session.SessionID, ticket.SessionID)
		assert.NotEmpty(t, ticket.Hash)

		// Verify constraints extracted
		assert.NotNil(t, ticket.Constraints.Budget)
		assert.Equal(t, 5000.0, ticket.Constraints.Budget.MaxMonthly)
		assert.Equal(t, "USD", ticket.Constraints.Budget.Currency)

		assert.NotNil(t, ticket.Constraints.Risk)
		assert.Equal(t, "medium", ticket.Constraints.Risk.Level)

		// Verify context extracted
		assert.Equal(t, "US", ticket.Context.Jurisdiction)
		assert.Equal(t, "fintech", ticket.Context.Industry)

		// Session should be completed
		assert.Equal(t, "completed", session.Status)
	})
}

func TestStudio_Compile_FailsWithMissingRequired(t *testing.T) {
	studio := NewStudio()
	session := studio.StartSession(context.Background())

	// Only answer one required card
	err := studio.CaptureDecision(session, "risk_tolerance", &CardAnswer{
		SelectedOptions: []string{"low"},
	})
	require.NoError(t, err)

	_, err = studio.Compile(session)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "required card not answered")
}

func TestIntentTicket_HashDeterminism(t *testing.T) {
	studio := NewStudio()

	// Create two sessions with identical answers
	makeSession := func() *IntentSession {
		session := studio.StartSession(context.Background())
		session.SessionID = "fixed-session-id" // Fix for determinism test

		_ = studio.CaptureDecision(session, "budget", &CardAnswer{
			StructuredValue: map[string]interface{}{
				"max_monthly": 1000.0,
				"currency":    "EUR",
			},
		})
		_ = studio.CaptureDecision(session, "risk_tolerance", &CardAnswer{
			SelectedOptions: []string{"high"},
		})
		_ = studio.CaptureDecision(session, "jurisdiction", &CardAnswer{
			SelectedOptions: []string{"DE"},
		})
		_ = studio.CaptureDecision(session, "industry", &CardAnswer{
			SelectedOptions: []string{"saas"},
		})
		return session
	}

	session1 := makeSession()
	session2 := makeSession()

	ticket1, err := studio.Compile(session1)
	require.NoError(t, err)

	ticket2, err := studio.Compile(session2)
	require.NoError(t, err)

	// Fix ticket IDs for comparison
	ticket1.TicketID = "fixed"
	ticket2.TicketID = "fixed"

	// Recompute hashes
	hash1, _ := studio.computeHash(ticket1)
	hash2, _ := studio.computeHash(ticket2)

	assert.Equal(t, hash1, hash2, "Same inputs must produce same hash")
}

func TestIntentValidator(t *testing.T) {
	validator := NewIntentValidator()

	t.Run("Validates required answer", func(t *testing.T) {
		card := &DecisionCard{Required: true}
		err := validator.ValidateAnswer(card, nil)
		assert.Error(t, err)
	})

	t.Run("Validates min constraint", func(t *testing.T) {
		card := &DecisionCard{
			Constraints: []Constraint{
				{Type: "min", Field: "amount", Value: 10.0, Message: "Too small"},
			},
		}
		answer := &CardAnswer{
			StructuredValue: map[string]interface{}{"amount": 5.0},
		}
		err := validator.ValidateAnswer(card, answer)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "Too small")
	})
}
