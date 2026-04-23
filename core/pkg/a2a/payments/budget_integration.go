package payments

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/budget"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/crypto/hsm"
	"github.com/google/uuid"
)

// BudgetGate wires AP2 payment requests into the budget enforcement gate.
// It ensures that every agent payment is checked against tenant spend limits
// before being processed. Fail-closed: if budget check fails or returns
// an error, the payment is denied.
type BudgetGate struct {
	mu        sync.Mutex
	enforcer  budget.Enforcer
	verifier  *ReceiptVerifier
	hsm       hsm.Provider
	keyHandle hsm.KeyHandle // Default signing key for receipts

	// idempotency tracks processed idempotency keys to prevent duplicates.
	idempotency map[string]string // idempotencyKey -> receiptID
}

// NewBudgetGate creates a new budget gate for AP2 payments.
func NewBudgetGate(enforcer budget.Enforcer, verifier *ReceiptVerifier, hsmProvider hsm.Provider, keyHandle hsm.KeyHandle) *BudgetGate {
	return &BudgetGate{
		enforcer:    enforcer,
		verifier:    verifier,
		hsm:         hsmProvider,
		keyHandle:   keyHandle,
		idempotency: make(map[string]string),
	}
}

// PaymentResult is the outcome of processing a payment through the budget gate.
type PaymentResult struct {
	Allowed        bool             `json:"allowed"`
	Receipt        *PaymentReceipt  `json:"receipt,omitempty"`
	DenyReason     string           `json:"deny_reason,omitempty"`
	BudgetDecision *budget.Decision `json:"budget_decision,omitempty"`
}

// ProcessPayment validates a payment request against the budget gate,
// creates a signed receipt on success, and records the spend.
//
// Flow:
//  1. Validate request fields
//  2. Check idempotency (return existing receipt if duplicate)
//  3. Check budget limits via budget.Enforcer
//  4. Create and sign payment receipt
//  5. Record spend
//  6. Register receipt with verifier
func (g *BudgetGate) ProcessPayment(ctx context.Context, req *PaymentRequest) (*PaymentResult, error) {
	g.mu.Lock()
	defer g.mu.Unlock()

	// 1. Validate request
	if err := g.validateRequest(req); err != nil {
		return &PaymentResult{
			Allowed:    false,
			DenyReason: err.Error(),
		}, nil
	}

	// 2. Idempotency check
	if existingReceiptID, ok := g.idempotency[req.IdempotencyKey]; ok {
		existing, err := g.verifier.GetReceipt(existingReceiptID)
		if err == nil {
			return &PaymentResult{
				Allowed: true,
				Receipt: existing,
			}, nil
		}
		// If receipt not found despite idempotency entry, continue processing
	}

	// 3. Budget check (fail-closed)
	cost := budget.Cost{
		Amount:   req.AmountCents,
		Currency: req.Currency,
		Reason:   fmt.Sprintf("ap2:%s:%s", req.RequestID, req.Description),
	}

	decision, err := g.enforcer.Check(ctx, req.ToAgentID, cost)
	if err != nil {
		// Fail-closed on error
		return &PaymentResult{
			Allowed:        false,
			DenyReason:     fmt.Sprintf("budget check error: %v", err),
			BudgetDecision: decision,
		}, nil
	}

	if !decision.Allowed {
		return &PaymentResult{
			Allowed:        false,
			DenyReason:     fmt.Sprintf("budget denied: %s", decision.Reason),
			BudgetDecision: decision,
		}, nil
	}

	// 4. Get channel and create receipt
	ch, err := g.verifier.GetChannel(req.ChannelID)
	if err != nil {
		return &PaymentResult{
			Allowed:    false,
			DenyReason: fmt.Sprintf("channel error: %v", err),
		}, nil
	}

	receiptID := uuid.New().String()
	budgetReceiptID := ""
	if decision.Receipt != nil {
		budgetReceiptID = decision.Receipt.ID
	}

	receipt := &PaymentReceipt{
		ReceiptID:       receiptID,
		RequestID:       req.RequestID,
		ChannelID:       req.ChannelID,
		FromAgentID:     req.FromAgentID,
		ToAgentID:       req.ToAgentID,
		AmountCents:     req.AmountCents,
		Currency:        req.Currency,
		Status:          PaymentStatusCompleted,
		Method:          req.Method,
		SequenceNum:     ch.NextSequence(),
		RequestHash:     req.Hash(),
		IssuedAt:        time.Now(),
		BudgetReceiptID: budgetReceiptID,
	}

	// 5. Sign receipt
	if err := g.verifier.SignReceipt(ctx, receipt, g.keyHandle); err != nil {
		return &PaymentResult{
			Allowed:    false,
			DenyReason: fmt.Sprintf("receipt signing failed: %v", err),
		}, nil
	}

	// 6. Record spend
	if err := g.enforcer.RecordSpend(ctx, req.ToAgentID, cost); err != nil {
		// Log but don't fail - budget was already reserved in Check()
		_ = err
	}

	// 7. Store in verifier (outside verifier lock scope since we hold our own lock)
	g.verifier.mu.Lock()
	g.verifier.receipts[receipt.ReceiptID] = receipt

	// Update channel state
	ch.LastActivityAt = time.Now()
	if receipt.FromAgentID == ch.AgentA {
		ch.BalanceCentsA += receipt.AmountCents
		ch.TotalVolumeB += receipt.AmountCents
	} else {
		ch.BalanceCentsB += receipt.AmountCents
		ch.TotalVolumeA += receipt.AmountCents
	}
	g.verifier.mu.Unlock()

	// 8. Record idempotency
	if req.IdempotencyKey != "" {
		g.idempotency[req.IdempotencyKey] = receipt.ReceiptID
	}

	return &PaymentResult{
		Allowed:        true,
		Receipt:        receipt,
		BudgetDecision: decision,
	}, nil
}

// validateRequest performs basic field validation on a payment request.
func (g *BudgetGate) validateRequest(req *PaymentRequest) error {
	if req == nil {
		return fmt.Errorf("request is nil")
	}
	if req.RequestID == "" {
		return fmt.Errorf("request_id is required")
	}
	if req.FromAgentID == "" {
		return fmt.Errorf("from_agent_id is required")
	}
	if req.ToAgentID == "" {
		return fmt.Errorf("to_agent_id is required")
	}
	if req.ChannelID == "" {
		return fmt.Errorf("channel_id is required")
	}
	if req.AmountCents <= 0 {
		return fmt.Errorf("amount_cents must be positive")
	}
	if req.Currency == "" {
		return fmt.Errorf("currency is required")
	}
	if !req.ExpiresAt.IsZero() && time.Now().After(req.ExpiresAt) {
		return fmt.Errorf("request has expired")
	}
	return nil
}

// GetSpendSummary returns the current budget state for an agent.
func (g *BudgetGate) GetSpendSummary(ctx context.Context, agentID string) (*budget.Budget, error) {
	return g.enforcer.GetBudget(ctx, agentID)
}

// SetAgentLimits configures budget limits for an agent.
func (g *BudgetGate) SetAgentLimits(ctx context.Context, agentID string, dailyCents, monthlyCents int64) error {
	return g.enforcer.SetLimits(ctx, agentID, dailyCents, monthlyCents)
}
