package payments

import (
	"context"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/budget"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto/hsm"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- Test helpers ---

func setupHSM(t *testing.T) (hsm.Provider, hsm.KeyHandle) {
	t.Helper()
	provider := hsm.NewSoftwareProvider()
	ctx := context.Background()
	require.NoError(t, provider.Open(ctx))

	handle, err := provider.GenerateKey(ctx, hsm.KeyGenOpts{
		Algorithm: hsm.AlgorithmEd25519,
		Label:     "test-ap2",
		Usage:     hsm.KeyUsageSign | hsm.KeyUsageVerify,
	})
	require.NoError(t, err)
	return provider, handle
}

func setupChannel() *PaymentChannel {
	return &PaymentChannel{
		ChannelID:      "ch-001",
		AgentA:         "agent-alice",
		AgentB:         "agent-bob",
		Method:         PaymentMethodBudget,
		Currency:       "USD",
		SpendLimitA:    100000, // $1000
		SpendLimitB:    100000,
		IsOpen:         true,
		OpenedAt:       time.Now(),
		LastActivityAt: time.Now(),
	}
}

func setupRequest() *PaymentRequest {
	return &PaymentRequest{
		RequestID:      "req-001",
		FromAgentID:    "agent-alice",
		ToAgentID:      "agent-bob",
		ChannelID:      "ch-001",
		AmountCents:    500, // $5.00
		Currency:       "USD",
		Description:    "test payment",
		Method:         PaymentMethodBudget,
		IdempotencyKey: "idem-001",
		CreatedAt:      time.Now(),
		ExpiresAt:      time.Now().Add(1 * time.Hour),
	}
}

// --- Type tests ---

func TestPaymentRequest_Hash_Deterministic(t *testing.T) {
	req := setupRequest()
	h1 := req.Hash()
	h2 := req.Hash()
	assert.Equal(t, h1, h2, "hash must be deterministic")
	assert.Contains(t, h1, "sha256:")
}

func TestPaymentRequest_Hash_DiffersOnChange(t *testing.T) {
	req1 := setupRequest()
	h1 := req1.Hash()

	req2 := setupRequest()
	req2.AmountCents = 999
	h2 := req2.Hash()

	assert.NotEqual(t, h1, h2, "different amounts must produce different hashes")
}

func TestPaymentReceipt_SignableContent(t *testing.T) {
	receipt := &PaymentReceipt{
		ReceiptID:   "rcpt-001",
		RequestID:   "req-001",
		ChannelID:   "ch-001",
		FromAgentID: "agent-alice",
		ToAgentID:   "agent-bob",
		AmountCents: 500,
		Currency:    "USD",
		Status:      PaymentStatusCompleted,
		SequenceNum: 1,
		RequestHash: "sha256:abc",
	}

	content := receipt.SignableContent()
	assert.NotEmpty(t, content)

	// Must be deterministic
	assert.Equal(t, content, receipt.SignableContent())
}

func TestPaymentReceipt_Hash(t *testing.T) {
	receipt := &PaymentReceipt{
		ReceiptID:   "rcpt-001",
		RequestID:   "req-001",
		AmountCents: 500,
	}
	h := receipt.Hash()
	assert.Contains(t, h, "sha256:")
	assert.Equal(t, h, receipt.Hash(), "hash must be deterministic")
}

func TestPaymentChannel_NextSequence(t *testing.T) {
	ch := setupChannel()
	assert.Equal(t, int64(0), ch.SequenceNum)

	s1 := ch.NextSequence()
	assert.Equal(t, int64(1), s1)

	s2 := ch.NextSequence()
	assert.Equal(t, int64(2), s2)
}

func TestPaymentChannel_NetBalance(t *testing.T) {
	ch := setupChannel()
	ch.BalanceCentsA = 1000
	ch.BalanceCentsB = 300
	assert.Equal(t, int64(700), ch.NetBalance())
}

func TestPaymentChannel_Summarize(t *testing.T) {
	ch := setupChannel()
	ch.BalanceCentsA = 500
	ch.TotalVolumeA = 1000
	ch.TotalVolumeB = 2000
	ch.SequenceNum = 5

	summary := ch.Summarize()
	assert.Equal(t, "ch-001", summary.ChannelID)
	assert.Equal(t, int64(500), summary.NetBalance)
	assert.Equal(t, int64(5), summary.SequenceNum)
	assert.Equal(t, int64(3000), summary.TotalVolume)
	assert.True(t, summary.IsOpen)
}

// --- Verifier tests ---

func TestVerifier_SignAndVerifyReceipt(t *testing.T) {
	hsmProvider, keyHandle := setupHSM(t)
	ctx := context.Background()

	verifier := NewReceiptVerifier(hsmProvider)
	ch := setupChannel()
	require.NoError(t, verifier.RegisterChannel(ch))

	req := setupRequest()
	require.NoError(t, verifier.RegisterRequest(req))

	receipt := &PaymentReceipt{
		ReceiptID:   "rcpt-001",
		RequestID:   "req-001",
		ChannelID:   "ch-001",
		FromAgentID: "agent-alice",
		ToAgentID:   "agent-bob",
		AmountCents: 500,
		Currency:    "USD",
		Status:      PaymentStatusCompleted,
		SequenceNum: 1,
		RequestHash: req.Hash(),
		IssuedAt:    time.Now(),
	}

	// Sign
	require.NoError(t, verifier.SignReceipt(ctx, receipt, keyHandle))
	assert.NotEmpty(t, receipt.SignatureVal)
	assert.NotEmpty(t, receipt.SignatureKID)

	// Verify
	require.NoError(t, verifier.VerifyReceipt(ctx, receipt))
}

func TestVerifier_RejectUnsignedReceipt(t *testing.T) {
	hsmProvider, _ := setupHSM(t)
	ctx := context.Background()

	verifier := NewReceiptVerifier(hsmProvider)
	ch := setupChannel()
	require.NoError(t, verifier.RegisterChannel(ch))

	receipt := &PaymentReceipt{
		ReceiptID:   "rcpt-001",
		RequestID:   "req-001",
		ChannelID:   "ch-001",
		FromAgentID: "agent-alice",
		ToAgentID:   "agent-bob",
		AmountCents: 500,
		Currency:    "USD",
		SequenceNum: 1,
		// No signature
	}

	err := verifier.VerifyReceipt(ctx, receipt)
	assert.ErrorIs(t, err, ErrReceiptSignatureInvalid)
}

func TestVerifier_RejectDuplicateReceipt(t *testing.T) {
	hsmProvider, keyHandle := setupHSM(t)
	ctx := context.Background()

	verifier := NewReceiptVerifier(hsmProvider)
	ch := setupChannel()
	require.NoError(t, verifier.RegisterChannel(ch))

	receipt := &PaymentReceipt{
		ReceiptID:   "rcpt-001",
		RequestID:   "req-001",
		ChannelID:   "ch-001",
		FromAgentID: "agent-alice",
		ToAgentID:   "agent-bob",
		AmountCents: 500,
		Currency:    "USD",
		SequenceNum: 1,
	}

	require.NoError(t, verifier.SignReceipt(ctx, receipt, keyHandle))
	require.NoError(t, verifier.VerifyReceipt(ctx, receipt))

	// Second verify with same ID should fail
	receipt2 := &PaymentReceipt{
		ReceiptID:   "rcpt-001", // same ID
		RequestID:   "req-002",
		ChannelID:   "ch-001",
		FromAgentID: "agent-alice",
		ToAgentID:   "agent-bob",
		AmountCents: 300,
		Currency:    "USD",
		SequenceNum: 2,
	}
	require.NoError(t, verifier.SignReceipt(ctx, receipt2, keyHandle))
	err := verifier.VerifyReceipt(ctx, receipt2)
	assert.ErrorIs(t, err, ErrDuplicateReceipt)
}

func TestVerifier_RejectClosedChannel(t *testing.T) {
	hsmProvider, keyHandle := setupHSM(t)
	ctx := context.Background()

	verifier := NewReceiptVerifier(hsmProvider)
	ch := setupChannel()
	ch.IsOpen = false
	require.NoError(t, verifier.RegisterChannel(ch))

	receipt := &PaymentReceipt{
		ReceiptID:   "rcpt-001",
		ChannelID:   "ch-001",
		FromAgentID: "agent-alice",
		ToAgentID:   "agent-bob",
		AmountCents: 500,
		Currency:    "USD",
		SequenceNum: 1,
	}
	require.NoError(t, verifier.SignReceipt(ctx, receipt, keyHandle))

	err := verifier.VerifyReceipt(ctx, receipt)
	assert.ErrorIs(t, err, ErrChannelClosed)
}

func TestVerifier_RejectSequenceRegression(t *testing.T) {
	hsmProvider, keyHandle := setupHSM(t)
	ctx := context.Background()

	verifier := NewReceiptVerifier(hsmProvider)
	ch := setupChannel()
	ch.SequenceNum = 5 // Already at 5
	require.NoError(t, verifier.RegisterChannel(ch))

	receipt := &PaymentReceipt{
		ReceiptID:   "rcpt-001",
		ChannelID:   "ch-001",
		FromAgentID: "agent-alice",
		ToAgentID:   "agent-bob",
		AmountCents: 500,
		Currency:    "USD",
		SequenceNum: 3, // Regression!
	}
	require.NoError(t, verifier.SignReceipt(ctx, receipt, keyHandle))

	err := verifier.VerifyReceipt(ctx, receipt)
	assert.ErrorIs(t, err, ErrSequenceRegression)
}

func TestVerifier_RejectAgentMismatch(t *testing.T) {
	hsmProvider, keyHandle := setupHSM(t)
	ctx := context.Background()

	verifier := NewReceiptVerifier(hsmProvider)
	ch := setupChannel()
	require.NoError(t, verifier.RegisterChannel(ch))

	receipt := &PaymentReceipt{
		ReceiptID:   "rcpt-001",
		ChannelID:   "ch-001",
		FromAgentID: "agent-charlie", // Not in channel
		ToAgentID:   "agent-bob",
		AmountCents: 500,
		Currency:    "USD",
		SequenceNum: 1,
	}
	require.NoError(t, verifier.SignReceipt(ctx, receipt, keyHandle))

	err := verifier.VerifyReceipt(ctx, receipt)
	assert.ErrorIs(t, err, ErrAgentMismatch)
}

func TestVerifier_RejectAmountMismatch(t *testing.T) {
	hsmProvider, keyHandle := setupHSM(t)
	ctx := context.Background()

	verifier := NewReceiptVerifier(hsmProvider)
	ch := setupChannel()
	require.NoError(t, verifier.RegisterChannel(ch))

	req := setupRequest()
	req.AmountCents = 500
	require.NoError(t, verifier.RegisterRequest(req))

	receipt := &PaymentReceipt{
		ReceiptID:   "rcpt-001",
		RequestID:   "req-001",
		ChannelID:   "ch-001",
		FromAgentID: "agent-alice",
		ToAgentID:   "agent-bob",
		AmountCents: 999, // Mismatch!
		Currency:    "USD",
		SequenceNum: 1,
		RequestHash: req.Hash(),
	}
	require.NoError(t, verifier.SignReceipt(ctx, receipt, keyHandle))

	err := verifier.VerifyReceipt(ctx, receipt)
	assert.ErrorIs(t, err, ErrAmountMismatch)
}

func TestVerifier_RejectInvalidAmount(t *testing.T) {
	hsmProvider, _ := setupHSM(t)
	verifier := NewReceiptVerifier(hsmProvider)

	req := setupRequest()
	req.AmountCents = -100
	err := verifier.RegisterRequest(req)
	assert.ErrorIs(t, err, ErrInvalidAmount)
}

// --- Dispute tests ---

func TestVerifier_FileAndResolveDispute(t *testing.T) {
	hsmProvider, keyHandle := setupHSM(t)
	ctx := context.Background()

	verifier := NewReceiptVerifier(hsmProvider)
	ch := setupChannel()
	require.NoError(t, verifier.RegisterChannel(ch))

	// Create and verify a receipt first
	receipt := &PaymentReceipt{
		ReceiptID:   "rcpt-001",
		ChannelID:   "ch-001",
		FromAgentID: "agent-alice",
		ToAgentID:   "agent-bob",
		AmountCents: 500,
		Currency:    "USD",
		SequenceNum: 1,
	}
	require.NoError(t, verifier.SignReceipt(ctx, receipt, keyHandle))
	require.NoError(t, verifier.VerifyReceipt(ctx, receipt))

	// File dispute
	dispute := &PaymentDispute{
		DisputeID:   "disp-001",
		ReceiptID:   "rcpt-001",
		ChannelID:   "ch-001",
		DisputerID:  "agent-bob",
		Reason:      DisputeServiceNotRendered,
		Description: "Service was not rendered",
	}
	require.NoError(t, verifier.FileDispute(dispute))

	// Verify dispute is stored
	stored, err := verifier.GetDispute("disp-001")
	require.NoError(t, err)
	assert.Equal(t, DisputeStatusOpen, stored.Status)

	// Resolve
	require.NoError(t, verifier.ResolveDispute("disp-001", DisputeStatusResolved, "Refund issued"))

	resolved, err := verifier.GetDispute("disp-001")
	require.NoError(t, err)
	assert.Equal(t, DisputeStatusResolved, resolved.Status)
	assert.Equal(t, "Refund issued", resolved.Resolution)
	assert.NotNil(t, resolved.ResolvedAt)
}

func TestVerifier_DisputeNonExistentReceipt(t *testing.T) {
	hsmProvider, _ := setupHSM(t)
	verifier := NewReceiptVerifier(hsmProvider)

	dispute := &PaymentDispute{
		DisputeID:  "disp-001",
		ReceiptID:  "nonexistent",
		DisputerID: "agent-bob",
		Reason:     DisputeUnauthorized,
	}
	err := verifier.FileDispute(dispute)
	assert.ErrorIs(t, err, ErrDisputeReceiptNotFound)
}

// --- Budget integration tests ---

// testBudgetEnforcer is a minimal budget.Enforcer for testing.
type testBudgetEnforcer struct {
	budgets map[string]*budget.Budget
	spends  map[string]int64
}

func newTestBudgetEnforcer() *testBudgetEnforcer {
	return &testBudgetEnforcer{
		budgets: make(map[string]*budget.Budget),
		spends:  make(map[string]int64),
	}
}

func (e *testBudgetEnforcer) SetLimits(_ context.Context, tenantID string, daily, monthly int64) error {
	e.budgets[tenantID] = &budget.Budget{
		TenantID:     tenantID,
		DailyLimit:   daily,
		MonthlyLimit: monthly,
		LastUpdated:  time.Now(),
	}
	return nil
}

func (e *testBudgetEnforcer) GetBudget(_ context.Context, tenantID string) (*budget.Budget, error) {
	if b, ok := e.budgets[tenantID]; ok {
		return b, nil
	}
	return nil, nil
}

func (e *testBudgetEnforcer) Check(_ context.Context, tenantID string, cost budget.Cost) (*budget.Decision, error) {
	b, ok := e.budgets[tenantID]
	if !ok {
		return &budget.Decision{
			Allowed: false,
			Reason:  "no budget configured",
			Receipt: &budget.EnforcementReceipt{
				ID:        "budget-deny-" + tenantID,
				TenantID:  tenantID,
				Action:    "denied",
				CostCents: cost.Amount,
				Reason:    "no_budget",
				Timestamp: time.Now(),
			},
		}, nil
	}

	if b.DailyUsed+cost.Amount > b.DailyLimit {
		return &budget.Decision{
			Allowed:   false,
			Reason:    "daily limit exceeded",
			Remaining: b,
		}, nil
	}

	b.DailyUsed += cost.Amount
	b.MonthlyUsed += cost.Amount

	return &budget.Decision{
		Allowed:   true,
		Reason:    "within limits",
		Remaining: b,
		Receipt: &budget.EnforcementReceipt{
			ID:        "budget-allow-" + tenantID,
			TenantID:  tenantID,
			Action:    "allowed",
			CostCents: cost.Amount,
			Reason:    "ok",
			Timestamp: time.Now(),
		},
	}, nil
}

func (e *testBudgetEnforcer) RecordSpend(_ context.Context, tenantID string, cost budget.Cost) error {
	e.spends[tenantID] += cost.Amount
	return nil
}

func TestBudgetGate_ProcessPayment_Success(t *testing.T) {
	hsmProvider, keyHandle := setupHSM(t)
	ctx := context.Background()

	enforcer := newTestBudgetEnforcer()
	require.NoError(t, enforcer.SetLimits(ctx, "agent-bob", 100000, 1000000))

	verifier := NewReceiptVerifier(hsmProvider)
	ch := setupChannel()
	require.NoError(t, verifier.RegisterChannel(ch))

	gate := NewBudgetGate(enforcer, verifier, hsmProvider, keyHandle)

	req := setupRequest()
	result, err := gate.ProcessPayment(ctx, req)
	require.NoError(t, err)
	assert.True(t, result.Allowed)
	assert.NotNil(t, result.Receipt)
	assert.Equal(t, PaymentStatusCompleted, result.Receipt.Status)
	assert.NotEmpty(t, result.Receipt.SignatureVal)
	assert.NotEmpty(t, result.Receipt.BudgetReceiptID)
}

func TestBudgetGate_ProcessPayment_BudgetDenied(t *testing.T) {
	hsmProvider, keyHandle := setupHSM(t)
	ctx := context.Background()

	enforcer := newTestBudgetEnforcer()
	// Set very low budget: $1/day
	require.NoError(t, enforcer.SetLimits(ctx, "agent-bob", 100, 10000))

	verifier := NewReceiptVerifier(hsmProvider)
	ch := setupChannel()
	require.NoError(t, verifier.RegisterChannel(ch))

	gate := NewBudgetGate(enforcer, verifier, hsmProvider, keyHandle)

	req := setupRequest()
	req.AmountCents = 500 // $5 exceeds $1 limit
	result, err := gate.ProcessPayment(ctx, req)
	require.NoError(t, err)
	assert.False(t, result.Allowed)
	assert.Contains(t, result.DenyReason, "budget denied")
}

func TestBudgetGate_ProcessPayment_NoBudget_FailClosed(t *testing.T) {
	hsmProvider, keyHandle := setupHSM(t)
	ctx := context.Background()

	enforcer := newTestBudgetEnforcer()
	// No budget set for agent-bob => fail closed

	verifier := NewReceiptVerifier(hsmProvider)
	ch := setupChannel()
	require.NoError(t, verifier.RegisterChannel(ch))

	gate := NewBudgetGate(enforcer, verifier, hsmProvider, keyHandle)

	req := setupRequest()
	result, err := gate.ProcessPayment(ctx, req)
	require.NoError(t, err)
	assert.False(t, result.Allowed)
	assert.Contains(t, result.DenyReason, "budget denied")
}

func TestBudgetGate_ProcessPayment_Idempotency(t *testing.T) {
	hsmProvider, keyHandle := setupHSM(t)
	ctx := context.Background()

	enforcer := newTestBudgetEnforcer()
	require.NoError(t, enforcer.SetLimits(ctx, "agent-bob", 100000, 1000000))

	verifier := NewReceiptVerifier(hsmProvider)
	ch := setupChannel()
	require.NoError(t, verifier.RegisterChannel(ch))

	gate := NewBudgetGate(enforcer, verifier, hsmProvider, keyHandle)

	req := setupRequest()

	// First call
	result1, err := gate.ProcessPayment(ctx, req)
	require.NoError(t, err)
	assert.True(t, result1.Allowed)

	// Second call with same idempotency key
	result2, err := gate.ProcessPayment(ctx, req)
	require.NoError(t, err)
	assert.True(t, result2.Allowed)
	assert.Equal(t, result1.Receipt.ReceiptID, result2.Receipt.ReceiptID, "idempotent calls must return same receipt")
}

func TestBudgetGate_ProcessPayment_InvalidRequest(t *testing.T) {
	hsmProvider, keyHandle := setupHSM(t)
	ctx := context.Background()

	enforcer := newTestBudgetEnforcer()
	verifier := NewReceiptVerifier(hsmProvider)
	gate := NewBudgetGate(enforcer, verifier, hsmProvider, keyHandle)

	tests := []struct {
		name string
		mod  func(*PaymentRequest)
	}{
		{"empty_request_id", func(r *PaymentRequest) { r.RequestID = "" }},
		{"empty_from_agent", func(r *PaymentRequest) { r.FromAgentID = "" }},
		{"empty_to_agent", func(r *PaymentRequest) { r.ToAgentID = "" }},
		{"empty_channel", func(r *PaymentRequest) { r.ChannelID = "" }},
		{"zero_amount", func(r *PaymentRequest) { r.AmountCents = 0 }},
		{"negative_amount", func(r *PaymentRequest) { r.AmountCents = -100 }},
		{"empty_currency", func(r *PaymentRequest) { r.Currency = "" }},
		{"expired_request", func(r *PaymentRequest) { r.ExpiresAt = time.Now().Add(-1 * time.Hour) }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := setupRequest()
			tt.mod(req)
			result, err := gate.ProcessPayment(ctx, req)
			require.NoError(t, err)
			assert.False(t, result.Allowed)
		})
	}
}

func TestBudgetGate_ProcessPayment_NilRequest(t *testing.T) {
	hsmProvider, keyHandle := setupHSM(t)
	ctx := context.Background()

	enforcer := newTestBudgetEnforcer()
	verifier := NewReceiptVerifier(hsmProvider)
	gate := NewBudgetGate(enforcer, verifier, hsmProvider, keyHandle)

	result, err := gate.ProcessPayment(ctx, nil)
	require.NoError(t, err)
	assert.False(t, result.Allowed)
}

func TestBudgetGate_SetAndGetLimits(t *testing.T) {
	hsmProvider, keyHandle := setupHSM(t)
	ctx := context.Background()

	enforcer := newTestBudgetEnforcer()
	verifier := NewReceiptVerifier(hsmProvider)
	gate := NewBudgetGate(enforcer, verifier, hsmProvider, keyHandle)

	require.NoError(t, gate.SetAgentLimits(ctx, "agent-bob", 50000, 500000))

	b, err := gate.GetSpendSummary(ctx, "agent-bob")
	require.NoError(t, err)
	assert.NotNil(t, b)
	assert.Equal(t, int64(50000), b.DailyLimit)
	assert.Equal(t, int64(500000), b.MonthlyLimit)
}
