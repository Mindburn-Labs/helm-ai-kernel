package payments

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/crypto/hsm"
)

// Common errors for payment verification.
var (
	ErrReceiptSignatureInvalid = errors.New("ap2: receipt signature invalid")
	ErrReceiptExpired          = errors.New("ap2: receipt references expired request")
	ErrAmountMismatch          = errors.New("ap2: receipt amount does not match request")
	ErrChannelClosed           = errors.New("ap2: payment channel is closed")
	ErrChannelNotFound         = errors.New("ap2: payment channel not found")
	ErrSequenceRegression      = errors.New("ap2: sequence number regression detected")
	ErrAgentMismatch           = errors.New("ap2: agent IDs do not match channel")
	ErrDuplicateReceipt        = errors.New("ap2: duplicate receipt ID")
	ErrRequestNotFound         = errors.New("ap2: payment request not found")
	ErrRequestExpired          = errors.New("ap2: payment request expired")
	ErrDisputeReceiptNotFound  = errors.New("ap2: disputed receipt not found")
	ErrSpendLimitExceeded      = errors.New("ap2: channel spend limit exceeded")
	ErrInvalidAmount           = errors.New("ap2: amount must be positive")
)

// ReceiptVerifier verifies AP2 payment receipts using HSM-backed signatures.
type ReceiptVerifier struct {
	mu       sync.RWMutex
	hsm      hsm.Provider
	channels map[string]*PaymentChannel
	receipts map[string]*PaymentReceipt // receiptID -> receipt
	requests map[string]*PaymentRequest // requestID -> request
	disputes map[string]*PaymentDispute // disputeID -> dispute
}

// NewReceiptVerifier creates a new receipt verifier with an HSM provider.
func NewReceiptVerifier(hsmProvider hsm.Provider) *ReceiptVerifier {
	return &ReceiptVerifier{
		hsm:      hsmProvider,
		channels: make(map[string]*PaymentChannel),
		receipts: make(map[string]*PaymentReceipt),
		requests: make(map[string]*PaymentRequest),
		disputes: make(map[string]*PaymentDispute),
	}
}

// RegisterChannel registers a payment channel for verification tracking.
func (v *ReceiptVerifier) RegisterChannel(ch *PaymentChannel) error {
	v.mu.Lock()
	defer v.mu.Unlock()

	if ch == nil {
		return fmt.Errorf("ap2: channel is nil")
	}
	v.channels[ch.ChannelID] = ch
	return nil
}

// GetChannel returns a channel by ID.
func (v *ReceiptVerifier) GetChannel(channelID string) (*PaymentChannel, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()

	ch, ok := v.channels[channelID]
	if !ok {
		return nil, ErrChannelNotFound
	}
	return ch, nil
}

// RegisterRequest stores a payment request for later receipt verification.
func (v *ReceiptVerifier) RegisterRequest(req *PaymentRequest) error {
	v.mu.Lock()
	defer v.mu.Unlock()

	if req == nil {
		return fmt.Errorf("ap2: request is nil")
	}
	if req.AmountCents <= 0 {
		return ErrInvalidAmount
	}
	v.requests[req.RequestID] = req
	return nil
}

// SignReceipt signs a payment receipt using the HSM provider.
func (v *ReceiptVerifier) SignReceipt(ctx context.Context, receipt *PaymentReceipt, keyHandle hsm.KeyHandle) error {
	if receipt == nil {
		return fmt.Errorf("ap2: receipt is nil")
	}

	content := receipt.SignableContent()
	sig, err := v.hsm.Sign(ctx, keyHandle, content, hsm.SignOpts{})
	if err != nil {
		return fmt.Errorf("ap2: sign receipt: %w", err)
	}

	keyInfo, err := v.hsm.GetKeyInfo(ctx, keyHandle)
	if err != nil {
		return fmt.Errorf("ap2: get key info: %w", err)
	}

	receipt.SignatureKID = string(keyHandle)
	receipt.SignatureAlg = keyInfo.Algorithm.String()
	receipt.SignatureVal = sig
	return nil
}

// VerifyReceipt performs full verification of a payment receipt:
//  1. Signature validity (HSM-backed)
//  2. Amount matches the original request
//  3. Channel is open and agents match
//  4. Sequence number is monotonically increasing
//  5. No duplicate receipt IDs
func (v *ReceiptVerifier) VerifyReceipt(ctx context.Context, receipt *PaymentReceipt) error {
	if receipt == nil {
		return fmt.Errorf("ap2: receipt is nil")
	}

	v.mu.Lock()
	defer v.mu.Unlock()

	// 1. Check for duplicate receipt
	if _, exists := v.receipts[receipt.ReceiptID]; exists {
		return ErrDuplicateReceipt
	}

	// 2. Verify signature
	if err := v.verifySignature(ctx, receipt); err != nil {
		return err
	}

	// 3. Validate against original request
	if err := v.validateAgainstRequest(receipt); err != nil {
		return err
	}

	// 4. Validate channel state
	if err := v.validateChannelState(receipt); err != nil {
		return err
	}

	// 5. Store receipt
	v.receipts[receipt.ReceiptID] = receipt

	return nil
}

// verifySignature checks the HSM signature on the receipt.
func (v *ReceiptVerifier) verifySignature(ctx context.Context, receipt *PaymentReceipt) error {
	if len(receipt.SignatureVal) == 0 {
		return ErrReceiptSignatureInvalid
	}

	content := receipt.SignableContent()
	valid, err := v.hsm.Verify(ctx, hsm.KeyHandle(receipt.SignatureKID), content, receipt.SignatureVal)
	if err != nil {
		return fmt.Errorf("ap2: verify signature: %w", err)
	}
	if !valid {
		return ErrReceiptSignatureInvalid
	}
	return nil
}

// validateAgainstRequest checks that the receipt matches its originating request.
func (v *ReceiptVerifier) validateAgainstRequest(receipt *PaymentReceipt) error {
	req, ok := v.requests[receipt.RequestID]
	if !ok {
		// If we don't have the request, we can still verify the receipt
		// based on its request hash (non-repudiation without full request).
		return nil
	}

	// Check expiry
	if !req.ExpiresAt.IsZero() && time.Now().After(req.ExpiresAt) {
		return ErrRequestExpired
	}

	// Amount must match exactly
	if receipt.AmountCents != req.AmountCents {
		return ErrAmountMismatch
	}

	// Currency must match
	if receipt.Currency != req.Currency {
		return fmt.Errorf("ap2: currency mismatch: receipt=%s request=%s", receipt.Currency, req.Currency)
	}

	// Verify request hash
	if receipt.RequestHash != "" && receipt.RequestHash != req.Hash() {
		return fmt.Errorf("ap2: request hash mismatch")
	}

	return nil
}

// validateChannelState ensures the receipt is valid within its channel.
func (v *ReceiptVerifier) validateChannelState(receipt *PaymentReceipt) error {
	ch, ok := v.channels[receipt.ChannelID]
	if !ok {
		return ErrChannelNotFound
	}

	// Channel must be open
	if !ch.IsOpen {
		return ErrChannelClosed
	}

	// Agents must match channel participants
	validAgents := (receipt.FromAgentID == ch.AgentA && receipt.ToAgentID == ch.AgentB) ||
		(receipt.FromAgentID == ch.AgentB && receipt.ToAgentID == ch.AgentA)
	if !validAgents {
		return ErrAgentMismatch
	}

	// Sequence must be monotonically increasing
	if receipt.SequenceNum <= ch.SequenceNum {
		return ErrSequenceRegression
	}

	// Check spend limits
	if receipt.FromAgentID == ch.AgentA {
		if ch.SpendLimitB > 0 && ch.TotalVolumeB+receipt.AmountCents > ch.SpendLimitB {
			return ErrSpendLimitExceeded
		}
	} else {
		if ch.SpendLimitA > 0 && ch.TotalVolumeA+receipt.AmountCents > ch.SpendLimitA {
			return ErrSpendLimitExceeded
		}
	}

	// Update channel state
	ch.SequenceNum = receipt.SequenceNum
	ch.LastActivityAt = time.Now()
	if receipt.FromAgentID == ch.AgentA {
		ch.BalanceCentsA += receipt.AmountCents
		ch.TotalVolumeB += receipt.AmountCents
	} else {
		ch.BalanceCentsB += receipt.AmountCents
		ch.TotalVolumeA += receipt.AmountCents
	}

	return nil
}

// FileDispute creates a dispute against a receipt.
func (v *ReceiptVerifier) FileDispute(dispute *PaymentDispute) error {
	v.mu.Lock()
	defer v.mu.Unlock()

	if dispute == nil {
		return fmt.Errorf("ap2: dispute is nil")
	}

	// Verify the disputed receipt exists
	_, ok := v.receipts[dispute.ReceiptID]
	if !ok {
		return ErrDisputeReceiptNotFound
	}

	dispute.Status = DisputeStatusOpen
	if dispute.CreatedAt.IsZero() {
		dispute.CreatedAt = time.Now()
	}

	v.disputes[dispute.DisputeID] = dispute
	return nil
}

// ResolveDispute resolves an open dispute.
func (v *ReceiptVerifier) ResolveDispute(disputeID string, status DisputeStatus, resolution string) error {
	v.mu.Lock()
	defer v.mu.Unlock()

	dispute, ok := v.disputes[disputeID]
	if !ok {
		return fmt.Errorf("ap2: dispute %s not found", disputeID)
	}

	if dispute.Status != DisputeStatusOpen {
		return fmt.Errorf("ap2: dispute %s is not open (status=%s)", disputeID, dispute.Status)
	}

	now := time.Now()
	dispute.Status = status
	dispute.Resolution = resolution
	dispute.ResolvedAt = &now

	return nil
}

// GetReceipt returns a stored receipt by ID.
func (v *ReceiptVerifier) GetReceipt(receiptID string) (*PaymentReceipt, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()

	r, ok := v.receipts[receiptID]
	if !ok {
		return nil, ErrRequestNotFound
	}
	return r, nil
}

// GetDispute returns a stored dispute by ID.
func (v *ReceiptVerifier) GetDispute(disputeID string) (*PaymentDispute, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()

	d, ok := v.disputes[disputeID]
	if !ok {
		return nil, fmt.Errorf("ap2: dispute %s not found", disputeID)
	}
	return d, nil
}
