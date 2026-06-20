package inferencegateway

import (
	"errors"
	"fmt"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts/economic"
)

// MovementResult is the outcome of one balance lifecycle movement.
type MovementResult struct {
	Receipt           *economic.BalanceMovementReceipt
	Entry             *economic.UsageLedgerEntry
	BalanceAfterCents int64
	HoldAfterCents    int64
	Replayed          bool
}

// nextEntryIDLocked allocates a deterministic, monotonically increasing entry id.
// Callers must hold l.mu.
func (l *BalanceLedger) nextEntryIDLocked(kind string) string {
	l.nextEntryID++
	return fmt.Sprintf("ule-%s-%s-%d", l.account.ID, kind, l.nextEntryID)
}

// postMovementLocked appends one immutable ledger entry for a movement receipt
// and indexes it by the movement's idempotency key. Callers must hold l.mu and
// must have already applied the balance/hold change.
func (l *BalanceLedger) postMovementLocked(receipt *economic.BalanceMovementReceipt, entryType economic.UsageLedgerEntryType, kind string) (*economic.UsageLedgerEntry, error) {
	entry := economic.NewUsageLedgerEntry(
		l.nextEntryIDLocked(kind),
		l.account.TenantID,
		l.account.ID,
		entryType,
		receipt.Direction,
		receipt.AmountCents,
		l.account.Currency,
		movementReasonCode(receipt.Type),
		receipt.ContentHash,
	)
	if err := entry.Validate(); err != nil {
		return nil, fmt.Errorf("inferencegateway: movement ledger entry invalid: %w", err)
	}
	l.entries = append(l.entries, entry)
	l.movements[receipt.IdempotencyKey] = entry
	l.account.UpdatedAt = time.Now().UTC()
	return entry, nil
}

// movementReasonCode maps a movement type to a stable spend reason code so the
// resulting ledger entry remains auditable.
func movementReasonCode(t economic.BalanceMovementType) economic.SpendReasonCode {
	switch t {
	case economic.BalanceMovementCorrection:
		return economic.SpendReasonOKApproved
	default:
		return economic.SpendReasonOKWithinEnvelope
	}
}

// validateMovementCurrency fails closed on a cross-currency movement.
func (l *BalanceLedger) validateMovementCurrency(receipt *economic.BalanceMovementReceipt) error {
	if receipt.Currency != l.account.Currency {
		return fmt.Errorf("inferencegateway: movement currency %s does not match balance account %s", receipt.Currency, l.account.Currency)
	}
	return nil
}

// creditMovement is the shared credit path for TOP_UP, PROMO_CREDIT, and REFUND.
// It is idempotent on the receipt's idempotency key and adds funds to the
// available balance.
func (l *BalanceLedger) creditMovement(receipt *economic.BalanceMovementReceipt) (*MovementResult, error) {
	if receipt == nil {
		return nil, errors.New("inferencegateway: movement receipt is required")
	}
	if err := receipt.Validate(); err != nil {
		return nil, fmt.Errorf("inferencegateway: movement receipt invalid: %w", err)
	}
	if receipt.Direction != economic.SettlementCredit {
		return nil, errors.New("inferencegateway: credit movement must have CREDIT direction")
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	if existing, ok := l.movements[receipt.IdempotencyKey]; ok {
		return &MovementResult{
			Entry:             existing,
			BalanceAfterCents: l.account.BalanceCents,
			HoldAfterCents:    l.account.HoldCents,
			Replayed:          true,
		}, nil
	}
	if err := l.validateMovementCurrency(receipt); err != nil {
		return nil, err
	}
	if l.account.Status != economic.BalanceAccountActive {
		return nil, fmt.Errorf("inferencegateway: balance account is %s, credit refused", l.account.Status)
	}

	l.account.BalanceCents += receipt.AmountCents
	entry, err := l.postMovementLocked(receipt, receipt.LedgerEntryType(), movementKind(receipt.Type))
	if err != nil {
		l.account.BalanceCents -= receipt.AmountCents // unwind on failure
		return nil, err
	}
	return &MovementResult{
		Receipt:           receipt,
		Entry:             entry,
		BalanceAfterCents: l.account.BalanceCents,
		HoldAfterCents:    l.account.HoldCents,
	}, nil
}

func movementKind(t economic.BalanceMovementType) string {
	switch t {
	case economic.BalanceMovementTopUp:
		return "topup"
	case economic.BalanceMovementPromoCredit:
		return "promo"
	case economic.BalanceMovementRefund:
		return "refund"
	case economic.BalanceMovementCorrection:
		return "correction"
	case economic.BalanceMovementProviderCostAccrual:
		return "provcost"
	case economic.BalanceMovementPlatformFeeAccrual:
		return "platfee"
	case economic.BalanceMovementInvoiceAccrual:
		return "invoice"
	default:
		return "movement"
	}
}

// TopUp adds prepaid funds to the usage balance. Idempotent on idempotencyKey.
func (l *BalanceLedger) TopUp(receiptID string, amountCents int64, idempotencyKey, evidencePackRef string) (*MovementResult, error) {
	receipt := economic.NewBalanceMovementReceipt(receiptID, l.account.TenantID, l.account.ID, economic.BalanceMovementTopUp, amountCents, l.account.Currency, idempotencyKey, evidencePackRef)
	return l.creditMovement(receipt)
}

// Promo adds promotional (non-cash) credit to the usage balance.
func (l *BalanceLedger) Promo(receiptID string, amountCents int64, idempotencyKey, evidencePackRef string) (*MovementResult, error) {
	receipt := economic.NewBalanceMovementReceipt(receiptID, l.account.TenantID, l.account.ID, economic.BalanceMovementPromoCredit, amountCents, l.account.Currency, idempotencyKey, evidencePackRef)
	return l.creditMovement(receipt)
}

// Refund returns funds for a reversed usage debit. sourceUsageReceiptHash binds
// the refund to the UsageReceipt it reverses so the movement is auditable.
func (l *BalanceLedger) Refund(receiptID string, amountCents int64, idempotencyKey, sourceUsageReceiptHash, evidencePackRef string) (*MovementResult, error) {
	receipt := economic.NewBalanceMovementReceipt(receiptID, l.account.TenantID, l.account.ID, economic.BalanceMovementRefund, amountCents, l.account.Currency, idempotencyKey, evidencePackRef)
	receipt.SourceReceiptHash = sourceUsageReceiptHash
	receipt.Reseal()
	return l.creditMovement(receipt)
}

// Reserve places a hold for a dispatch's estimated max cost, keyed by the quote.
// It is fail-closed: a hold that would push available funds below zero is
// refused unless enterprise invoicing is enabled. quoteReceiptHash binds the
// hold to the RouteQuote that authorized it. Idempotent on reservationKey.
func (l *BalanceLedger) Reserve(reservationKey string, amountCents int64, quoteReceiptHash string) (*Reservation, error) {
	if reservationKey == "" {
		return nil, errors.New("inferencegateway: reservation key is required")
	}
	if amountCents <= 0 {
		return nil, errors.New("inferencegateway: reservation amount must be positive")
	}
	if quoteReceiptHash == "" {
		return nil, errors.New("inferencegateway: reservation requires a quote receipt hash")
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	if existing, ok := l.reservations[reservationKey]; ok {
		return existing, nil // idempotent: same dispatch reserves once
	}
	if l.account.Status != economic.BalanceAccountActive {
		return nil, fmt.Errorf("inferencegateway: balance account is %s, reservation refused", l.account.Status)
	}
	if !l.allowNegativeBalance && amountCents > l.account.AvailableCents() {
		return nil, errors.New("inferencegateway: reservation exceeds available funds")
	}

	entry := economic.NewUsageLedgerEntry(
		l.nextEntryIDLocked("reserve"),
		l.account.TenantID, l.account.ID,
		economic.UsageLedgerReserve, economic.SettlementDebit,
		amountCents, l.account.Currency,
		economic.SpendReasonOKWithinEnvelope, quoteReceiptHash,
	)
	if err := entry.Validate(); err != nil {
		return nil, fmt.Errorf("inferencegateway: reserve entry invalid: %w", err)
	}
	l.account.HoldCents += amountCents
	l.account.UpdatedAt = time.Now().UTC()
	l.entries = append(l.entries, entry)

	res := &Reservation{Key: reservationKey, AmountCents: amountCents, ReceiptHash: quoteReceiptHash, EntryID: entry.ID}
	l.reservations[reservationKey] = res
	return res, nil
}

// Release frees an open reservation when a run fails or is abandoned. It is
// idempotent and a no-op for a reservation that was already consumed by a debit.
func (l *BalanceLedger) Release(reservationKey string) (*economic.UsageLedgerEntry, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	res, ok := l.reservations[reservationKey]
	if !ok {
		return nil, errors.New("inferencegateway: no reservation for key")
	}
	if res.Consumed {
		return nil, errors.New("inferencegateway: reservation already consumed by a debit")
	}
	if res.Released {
		// Idempotent: return the prior release entry.
		if e := l.findReleaseEntryLocked(reservationKey); e != nil {
			return e, nil
		}
	}

	entry := economic.NewUsageLedgerEntry(
		l.nextEntryIDLocked("release"),
		l.account.TenantID, l.account.ID,
		economic.UsageLedgerRelease, economic.SettlementCredit,
		res.AmountCents, l.account.Currency,
		economic.SpendReasonOKWithinEnvelope, res.ReceiptHash,
	)
	if err := entry.Validate(); err != nil {
		return nil, fmt.Errorf("inferencegateway: release entry invalid: %w", err)
	}
	l.releaseHoldLocked(res.AmountCents)
	res.Released = true
	l.entries = append(l.entries, entry)
	return entry, nil
}

func (l *BalanceLedger) findReleaseEntryLocked(reservationKey string) *economic.UsageLedgerEntry {
	res := l.reservations[reservationKey]
	if res == nil {
		return nil
	}
	for _, e := range l.entries {
		if e.Type == economic.UsageLedgerRelease && e.SourceContentHash == res.ReceiptHash {
			return e
		}
	}
	return nil
}

// releaseHoldLocked drops a hold without underflowing. Callers must hold l.mu.
func (l *BalanceLedger) releaseHoldLocked(amountCents int64) {
	l.account.HoldCents -= amountCents
	if l.account.HoldCents < 0 {
		l.account.HoldCents = 0
	}
	l.account.UpdatedAt = time.Now().UTC()
}

// consumeReservationForDebit converts an open reservation into a settled debit:
// it drops the hold so the subsequent balance debit is not double-counted, and
// marks the reservation consumed so it can no longer be released. It is a no-op
// when no reservation exists for the key. Callers must NOT hold l.mu.
func (l *BalanceLedger) consumeReservationForDebit(reservationKey string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	res, ok := l.reservations[reservationKey]
	if !ok || res.Consumed || res.Released {
		return
	}
	l.releaseHoldLocked(res.AmountCents)
	res.Consumed = true
}

// Adjust posts an append-only manual correction. It requires an approved,
// dual-control approval ceremony and never edits prior history. A debit
// correction respects the no-negative-balance rule unless invoicing is enabled.
func (l *BalanceLedger) Adjust(receiptID string, direction economic.SettlementDirection, amountCents int64, idempotencyKey, reason string, approval *contracts.ApprovalCeremony, evidencePackRef string) (*MovementResult, error) {
	if direction != economic.SettlementDebit && direction != economic.SettlementCredit {
		return nil, errors.New("inferencegateway: correction direction must be DEBIT or CREDIT")
	}
	receipt := economic.NewBalanceMovementReceipt(receiptID, l.account.TenantID, l.account.ID, economic.BalanceMovementCorrection, amountCents, l.account.Currency, idempotencyKey, evidencePackRef)
	receipt.Direction = direction
	receipt.Reason = reason
	receipt.Approval = approval
	receipt.Reseal()
	if err := receipt.Validate(); err != nil {
		return nil, fmt.Errorf("inferencegateway: correction receipt invalid: %w", err)
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	if existing, ok := l.movements[receipt.IdempotencyKey]; ok {
		return &MovementResult{
			Entry:             existing,
			BalanceAfterCents: l.account.BalanceCents,
			HoldAfterCents:    l.account.HoldCents,
			Replayed:          true,
		}, nil
	}
	if err := l.validateMovementCurrency(receipt); err != nil {
		return nil, err
	}
	if l.account.Status != economic.BalanceAccountActive {
		return nil, fmt.Errorf("inferencegateway: balance account is %s, correction refused", l.account.Status)
	}

	before := l.account.BalanceCents
	if direction == economic.SettlementCredit {
		l.account.BalanceCents += amountCents
	} else {
		if !l.allowNegativeBalance && amountCents > l.account.BalanceCents {
			return nil, errors.New("inferencegateway: debit correction would drive balance negative")
		}
		l.account.BalanceCents -= amountCents
	}
	entry, err := l.postMovementLocked(receipt, economic.UsageLedgerAdjustment, "correction")
	if err != nil {
		l.account.BalanceCents = before // unwind
		return nil, err
	}
	return &MovementResult{
		Receipt:           receipt,
		Entry:             entry,
		BalanceAfterCents: l.account.BalanceCents,
		HoldAfterCents:    l.account.HoldCents,
	}, nil
}

// Accrue records a bookkeeping-only accrual (provider cost, platform fee, or
// enterprise invoice). It does NOT move the cash balance, but it IS posted as an
// immutable, receipt-bound ledger entry so the finance export totals can be
// reconciled against raw provider cost and platform fee. Idempotent on key.
func (l *BalanceLedger) Accrue(receiptID string, accrualType economic.BalanceMovementType, amountCents int64, idempotencyKey, evidencePackRef string) (*MovementResult, error) {
	if !accrualType.IsAccrual() {
		return nil, fmt.Errorf("inferencegateway: %s is not an accrual type", accrualType)
	}
	receipt := economic.NewBalanceMovementReceipt(receiptID, l.account.TenantID, l.account.ID, accrualType, amountCents, l.account.Currency, idempotencyKey, evidencePackRef)
	if err := receipt.Validate(); err != nil {
		return nil, fmt.Errorf("inferencegateway: accrual receipt invalid: %w", err)
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	if existing, ok := l.movements[receipt.IdempotencyKey]; ok {
		return &MovementResult{Entry: existing, BalanceAfterCents: l.account.BalanceCents, HoldAfterCents: l.account.HoldCents, Replayed: true}, nil
	}
	if err := l.validateMovementCurrency(receipt); err != nil {
		return nil, err
	}
	// Accruals do not mutate BalanceCents; they only append an entry and roll up
	// into the finance-export accrual totals.
	entry, err := l.postMovementLocked(receipt, economic.UsageLedgerCredit, movementKind(accrualType))
	if err != nil {
		return nil, err
	}
	l.accrualEntryIDs[entry.ID] = struct{}{}
	switch accrualType {
	case economic.BalanceMovementProviderCostAccrual:
		l.providerCostAccruedCents += amountCents
	case economic.BalanceMovementPlatformFeeAccrual:
		l.platformFeeAccruedCents += amountCents
	case economic.BalanceMovementInvoiceAccrual:
		l.invoiceAccruedCents += amountCents
	}
	return &MovementResult{Receipt: receipt, Entry: entry, BalanceAfterCents: l.account.BalanceCents, HoldAfterCents: l.account.HoldCents}, nil
}

// HoldCents returns the currently reserved (held) cents.
func (l *BalanceLedger) HoldCents() int64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.account.HoldCents
}

// Reservation returns an open or settled reservation by key.
func (l *BalanceLedger) Reservation(reservationKey string) (*Reservation, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	res, ok := l.reservations[reservationKey]
	return res, ok
}
