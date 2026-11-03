package inferencegateway

import (
	"errors"
	"fmt"
	"time"

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

// reserveExclusive places a hold that only one dispatch may own: it refuses
// while a hold for the key is open (a dispatch is in flight or failed to
// settle) or consumed (the key already settled). A released hold, left by a
// failed dispatch, is replaced so a retry reserves afresh.
func (l *BalanceLedger) reserveExclusive(reservationKey string, amountCents int64, quoteReceiptHash string) (*Reservation, error) {
	if reservationKey == "" || amountCents <= 0 || quoteReceiptHash == "" {
		return nil, errors.New("inferencegateway: reservation requires a key, a positive amount and a quote receipt hash")
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	if existing, ok := l.reservations[reservationKey]; ok && !existing.Released {
		return nil, ErrDispatchConflict
	}
	return l.reserveLocked(reservationKey, amountCents, quoteReceiptHash)
}

// reserveLocked checks funds and posts a new hold. Callers must hold l.mu.
func (l *BalanceLedger) reserveLocked(reservationKey string, amountCents int64, quoteReceiptHash string) (*Reservation, error) {
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

// openReservationLocked returns the key's reservation while it still holds
// funds (neither released nor consumed). Callers must hold l.mu.
func (l *BalanceLedger) openReservationLocked(reservationKey string) *Reservation {
	res, ok := l.reservations[reservationKey]
	if !ok || res.Consumed || res.Released {
		return nil
	}
	return res
}

// hasOpenReservation reports whether a dispatch hold for the key still holds
// funds, i.e. the dispatch was authorized and has not settled or released.
func (l *BalanceLedger) hasOpenReservation(reservationKey string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.openReservationLocked(reservationKey) != nil
}
