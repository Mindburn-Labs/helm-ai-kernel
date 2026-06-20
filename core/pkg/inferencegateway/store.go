// Package inferencegateway implements the RouteQuote engine that backs HELM's
// OpenAI-compatible governed inference gateway (MIN-468 / SPEND3).
//
// The engine binds every model dispatch to source-owned economic evidence:
// it creates an expiring RouteQuote from a ProviderPriceSnapshot before
// dispatch, fails closed on stale pricing or unreviewed provider terms, caps
// or escalates when actual cost exceeds the quote ceiling, and emits the
// UsageReceipt + balanced SettlementReceipt that debit the governed balance
// exactly once per idempotency key.
//
// This package only orchestrates the canonical contracts in
// core/pkg/contracts/economic; it does not define a parallel proof universe.
package inferencegateway

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts/economic"
)

// PriceProvider returns the current price snapshot for a provider/model pair.
type PriceProvider interface {
	Snapshot(providerID, modelID string) (*economic.ProviderPriceSnapshot, bool)
}

// TermsProvider returns the legal/commercial terms profile for a provider.
type TermsProvider interface {
	Terms(providerID string) (*economic.ProviderTermsProfile, bool)
}

// MemoryPriceBook is an in-memory PriceProvider keyed by provider/model.
type MemoryPriceBook struct {
	mu        sync.RWMutex
	snapshots map[string]*economic.ProviderPriceSnapshot
}

// NewMemoryPriceBook creates an empty price book.
func NewMemoryPriceBook() *MemoryPriceBook {
	return &MemoryPriceBook{snapshots: make(map[string]*economic.ProviderPriceSnapshot)}
}

func priceKey(providerID, modelID string) string { return providerID + "\x00" + modelID }

// Put stores a price snapshot. It rejects snapshots that do not validate so the
// engine can trust any snapshot the book hands back.
func (b *MemoryPriceBook) Put(snapshot *economic.ProviderPriceSnapshot) error {
	if err := snapshot.Validate(); err != nil {
		return err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.snapshots[priceKey(snapshot.ProviderID, snapshot.ModelID)] = snapshot
	return nil
}

// Snapshot implements PriceProvider.
func (b *MemoryPriceBook) Snapshot(providerID, modelID string) (*economic.ProviderPriceSnapshot, bool) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	s, ok := b.snapshots[priceKey(providerID, modelID)]
	return s, ok
}

// MemoryTermsBook is an in-memory TermsProvider keyed by provider.
type MemoryTermsBook struct {
	mu    sync.RWMutex
	terms map[string]*economic.ProviderTermsProfile
}

// NewMemoryTermsBook creates an empty terms book.
func NewMemoryTermsBook() *MemoryTermsBook {
	return &MemoryTermsBook{terms: make(map[string]*economic.ProviderTermsProfile)}
}

// Put stores a terms profile, rejecting profiles that do not validate.
func (b *MemoryTermsBook) Put(profile *economic.ProviderTermsProfile) error {
	if err := profile.Validate(); err != nil {
		return err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.terms[profile.ProviderID] = profile
	return nil
}

// Terms implements TermsProvider.
func (b *MemoryTermsBook) Terms(providerID string) (*economic.ProviderTermsProfile, bool) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	t, ok := b.terms[providerID]
	return t, ok
}

// BalanceLedger is the fail-closed, idempotent governed balance backing the
// gateway. It holds the canonical economic.BalanceAccount, the immutable list
// of posted economic.UsageLedgerEntry rows, and an idempotency index so a
// replayed request never debits twice.
//
// Beyond the SPEND3 settle/debit path it owns the full SPEND5 balance lifecycle
// (top-up, reserve, release, refund, promo, accrual, and approved correction).
// Every method appends an immutable, receipt-hash-bound economic.UsageLedgerEntry;
// no method ever edits or deletes a prior entry, so the ledger is append-only.
type BalanceLedger struct {
	mu           sync.Mutex
	account      *economic.BalanceAccount
	entries      []*economic.UsageLedgerEntry
	settled      map[string]*SettlementRecord          // settle idempotency key -> committed settlement
	movements    map[string]*economic.UsageLedgerEntry // movement idempotency key -> posted entry
	reservations map[string]*Reservation               // reservation key -> open hold
	nextEntryID  int64
	// allowNegativeBalance permits the balance to go below zero. It is only set
	// when enterprise invoicing (deferred billing) is enabled for the account.
	allowNegativeBalance bool
	// Accrual roll-ups feed the finance export. They are bookkeeping totals only
	// and never move the cash balance. accrualEntryIDs marks which posted entries
	// are accruals so the export excludes them from the cash balance delta
	// without re-deriving type from the entry id.
	providerCostAccruedCents int64
	platformFeeAccruedCents  int64
	invoiceAccruedCents      int64
	accrualEntryIDs          map[string]struct{}
}

// Reservation is an open hold placed against the balance for a dispatch's
// estimated max cost. It is consumed by a debit at settlement or freed by a
// release when the run fails.
type Reservation struct {
	Key         string
	AmountCents int64
	ReceiptHash string
	EntryID     string
	Released    bool
	Consumed    bool
}

// SettlementRecord is the committed financial outcome for one governed request.
type SettlementRecord struct {
	IdempotencyKey    string
	UsageReceipt      *economic.UsageReceipt
	SettlementReceipt *economic.SettlementReceipt
	LedgerEntries     []*economic.UsageLedgerEntry
	BalanceDebitCents int64
	BalanceAfterCents int64
}

// NewBalanceLedger creates a ledger over a validated balance account.
func NewBalanceLedger(account *economic.BalanceAccount) (*BalanceLedger, error) {
	if err := account.Validate(); err != nil {
		return nil, err
	}
	return &BalanceLedger{
		account:              account,
		settled:              make(map[string]*SettlementRecord),
		movements:            make(map[string]*economic.UsageLedgerEntry),
		reservations:         make(map[string]*Reservation),
		accrualEntryIDs:      make(map[string]struct{}),
		allowNegativeBalance: account.Type == economic.BalanceAccountInvoiceAccrual,
	}, nil
}

// EnableEnterpriseInvoicing turns on deferred (invoice-accrual) billing for the
// account, which is the only condition under which the balance may go negative.
// It is fail-closed by default: a plain USAGE_BALANCE account never goes
// negative unless this is explicitly enabled.
func (l *BalanceLedger) EnableEnterpriseInvoicing() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.allowNegativeBalance = true
}

// AvailableCents returns funds currently available for debit.
func (l *BalanceLedger) AvailableCents() int64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.account.AvailableCents()
}

// BalanceCents returns the current posted balance.
func (l *BalanceLedger) BalanceCents() int64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.account.BalanceCents
}

// Lookup returns a previously committed settlement for an idempotency key.
func (l *BalanceLedger) Lookup(idempotencyKey string) (*SettlementRecord, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	rec, ok := l.settled[idempotencyKey]
	return rec, ok
}

// Entries returns a snapshot copy of all posted ledger entries.
func (l *BalanceLedger) Entries() []*economic.UsageLedgerEntry {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]*economic.UsageLedgerEntry, len(l.entries))
	copy(out, l.entries)
	return out
}

// commit posts the double-entry debit for a usage receipt against the governed
// balance under the ledger's balancing and idempotency invariants:
//
//   - Idempotent: replaying the same idempotency key returns the prior record
//     without mutating the balance again.
//   - Balanced: the SettlementReceipt double-entry must balance (debits ==
//     credits) before any balance mutation.
//   - Fail-closed: the account must be ACTIVE with sufficient available funds;
//     otherwise nothing is posted.
//   - Conservation: balance_after == balance_before - balance_debit exactly.
func (l *BalanceLedger) commit(
	idempotencyKey string,
	usage *economic.UsageReceipt,
	settlement *economic.SettlementReceipt,
) (*SettlementRecord, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if idempotencyKey == "" {
		return nil, errors.New("inferencegateway: idempotency key is required to commit a debit")
	}
	if existing, ok := l.settled[idempotencyKey]; ok {
		return existing, nil
	}
	if err := usage.Validate(); err != nil {
		return nil, fmt.Errorf("inferencegateway: usage receipt invalid: %w", err)
	}
	if err := settlement.Validate(); err != nil {
		return nil, fmt.Errorf("inferencegateway: settlement receipt invalid: %w", err)
	}
	if !settlement.Balanced() {
		return nil, errors.New("inferencegateway: settlement ledger is not balanced")
	}
	if settlement.SourceUsageReceiptHash != usage.ContentHash {
		return nil, errors.New("inferencegateway: settlement does not bind the usage receipt hash")
	}
	if usage.Currency != l.account.Currency {
		return nil, errors.New("inferencegateway: usage currency does not match balance account")
	}
	debit := usage.BalanceDebitCents
	if debit <= 0 {
		return nil, errors.New("inferencegateway: balance debit must be positive")
	}
	if l.account.Status != economic.BalanceAccountActive {
		return nil, fmt.Errorf("inferencegateway: balance account is %s, debit refused", l.account.Status)
	}
	if debit > l.account.AvailableCents() {
		return nil, errors.New("inferencegateway: balance debit exceeds available funds")
	}

	before := l.account.BalanceCents
	l.nextEntryID++
	entry := economic.NewUsageLedgerEntry(
		fmt.Sprintf("ule-%s-%d", l.account.ID, l.nextEntryID),
		l.account.TenantID,
		l.account.ID,
		economic.UsageLedgerDebit,
		economic.SettlementDebit,
		debit,
		l.account.Currency,
		usage.ReasonCode,
		usage.ContentHash,
	)
	entry.UsageReceiptID = usage.ID
	entry.SettlementReceiptID = settlement.ID
	if err := entry.Validate(); err != nil {
		return nil, fmt.Errorf("inferencegateway: ledger entry invalid: %w", err)
	}

	l.account.BalanceCents = before - debit
	l.account.UpdatedAt = time.Now().UTC()
	l.entries = append(l.entries, entry)

	rec := &SettlementRecord{
		IdempotencyKey:    idempotencyKey,
		UsageReceipt:      usage,
		SettlementReceipt: settlement,
		LedgerEntries:     []*economic.UsageLedgerEntry{entry},
		BalanceDebitCents: debit,
		BalanceAfterCents: l.account.BalanceCents,
	}
	l.settled[idempotencyKey] = rec
	return rec, nil
}
