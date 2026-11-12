// quantum_posture: this file only persists receipts whose classical Ed25519
// signatures are produced and verified elsewhere (issuer.go); it implements no
// cryptographic control itself beyond SHA-256-hashed content pass-through.

package spendproxy

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts/economic"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/inferencegateway"
)

// RecordKind classifies one line in the durable receipt log.
type RecordKind string

const (
	// RecordRouteQuote is appended BEFORE any provider dispatch (and also for
	// denied quotes, so refusals leave a durable audit trail).
	RecordRouteQuote RecordKind = "route_quote"
	// RecordBudgetVerdict is the Ed25519-signed pre-dispatch spend receipt.
	RecordBudgetVerdict RecordKind = "budget_verdict"
	// RecordUsage is the post-dispatch actual-usage receipt.
	RecordUsage RecordKind = "usage"
	// RecordSettlement is the balanced double-entry settlement receipt.
	RecordSettlement RecordKind = "settlement"
	// RecordSettleFailed marks a dispatch whose settlement could not commit
	// (e.g. quote expired mid-stream). It closes the audit trail instead of
	// leaving a silent authorized-but-unsettled gap; the dispatch stays held,
	// and a restart holds it again pending reconciliation.
	RecordSettleFailed RecordKind = "settle_failed"
	// RecordDispatchReleased marks a journalled dispatch whose hold was
	// released because no byte of its request left the proxy, so a restart
	// does not hold it again.
	RecordDispatchReleased RecordKind = "dispatch_released"
)

// NoteDispatchJournal is the note of the route_quote line appended before the
// provider call. A logged quote whose note starts with "rejected" was never
// dispatched.
const NoteDispatchJournal = "dispatch: journalled before the provider call"

// ReceiptRecord is one append-only line in the JSONL receipt log. Exactly one
// of the receipt pointers is set, matching Kind.
type ReceiptRecord struct {
	Kind          RecordKind `json:"kind"`
	TenantID      string     `json:"tenant_id"`
	SpendIntentID string     `json:"spend_intent_id,omitempty"`
	RecordedAt    time.Time  `json:"recorded_at"`
	// BalanceAfterCents is recorded on usage lines so a restarted proxy can
	// restore the idempotent-replay index with the historical balance.
	BalanceAfterCents int64  `json:"balance_after_cents,omitempty"`
	Note              string `json:"note,omitempty"`

	// PayloadSignature is the issuer's detached Ed25519 signature over the RFC
	// 8785 (JCS) canonicalization of the receipt payload carried by this record.
	// It covers post-dispatch fields (token counts, timestamps, substitution
	// flags) that the receipt types' sealed content-hash preimages omit, so
	// exported evidence can anchor them. PayloadSignatureKeyID resolves in the
	// trusted-key registry.
	PayloadSignature      string `json:"payload_signature,omitempty"`
	PayloadSignatureKeyID string `json:"payload_signature_key_id,omitempty"`

	RouteQuote    *economic.RouteQuote           `json:"route_quote,omitempty"`
	BudgetVerdict *economic.BudgetVerdictReceipt `json:"budget_verdict,omitempty"`
	Usage         *economic.UsageReceipt         `json:"usage,omitempty"`
	Settlement    *economic.SettlementReceipt    `json:"settlement,omitempty"`
}

// Payload returns the receipt payload carried by this record (exactly one
// pointer is set, matching Kind), or nil for kinds without a payload.
func (r *ReceiptRecord) Payload() any {
	switch {
	case r.RouteQuote != nil:
		return r.RouteQuote
	case r.BudgetVerdict != nil:
		return r.BudgetVerdict
	case r.Usage != nil:
		return r.Usage
	case r.Settlement != nil:
		return r.Settlement
	default:
		return nil
	}
}

// ReceiptLogName is the stable file name of the append-only receipt log inside
// a receipts directory. A single file (rather than per-day files) keeps restart
// replay trivially complete.
const ReceiptLogName = "spend-receipts.jsonl"

// FileStore is the append-only JSONL receipt log. Every append is fsynced so a
// pre-dispatch quote record is durable before the provider is called.
type FileStore struct {
	mu   sync.Mutex
	f    *os.File
	path string
}

// OpenFileStore opens (creating if needed) the receipt log inside dir.
func OpenFileStore(dir string) (*FileStore, error) {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, fmt.Errorf("spendproxy: create receipts dir: %w", err)
	}
	path := filepath.Join(dir, ReceiptLogName)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, fmt.Errorf("spendproxy: open receipt log: %w", err)
	}
	return &FileStore{f: f, path: path}, nil
}

// Path returns the receipt log path.
func (s *FileStore) Path() string { return s.path }

// Append writes one record as a JSON line and fsyncs it. Errors must be
// treated as fail-closed by dispatch paths.
func (s *FileStore) Append(rec *ReceiptRecord) error {
	if rec == nil {
		return errors.New("spendproxy: nil receipt record")
	}
	if rec.Kind == "" {
		return errors.New("spendproxy: receipt record kind is required")
	}
	if rec.RecordedAt.IsZero() {
		rec.RecordedAt = time.Now().UTC()
	}
	line, err := json.Marshal(rec)
	if err != nil {
		return fmt.Errorf("spendproxy: marshal receipt record: %w", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := s.f.Write(append(line, '\n')); err != nil {
		return fmt.Errorf("spendproxy: append receipt record: %w", err)
	}
	if err := s.f.Sync(); err != nil {
		return fmt.Errorf("spendproxy: sync receipt log: %w", err)
	}
	return nil
}

// Close closes the underlying file.
func (s *FileStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.f.Close()
}

// LoadRecords reads every record from a receipt log. A missing file yields an
// empty slice; a malformed line is an error (the log is evidence, not best
// effort).
func LoadRecords(path string) ([]*ReceiptRecord, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("spendproxy: open receipt log: %w", err)
	}
	defer f.Close()

	var out []*ReceiptRecord
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		rec := &ReceiptRecord{}
		if err := json.Unmarshal(line, rec); err != nil {
			return nil, fmt.Errorf("spendproxy: receipt log %s line %d: %w", path, lineNo, err)
		}
		out = append(out, rec)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("spendproxy: read receipt log: %w", err)
	}
	return out, nil
}

// ReplaySummary reports what restart replay recovered from the receipt log.
type ReplaySummary struct {
	// DebitedCents is the sum of committed balance debits found in the log; the
	// opening balance for this process is the configured opening minus this.
	DebitedCents int64
	// RestoredSettlements counts idempotency-index entries restored so replayed
	// requests do not dispatch (and debit) twice across restarts.
	RestoredSettlements int
	// Records is the total number of log lines read.
	Records int
	// PendingDispatches counts dispatches journalled before their provider
	// call that never settled or released; PendingCents is what they hold
	// again, pending reconciliation.
	PendingDispatches int
	PendingCents      int64
}

// ReplayRecords computes the already-debited total from the log and restores
// completed settlements into the ledger's idempotency index. Call it with the
// ledger built from the replay-adjusted opening balance:
//
//	records, _ := LoadRecords(path)
//	debited := DebitedCents(records)
//	ledger := NewBalanceLedger(account with opening-debited)
//	ReplayRecords(records, ledger)
func ReplayRecords(records []*ReceiptRecord, ledger *inferencegateway.BalanceLedger) (*ReplaySummary, error) {
	sum := &ReplaySummary{Records: len(records)}
	type pair struct {
		usage        *economic.UsageReceipt
		settlement   *economic.SettlementReceipt
		balanceAfter int64
	}
	pairs := make(map[string]*pair)
	order := make([]string, 0)
	for _, rec := range records {
		if rec.SpendIntentID == "" {
			continue
		}
		p, ok := pairs[rec.SpendIntentID]
		if !ok {
			p = &pair{}
			pairs[rec.SpendIntentID] = p
			order = append(order, rec.SpendIntentID)
		}
		switch rec.Kind {
		case RecordUsage:
			p.usage = rec.Usage
			p.balanceAfter = rec.BalanceAfterCents
		case RecordSettlement:
			p.settlement = rec.Settlement
		}
	}
	for _, intentID := range order {
		p := pairs[intentID]
		if p.usage == nil || p.settlement == nil {
			continue
		}
		if err := ledger.RestoreSettlement(p.usage, p.settlement, p.balanceAfter); err != nil {
			return nil, fmt.Errorf("spendproxy: restore settlement for %s: %w", intentID, err)
		}
		sum.DebitedCents += p.usage.BalanceDebitCents
		sum.RestoredSettlements++
	}
	return sum, nil
}

// DebitedCents sums the committed balance debits in the log — the amount
// already spent against the configured opening balance in prior runs. Only
// usage records with a matching settlement count (an unsettled usage line
// cannot exist under the ledger's commit invariants, but fail safe anyway).
func DebitedCents(records []*ReceiptRecord) int64 {
	settled := make(map[string]bool)
	for _, rec := range records {
		if rec.Kind == RecordSettlement && rec.SpendIntentID != "" {
			settled[rec.SpendIntentID] = true
		}
	}
	var total int64
	for _, rec := range records {
		if rec.Kind == RecordUsage && rec.Usage != nil && settled[rec.SpendIntentID] {
			total += rec.Usage.BalanceDebitCents
		}
	}
	return total
}

// restoreEnvelopeUse re-applies every settled debit in the log to the envelope
// window it was settled in, so a restarted proxy does not hand an envelope's
// limit out again (helm-tracker#313, audit H7). A debit under an envelope the
// config no longer declares is not applied to any.
func restoreEnvelopeUse(records []*ReceiptRecord, ledger *inferencegateway.BalanceLedger, envelopes map[string]*economic.AgentSpendEnvelope) {
	settled := make(map[string]bool)
	for _, rec := range records {
		if rec.Kind == RecordSettlement && rec.SpendIntentID != "" {
			settled[rec.SpendIntentID] = true
		}
	}
	seen := make(map[string]bool)
	for _, rec := range records {
		if rec.Kind != RecordUsage || rec.Usage == nil || !settled[rec.SpendIntentID] || seen[rec.SpendIntentID] {
			continue
		}
		seen[rec.SpendIntentID] = true
		if env := envelopes[rec.Usage.EnvelopeID]; env != nil {
			ledger.RestoreEnvelopeUse(env, rec.RecordedAt, rec.Usage.BalanceDebitCents)
		}
	}
}

// isDispatchJournal reports whether a route_quote line was appended before a
// provider call: an allowing quote bound to its receipt and not a logged
// refusal. Logs written before the journal note existed carry no note.
func isDispatchJournal(rec *ReceiptRecord) bool {
	if rec.Kind != RecordRouteQuote || rec.RouteQuote == nil {
		return false
	}
	q := rec.RouteQuote
	if q.BudgetVerdict != economic.BudgetVerdictAllow || q.ReceiptHash == "" {
		return false
	}
	return rec.Note == NoteDispatchJournal || rec.Note == ""
}

// RestorePendingDispatches holds again, in engine, every dispatch the log
// journalled before its provider call that has no settlement and no release:
// the provider may have billed it, so its quote ceiling stays reserved against
// its envelope and the balance, pending reconciliation, and its idempotency key
// cannot dispatch again (audit M18). A dispatch under an envelope the config no
// longer declares refuses the start: its cents would otherwise be forgotten.
func RestorePendingDispatches(records []*ReceiptRecord, engine *inferencegateway.Engine, envelopes map[string]*economic.AgentSpendEnvelope) ([]*inferencegateway.Reservation, error) {
	// Read the log in order: a journal line opens a dispatch, a release closes
	// the journal before it (a retry may journal the key again), and a
	// settlement closes the key for good.
	open := make(map[string]*ReceiptRecord)
	var order []string
	listed := make(map[string]bool)
	settled := make(map[string]bool)
	for _, rec := range records {
		switch {
		case rec.SpendIntentID == "":
		case rec.Kind == RecordSettlement:
			settled[rec.SpendIntentID] = true
		case rec.Kind == RecordDispatchReleased:
			delete(open, rec.SpendIntentID)
		case isDispatchJournal(rec):
			if !listed[rec.SpendIntentID] {
				listed[rec.SpendIntentID] = true
				order = append(order, rec.SpendIntentID)
			}
			open[rec.SpendIntentID] = rec
		}
	}
	var out []*inferencegateway.Reservation
	for _, intentID := range order {
		rec, pending := open[intentID]
		if !pending || settled[intentID] {
			continue
		}
		env := envelopes[rec.RouteQuote.EnvelopeID]
		if env == nil {
			return nil, fmt.Errorf("spendproxy: the log holds an unsettled dispatch %s under envelope %q, which the config no longer declares; refusing to start", rec.SpendIntentID, rec.RouteQuote.EnvelopeID)
		}
		res, err := engine.RestorePendingDispatch(env, rec.RouteQuote, rec.RecordedAt)
		if err != nil {
			return nil, fmt.Errorf("spendproxy: hold unsettled dispatch %s: %w", rec.SpendIntentID, err)
		}
		if res != nil {
			out = append(out, res)
		}
	}
	return out, nil
}
