// quantum_posture: this file persists receipts whose classical Ed25519
// signatures are produced in issuer.go, and verifyBookLines checks those
// signatures with classical Ed25519 (export.go verifyDetached) before a start
// replays the lines; no post-quantum primitive is used in this file.

package spendproxy

import (
	"bufio"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
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
	// released, so a restart does not hold it again: because no byte of its
	// request left the proxy, or because an operator released it with a
	// reason (`spend-proxy reconcile --release`). It carries the dispatch's
	// route quote, whose signed metadata binds the versioned release action
	// and its reason. Its signed tenant and intent must match this record.
	RecordDispatchReleased RecordKind = "dispatch_released"
)

// MetadataReleaseReason is the route-quote metadata key of a release record
// that says why the hold was released.
const MetadataReleaseReason = "release_reason"

// MetadataReleaseAction distinguishes an authorized release from a dispatch
// journal that carries the same RouteQuote type. This uses the existing signed
// RouteQuote metadata, not a new signature format. The v1 action also requires
// a nonempty reason and matching signed tenant/intent identities.
const MetadataReleaseAction = "release_action"

const releaseActionV1 = "dispatch_released/v1"

// The route-quote metadata keys of a settle_failed record: the actual cost, in
// cents (the provider's bill and the platform fee on it), and the overage,
// the actual cost above the hold, which with a fee can exceed what the
// provider billed above its part of the hold.
const (
	MetadataActualCents  = "actual_amount_cents"
	MetadataOverageCents = "overage_cents"
)

// NoteDispatchJournal is the note of the route_quote line appended before the
// provider call. A logged quote whose note starts with "rejected" was never
// dispatched.
const NoteDispatchJournal = "dispatch: journalled before the provider call"

// ReceiptRecord is one append-only line in the JSONL receipt log. Exactly one
// of the receipt pointers is set, the one its Kind names (payloadKinds).
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
	// 8785 (JCS) canonicalization of the receipt payload its Kind names. It
	// covers post-dispatch fields (token counts, timestamps, substitution
	// flags, metadata) that the receipt types' sealed content-hash preimages
	// omit, so exported evidence can anchor them. PayloadSignatureKeyID is the
	// issuer's key id.
	PayloadSignature      string `json:"payload_signature,omitempty"`
	PayloadSignatureKeyID string `json:"payload_signature_key_id,omitempty"`

	RouteQuote    *economic.RouteQuote           `json:"route_quote,omitempty"`
	BudgetVerdict *economic.BudgetVerdictReceipt `json:"budget_verdict,omitempty"`
	Usage         *economic.UsageReceipt         `json:"usage,omitempty"`
	Settlement    *economic.SettlementReceipt    `json:"settlement,omitempty"`

	// EnvelopeClosed and EnvelopeClosedWindows are set on a settlement line
	// whose usage receipt closed envelope windows, as that receipt's metadata
	// names them, so a start closes them though the usage line never reached
	// the log (helm-tracker#313 r3, finding 1). They lie outside the signed
	// payload, so a start only ever closes windows by them.
	EnvelopeClosed        string   `json:"envelope_closed,omitempty"`
	EnvelopeClosedWindows []string `json:"envelope_closed_windows,omitempty"`
}

// payloadKinds names the payload each record kind carries.
var payloadKinds = map[RecordKind]string{
	RecordRouteQuote:       "route_quote",
	RecordBudgetVerdict:    "budget_verdict",
	RecordUsage:            "usage",
	RecordSettlement:       "settlement",
	RecordSettleFailed:     "route_quote",
	RecordDispatchReleased: "route_quote",
}

// Payload returns the receipt payload the record's Kind names, which is what
// its detached signature covers, or nil when the record does not carry it.
// Whatever else a record carries is never the payload (helm-tracker#313 r1,
// F1): a line cannot borrow another line's payload and signature.
func (r *ReceiptRecord) Payload() any {
	switch payloadKinds[r.Kind] {
	case "route_quote":
		if r.RouteQuote != nil {
			return r.RouteQuote
		}
	case "budget_verdict":
		if r.BudgetVerdict != nil {
			return r.BudgetVerdict
		}
	case "usage":
		if r.Usage != nil {
			return r.Usage
		}
	case "settlement":
		if r.Settlement != nil {
			return r.Settlement
		}
	}
	return nil
}

// checkPayload refuses a record whose kind is unknown, or that does not carry
// exactly the one payload its kind names.
func (r *ReceiptRecord) checkPayload() error {
	want, known := payloadKinds[r.Kind]
	if !known {
		return fmt.Errorf("unknown record kind %q", r.Kind)
	}
	var carried []string
	for name, set := range map[string]bool{
		"route_quote": r.RouteQuote != nil, "budget_verdict": r.BudgetVerdict != nil,
		"usage": r.Usage != nil, "settlement": r.Settlement != nil,
	} {
		if set {
			carried = append(carried, name)
		}
	}
	if len(carried) != 1 || carried[0] != want {
		sort.Strings(carried)
		return fmt.Errorf("a %s line must carry exactly its %s payload, and it carries %v", r.Kind, want, carried)
	}
	if r.Kind == RecordDispatchReleased {
		q := r.RouteQuote
		if q.Metadata[MetadataReleaseAction] != releaseActionV1 || strings.TrimSpace(q.Metadata[MetadataReleaseReason]) == "" {
			return errors.New("dispatch_released requires its signed release_action dispatch_released/v1 and release_reason")
		}
		if q.SpendIntentID == "" || r.SpendIntentID != q.SpendIntentID || q.TenantID == "" || r.TenantID != q.TenantID {
			return errors.New("dispatch_released tenant and intent must match the signed route quote")
		}
	}
	return nil
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
		if err := rec.checkPayload(); err != nil {
			return nil, fmt.Errorf("spendproxy: receipt log %s line %d: %w", path, lineNo, err)
		}
		out = append(out, rec)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("spendproxy: read receipt log: %w", err)
	}
	return out, nil
}

// bookKinds are the lines a start replays into the books that debit a hold,
// free one or close an envelope and set the floor reconcile settles at: a
// start accepts them only signed by a trusted key.
var bookKinds = map[RecordKind]bool{RecordUsage: true, RecordSettlement: true, RecordDispatchReleased: true, RecordSettleFailed: true}

// verifyBookLines refuses a log whose usage, settlement, dispatch_released or
// settle_failed line is unsigned, signed by a key trusted does not resolve, or
// whose signature does not verify (helm-tracker#313 r2, finding 9; r3, note
// 4): an unsigned release line appended to the log would otherwise free a
// pending hold on the next start, and a forged usage line would replace it
// with a smaller debit.
func verifyBookLines(records []*ReceiptRecord, trusted func(string) (ed25519.PublicKey, bool)) error {
	for i, rec := range records {
		if !bookKinds[rec.Kind] {
			continue
		}
		if err := rec.checkPayload(); err != nil {
			return fmt.Errorf("spendproxy: receipt log record %d: %w", i+1, err)
		}
		var problem string
		pub, known := trusted(rec.PayloadSignatureKeyID)
		switch {
		case rec.PayloadSignature == "" || rec.PayloadSignatureKeyID == "":
			problem = "is unsigned"
		case !known:
			problem = fmt.Sprintf("is signed by the key %q, which is neither the proxy's nor one its receipts directory registered", rec.PayloadSignatureKeyID)
		default:
			if err := verifyDetached(pub, rec.Payload(), rec.PayloadSignature); err != nil {
				problem = "has a signature that does not verify: " + err.Error()
			}
		}
		if problem != "" {
			return fmt.Errorf("spendproxy: receipt log record %d, a %s line of intent %s, %s; a start replays only signed lines that debit, free or close: refusing to start", i+1, rec.Kind, rec.SpendIntentID, problem)
		}
	}
	return nil
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
// already spent against the configured opening balance in prior runs: the
// debit of each intent's committed usage line (pairedUsage). A usage line
// without a settlement line is held instead (RestorePendingDispatches), and a
// usage line a reconcile settlement replaced is not counted again.
func DebitedCents(records []*ReceiptRecord) int64 {
	var total int64
	for _, rec := range pairedUsage(records) {
		total += rec.Usage.BalanceDebitCents
	}
	return total
}

// pairedUsage is, for each intent with a settlement line, its last usage
// line: the one ReplayRecords restores beside the last settlement line, whose
// debit the log committed. An earlier usage line of the intent is one whose
// settlement line was lost and that a reconcile settled again (helm-tracker#313
// r3, finding 1).
func pairedUsage(records []*ReceiptRecord) map[string]*ReceiptRecord {
	settled := make(map[string]bool)
	last := make(map[string]*ReceiptRecord)
	for _, rec := range records {
		switch {
		case rec.SpendIntentID == "":
		case rec.Kind == RecordSettlement:
			settled[rec.SpendIntentID] = true
		case rec.Kind == RecordUsage && rec.Usage != nil:
			last[rec.SpendIntentID] = rec
		}
	}
	for intent := range last {
		if !settled[intent] {
			delete(last, intent)
		}
	}
	return last
}

// restoreEnvelopeUse re-applies every committed debit in the log to the
// envelope window its usage receipt names, so a restarted proxy does not hand
// an envelope's limit out again (helm-tracker#313, audit H7), and closes again
// the windows a settlement above its hold closed, from every verified line
// that records them (r2, findings 2 and 3; r3, finding 1): a usage line,
// whether or not its settlement line reached the log; a settlement line,
// which names them too; and a settle_failed line's route quote. A usage or
// settlement line whose debit exceeds its journal line's hold also closes the
// window of the journal's time and the window it names, so a line that names
// none still closes; only journals that carry NoteDispatchJournal count, since
// a legacy journal's hold excluded the platform fee. A settlement line's
// closure members are unsigned, so it closes only its own journal's envelope. A receipt written before the windows were recorded
// books, and closes, the window of its line's time. A debit under an envelope
// the config no longer declares is not applied to any.
func restoreEnvelopeUse(records []*ReceiptRecord, ledger *inferencegateway.BalanceLedger, envelopes map[string]*economic.AgentSpendEnvelope) {
	paired := pairedUsage(records)
	journals := make(map[string]*ReceiptRecord)
	for _, rec := range records {
		var env *economic.AgentSpendEnvelope
		var window string
		var cents, debit int64
		var closed []string
		switch {
		case isDispatchJournal(rec):
			journals[rec.SpendIntentID] = rec
			continue
		case rec.Kind == RecordSettleFailed && rec.RouteQuote != nil:
			if env := envelopes[rec.RouteQuote.EnvelopeID]; env != nil {
				ledger.RestoreEnvelopeUse(env, rec.RecordedAt, "", 0, closedWindows(rec.RouteQuote.Metadata))
			}
			continue
		case rec.Kind == RecordUsage && rec.Usage != nil:
			env = envelopes[rec.Usage.EnvelopeID]
			meta := rec.Usage.Metadata
			closed = closedWindows(meta)
			if meta[inferencegateway.MetadataEnvelopeClosed] != "" && len(closed) == 0 {
				closed = []string{""} // a legacy receipt: the window of its line
			}
			window = meta[inferencegateway.MetadataEnvelopeWindow]
			debit = rec.Usage.BalanceDebitCents
			if paired[rec.SpendIntentID] == rec {
				cents = debit
			}
		case rec.Kind == RecordSettlement && rec.Settlement != nil:
			// The closure members sit outside the signed payload, so a line
			// closes only the envelope its own journal reserved (r4 review N4).
			if journal := journals[rec.SpendIntentID]; rec.EnvelopeClosed != "" && journal != nil && journal.RouteQuote.EnvelopeID == rec.EnvelopeClosed {
				env, closed = envelopes[rec.EnvelopeClosed], rec.EnvelopeClosedWindows
			}
			debit = settlementDebit(rec.Settlement)
		default:
			continue
		}
		if journal := journals[rec.SpendIntentID]; journal != nil {
			if env == nil {
				env = envelopes[journal.RouteQuote.EnvelopeID]
			}
			// Only a journal written since holds include the platform fee
			// carries NoteDispatchJournal; a legacy journal's quote excluded the
			// fee, so an ordinary bill exceeds it (r4 review N1).
			if env != nil && journal.Note == NoteDispatchJournal && debit > journal.RouteQuote.MaxAmountCents {
				closed = append(closed, inferencegateway.PeriodWindow(env.Period, journal.RecordedAt))
				if window != "" {
					closed = append(closed, window)
				}
			}
		}
		if env == nil {
			continue
		}
		ledger.RestoreEnvelopeUse(env, rec.RecordedAt, window, cents, legacyWindows(env, rec.RecordedAt, closed))
	}
}

// settlementDebit is what a settlement receipt debited: its debit entries.
func settlementDebit(settlement *economic.SettlementReceipt) int64 {
	var debit int64
	for _, entry := range settlement.LedgerEntries {
		if entry.Direction == economic.SettlementDebit {
			debit += entry.AmountCents
		}
	}
	return debit
}

// closedWindows reads the envelope windows a receipt's metadata names as
// closed.
func closedWindows(meta map[string]string) []string {
	if meta[inferencegateway.MetadataEnvelopeClosed] == "" || meta[inferencegateway.MetadataEnvelopeClosedWindows] == "" {
		return nil
	}
	return strings.Split(meta[inferencegateway.MetadataEnvelopeClosedWindows], ",")
}

// legacyWindows replaces the empty window of a legacy closure with the window
// of the time its line was written.
func legacyWindows(env *economic.AgentSpendEnvelope, at time.Time, windows []string) []string {
	for i, w := range windows {
		if w == "" {
			windows[i] = inferencegateway.PeriodWindow(env.Period, at)
		}
	}
	return windows
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
// journalled before its provider call that has no committed settlement and no
// release: the provider may have billed it, so its quote ceiling stays
// reserved against its envelope and the balance, pending reconciliation, and
// its idempotency key cannot dispatch again (audit M18). A settlement is
// committed only with both its usage and its settlement line (ReplayRecords
// restored it into the engine's ledger): a dispatch with one of them and not
// the other is held at its hold (helm-tracker#313 r1, F10), or at the actual
// cost the log records when that is more (r3, finding 1). A dispatch under an
// envelope the config no longer declares refuses the start: its cents would
// otherwise be forgotten.
func RestorePendingDispatches(records []*ReceiptRecord, engine *inferencegateway.Engine, envelopes map[string]*economic.AgentSpendEnvelope) ([]PendingDispatch, error) {
	// Read the log in order: a journal line opens a dispatch, and a release
	// closes the journal before it (a retry may journal the key again). The
	// engine leaves a key it holds a committed settlement for as it is.
	open := make(map[string]*ReceiptRecord)
	var order []string
	listed := make(map[string]bool)
	billed := make(map[string]bool)
	for _, rec := range records {
		switch {
		case rec.SpendIntentID == "":
		case rec.Kind == RecordDispatchReleased:
			delete(open, rec.SpendIntentID)
		case isDispatchJournal(rec):
			if !listed[rec.SpendIntentID] {
				listed[rec.SpendIntentID] = true
				order = append(order, rec.SpendIntentID)
			}
			open[rec.SpendIntentID] = rec
		case rec.Kind == RecordUsage || rec.Kind == RecordSettlement || rec.Kind == RecordSettleFailed:
			billed[rec.SpendIntentID] = true
		}
	}
	var out []PendingDispatch
	for _, intentID := range order {
		rec, pending := open[intentID]
		if !pending {
			continue
		}
		env := envelopes[rec.RouteQuote.EnvelopeID]
		if env == nil {
			return nil, fmt.Errorf("spendproxy: the log holds an unsettled dispatch %s under envelope %q, which the config no longer declares; refusing to start", rec.SpendIntentID, rec.RouteQuote.EnvelopeID)
		}
		hold := rec.RouteQuote.MaxAmountCents
		if billed[intentID] {
			// A failed settlement or an incomplete receipt pair records what
			// the provider billed, even when that liability exceeds the balance.
			actual, _ := recordedActual(records, intentID)
			hold = max(hold, actual)
		}
		res, err := engine.RestorePendingDispatch(env, rec.RouteQuote, rec.RecordedAt, hold)
		if err != nil {
			return nil, fmt.Errorf("spendproxy: hold unsettled dispatch %s: %w", rec.SpendIntentID, err)
		}
		if res != nil {
			out = append(out, PendingDispatch{Reservation: res, Quote: rec.RouteQuote, Journal: rec})
		}
	}
	return out, nil
}

// PendingDispatch is a dispatch held again on start, pending reconciliation:
// its hold, the route quote its journal line carries and the journal line,
// whose PayloadSignatureKeyID is the key that signed the dispatch.
type PendingDispatch struct {
	*inferencegateway.Reservation
	Quote   *economic.RouteQuote
	Journal *ReceiptRecord
}
