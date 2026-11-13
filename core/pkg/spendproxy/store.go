// Legacy receipt records are read only for offline export and verification.
// quantum_posture: export.go verifies the historical classical Ed25519
// signatures; these records never authorize a live dispatch or reconciliation.

package spendproxy

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts/economic"
)

// RecordKind classifies one line in a historical receipt log.
type RecordKind string

const (
	// RecordRouteQuote was recorded before dispatch or for a denied quote.
	RecordRouteQuote RecordKind = "route_quote"
	// RecordBudgetVerdict is the Ed25519-signed pre-dispatch spend receipt.
	RecordBudgetVerdict RecordKind = "budget_verdict"
	// RecordUsage is the post-dispatch actual-usage receipt.
	RecordUsage RecordKind = "usage"
	// RecordSettlement is the balanced double-entry settlement receipt.
	RecordSettlement RecordKind = "settlement"
	// RecordSettleFailed records a historical settlement failure. The export
	// does not treat it as a successful settlement or recreate a live hold.
	RecordSettleFailed RecordKind = "settle_failed"
	// RecordDispatchReleased records a historical release. Its route quote
	// binds the versioned release action, reason, tenant and intent. Reading
	// it grants no authority to release or retry a live gateway attempt.
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
	// BalanceAfterCents is historical display data, never a live balance.
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

	// Legacy closure hints are retained for decoding only. They are unsigned
	// and never used to derive live authority or an export signature verdict.
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
	var tenant, intent string
	hasIntent := true
	switch {
	case r.RouteQuote != nil:
		tenant, intent = r.RouteQuote.TenantID, r.RouteQuote.SpendIntentID
	case r.BudgetVerdict != nil:
		tenant, intent = r.BudgetVerdict.TenantID, r.BudgetVerdict.SpendIntentID
	case r.Usage != nil:
		tenant, intent = r.Usage.TenantID, r.Usage.SpendIntentID
	case r.Settlement != nil:
		tenant, hasIntent = r.Settlement.TenantID, false
	}
	if tenant == "" || r.TenantID != tenant || (hasIntent && (intent == "" || r.SpendIntentID != intent)) {
		return errors.New("receipt record identity must match its signed payload")
	}
	if r.Kind == RecordDispatchReleased {
		q := r.RouteQuote
		if q.Metadata[MetadataReleaseAction] != releaseActionV1 || strings.TrimSpace(q.Metadata[MetadataReleaseReason]) == "" {
			return errors.New("dispatch_released requires its signed release_action dispatch_released/v1 and release_reason")
		}
	}
	return nil
}

// ReceiptLogName is the stable file name of the append-only receipt log inside
// a receipts directory. A single file (rather than per-day files) keeps restart
// replay trivially complete.
const ReceiptLogName = "spend-receipts.jsonl"

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
