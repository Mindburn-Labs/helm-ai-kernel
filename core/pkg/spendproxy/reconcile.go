// quantum_posture: reconcile signs the receipt lines it appends with the
// spend proxy's classical Ed25519 issuer key (issuer.go); no post-quantum
// primitive is used in this file.

package spendproxy

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts/economic"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/inferencegateway"
)

// ReconcileOptions name a pending dispatch and what an operator found
// (helm-tracker#313 r1, F11). Exactly one of SettleCents and Release is set.
type ReconcileOptions struct {
	Config      *Config
	SourceHash  string
	ReceiptsDir string
	// SigningSecret is the proxy's signing seed: the lines reconcile appends
	// must be signed by the key that signed the dispatch. Empty signs with
	// the seed the proxy generated in ReceiptsDir (SigningSeedFileName).
	SigningSecret string
	// SpendIntentID names the pending dispatch; empty lists them.
	SpendIntentID string
	// SettleCents is the provider cost, in cents, the operator settles the
	// dispatch at (the platform fee is added as on any settlement).
	SettleCents int64
	// Release frees the hold: the operator found that the provider did not
	// bill the dispatch.
	Release bool
	// Reason is why, recorded and signed with the line.
	Reason string
	// OverrideReason lets SettleCents debit less than the actual cost the log
	// records the provider billed (a settle_failed, usage or settlement line
	// of the intent); it is recorded and signed on the usage receipt as
	// reconcile_override_reason. Without it such a settlement is refused.
	OverrideReason string
	Logf           func(format string, args ...any)
}

// ReconcileResult reports one reconciled dispatch. RecordedActualCents is the
// actual cost the log recorded for it, 0 when it recorded none, and
// OverrideReason the override a settlement below it was made under.
type ReconcileResult struct {
	SpendIntentID       string `json:"spend_intent_id"`
	Action              string `json:"action"`
	HoldCents           int64  `json:"hold_cents"`
	DebitedCents        int64  `json:"debited_cents"`
	Reason              string `json:"reason"`
	RecordedActualCents int64  `json:"recorded_actual_cents,omitempty"`
	OverrideReason      string `json:"override_reason,omitempty"`
}

// The metadata keys of a reconciled settlement's usage receipt.
const (
	MetadataReconciledBy      = "reconciled_by"
	MetadataReconcileReason   = "reconcile_reason"
	MetadataReconcileOverride = "reconcile_override_reason"
	reconciledByOperator      = "operator"
	reconcileActionSettled    = "settled"
	reconcileActionReleased   = "released"
	reconcileReleasePrefix    = "operator: "
	reconcileProviderIDStart  = "reconciled-"
)

// PendingDispatches lists the dispatches a start would hold again, pending
// reconciliation, from the config and the receipt log.
func PendingDispatches(opts ReconcileOptions) ([]PendingDispatch, error) {
	keys, err := OpenTrustedKeys(opts.ReceiptsDir)
	if err != nil {
		return nil, err
	}
	st, err := rebuildState(ServerOptions{Config: opts.Config, SourceHash: opts.SourceHash, ReceiptsDir: opts.ReceiptsDir, Logf: opts.Logf}, trustedKeyResolver(keys, nil))
	if err != nil {
		return nil, err
	}
	return st.pending, nil
}

// Reconcile clears one pending dispatch: it settles it at the stated provider
// cost, as usage and settlement receipts whose usage metadata names the
// operator and the reason, or releases it with a dispatch_released line whose
// route quote carries the reason. Every line is signed by the issuer key that
// signed the dispatch and appended to the receipt log, so the next start
// replays it. It takes the receipts directory's lock, so it refuses to run
// beside a live proxy (helm-tracker#313 r2, finding 14).
//
// A dispatch the log records the provider billed (a settle_failed, usage or
// settlement line of its intent) is not released, and it is settled at no
// less than the recorded actual cost unless OverrideReason says why
// (finding 4).
func Reconcile(opts ReconcileOptions) (*ReconcileResult, error) {
	if opts.SpendIntentID == "" {
		return nil, errors.New("spendproxy: reconcile needs the spend intent of a pending dispatch")
	}
	if opts.Release == (opts.SettleCents > 0) {
		return nil, errors.New("spendproxy: reconcile settles at a positive amount or releases, exactly one of them")
	}
	if strings.TrimSpace(opts.Reason) == "" {
		return nil, errors.New("spendproxy: reconcile needs the reason the operator records")
	}
	// Check the intent, the key and the log's evidence before anything is
	// written; openServer writes only its lock file.
	s, err := openServer(ServerOptions{Config: opts.Config, SourceHash: opts.SourceHash, ReceiptsDir: opts.ReceiptsDir, SigningSecret: opts.SigningSecret, Logf: opts.Logf}, false)
	if err != nil {
		return nil, err
	}
	defer s.Close()
	pending, err := findPending(s.pending, opts)
	if err != nil {
		return nil, err
	}
	records, err := LoadRecords(receiptLogPath(opts.ReceiptsDir))
	if err != nil {
		return nil, err
	}
	quote := pending.Quote
	if signer := journalSigner(records, quote); signer != s.issuer.KeyID() {
		return nil, fmt.Errorf("spendproxy: the dispatch was signed by key %q and the signing seed is key %s: reconcile with the proxy's own seed", signer, s.issuer.KeyID())
	}
	actual, evidence := recordedActual(records, quote.SpendIntentID)
	result := &ReconcileResult{SpendIntentID: opts.SpendIntentID, HoldCents: pending.AmountCents, Reason: opts.Reason, RecordedActualCents: actual}
	if opts.Release {
		if evidence != "" {
			return nil, fmt.Errorf("spendproxy: the log records that the provider billed intent %s (%s, %d cents): it is not released; settle it with --settle-cents", opts.SpendIntentID, evidence, actual)
		}
		if _, err := s.engine.ReleaseReservation(quote); err != nil {
			return nil, fmt.Errorf("spendproxy: release %s: %w", opts.SpendIntentID, err)
		}
		if err := s.appendSigned(releaseRecord(quote, reconcileReleasePrefix+opts.Reason)); err != nil {
			return nil, err
		}
		result.Action = reconcileActionReleased
		return result, nil
	}
	debit, err := s.engine.DebitFor(quote, opts.SettleCents)
	if err != nil {
		return nil, fmt.Errorf("spendproxy: settle %s: %w", opts.SpendIntentID, err)
	}
	notes := map[string]string{MetadataReconciledBy: reconciledByOperator, MetadataReconcileReason: opts.Reason}
	if debit < actual {
		if strings.TrimSpace(opts.OverrideReason) == "" {
			return nil, fmt.Errorf("spendproxy: --settle-cents %d debits %d cents, below the %d cents the log records the provider billed intent %s (%s): settle at the recorded actual, or give an override reason", opts.SettleCents, debit, actual, opts.SpendIntentID, evidence)
		}
		notes[MetadataReconcileOverride] = opts.OverrideReason
		result.OverrideReason = opts.OverrideReason
	}
	settled, err := s.engine.SettleUsage(quote, inferencegateway.Usage{
		ProviderRequestID: reconcileProviderIDStart + quote.ID,
		ProviderCostCents: opts.SettleCents,
		Notes:             notes,
	})
	if err != nil {
		return nil, fmt.Errorf("spendproxy: settle %s: %w", opts.SpendIntentID, err)
	}
	for _, rec := range settlementRecords(settled.UsageReceipt, settled.SettlementReceipt, settled.BalanceAfterCents, "reconciled by the operator: "+opts.Reason) {
		if err := s.appendSigned(rec); err != nil {
			return nil, err
		}
	}
	result.Action, result.DebitedCents = reconcileActionSettled, settled.BalanceDebitCents
	return result, nil
}

// legacySettleFailedActual reads the actual cost from the note of a
// settle_failed line written before the line carried it signed.
var legacySettleFailedActual = regexp.MustCompile(`actual (\d+) cents not debited`)

// recordedActual is the most the log records the provider billed for an
// intent, and what recorded it: a settle_failed line (its route quote's
// MetadataActualCents, or for a line written before that, its note), a usage
// line's actual cost or a settlement line's debit. evidence is empty when the
// log records no bill.
func recordedActual(records []*ReceiptRecord, intent string) (int64, string) {
	var actual int64
	evidence := ""
	note := func(cents int64, what string) {
		if evidence == "" || cents > actual {
			actual, evidence = max(actual, cents), what
		}
	}
	for _, rec := range records {
		if rec.SpendIntentID != intent {
			continue
		}
		switch {
		case rec.Kind == RecordSettleFailed && rec.RouteQuote != nil:
			cents, err := strconv.ParseInt(rec.RouteQuote.Metadata[MetadataActualCents], 10, 64)
			if err != nil {
				if m := legacySettleFailedActual.FindStringSubmatch(rec.Note); m != nil {
					cents, _ = strconv.ParseInt(m[1], 10, 64)
				}
			}
			note(cents, "a settle_failed line")
		case rec.Kind == RecordUsage && rec.Usage != nil:
			note(rec.Usage.ActualAmountCents, "a usage line")
		case rec.Kind == RecordSettlement && rec.Settlement != nil:
			var debit int64
			for _, entry := range rec.Settlement.LedgerEntries {
				if entry.Direction == economic.SettlementDebit {
					debit += entry.AmountCents
				}
			}
			note(debit, "a settlement line")
		}
	}
	return actual, evidence
}

func findPending(list []PendingDispatch, opts ReconcileOptions) (*PendingDispatch, error) {
	for i := range list {
		if list[i].Quote.SpendIntentID == opts.SpendIntentID {
			return &list[i], nil
		}
	}
	return nil, fmt.Errorf("spendproxy: intent %s holds no pending dispatch in %s", opts.SpendIntentID, opts.ReceiptsDir)
}

// journalSigner is the key id that signed the dispatch's journal line.
func journalSigner(records []*ReceiptRecord, quote *economic.RouteQuote) string {
	signer := ""
	for _, rec := range records {
		if rec.SpendIntentID == quote.SpendIntentID && isDispatchJournal(rec) {
			signer = rec.PayloadSignatureKeyID
		}
	}
	return signer
}

// appendSigned signs a line and appends it, failing on either.
func (s *Server) appendSigned(rec *ReceiptRecord) error {
	if err := s.signRecord(rec); err != nil {
		return fmt.Errorf("spendproxy: sign %s line: %w", rec.Kind, err)
	}
	if err := s.store.Append(rec); err != nil {
		return fmt.Errorf("spendproxy: append %s line: %w", rec.Kind, err)
	}
	return nil
}

// settlementRecords are the usage and settlement lines of a settlement.
func settlementRecords(usage *economic.UsageReceipt, settlement *economic.SettlementReceipt, balanceAfter int64, note string) []*ReceiptRecord {
	return []*ReceiptRecord{
		{Kind: RecordUsage, TenantID: usage.TenantID, SpendIntentID: usage.SpendIntentID, BalanceAfterCents: balanceAfter, Note: note, Usage: usage},
		{Kind: RecordSettlement, TenantID: settlement.TenantID, SpendIntentID: usage.SpendIntentID, Settlement: settlement},
	}
}
