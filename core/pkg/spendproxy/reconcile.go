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
	// SigningSecret is the proxy's signing seed, whose key signs the lines
	// reconcile appends: the key that signed the dispatch, or, when that key
	// is another (a lost or changed seed), a key trusted_keys.json registers.
	// Empty signs with the seed the proxy generated in ReceiptsDir
	// (SigningSeedFileName).
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
	// JournalKeyReason lets reconcile sign for a dispatch whose journal line
	// is unsigned or signed by a key trusted_keys.json does not register (the
	// seed and the registry were lost); it is recorded and signed on the line
	// as reconcile_journal_key_reason. Without it such a dispatch is refused.
	JournalKeyReason string
	Logf             func(format string, args ...any)
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

// MetadataReconcileJournalKey names, on a line reconcile signs for a dispatch
// journalled under another key, the key that signed its journal line (empty
// when it was unsigned); MetadataReconcileJournalKeyReason is the operator's
// JournalKeyReason, when one cleared it (helm-tracker#313 r3, finding 2).
const (
	MetadataReconcileJournalKey       = "reconcile_journal_key_id"
	MetadataReconcileJournalKeyReason = "reconcile_journal_key_reason"
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
// route quote carries the reason. Every line is signed by the key of the
// signing seed and appended to the receipt log, so the next start replays it;
// a dispatch journalled under another key is cleared only as journalKeyNotes
// allows (helm-tracker#313 r3, finding 2). It takes the receipts directory's
// lock, so it refuses to run beside a live proxy (r2, finding 14).
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
	keyNotes, err := s.journalKeyNotes(pending, opts.JournalKeyReason)
	if err != nil {
		return nil, err
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
		release := releaseRecord(quote, reconcileReleasePrefix+opts.Reason)
		for k, v := range keyNotes {
			release.RouteQuote.Metadata[k] = v
		}
		if err := s.appendSigned(release); err != nil {
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
	for k, v := range keyNotes {
		notes[k] = v
	}
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
			note(settlementDebit(rec.Settlement), "a settlement line")
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

// journalKeyNotes decides whether reconcile signs for a pending dispatch with
// the signing seed's key, and returns what the line it signs records about the
// key that signed the dispatch's journal line (helm-tracker#313 r3, finding
// 2). A dispatch journalled under the seed's key needs nothing. One journalled
// under another key, as after the seed was lost or changed, or by a proxy run
// without --sign before the seed was generated, needs the seed's key to be one
// trusted_keys.json registers, so the next start accepts the line whatever
// seed it runs with; and the journal's key registered there with the journal
// line verifying against it, or the operator's reason for clearing it anyway.
// The line then names the journal's key, and the reason.
func (s *Server) journalKeyNotes(p *PendingDispatch, reason string) (map[string]string, error) {
	journalKey, signer := p.Journal.PayloadSignatureKeyID, s.issuer.KeyID()
	if journalKey == signer {
		return nil, nil
	}
	if _, registered := s.keys.PublicKeyFor(signer); !registered {
		return nil, fmt.Errorf("spendproxy: the dispatch was %s and the signing seed is key %s, which %s does not register: reconcile with the seed the proxy runs with", signedBy(journalKey), signer, TrustedKeyFileName)
	}
	notes := map[string]string{MetadataReconcileJournalKey: journalKey}
	if strings.TrimSpace(reason) != "" {
		notes[MetadataReconcileJournalKeyReason] = reason
		return notes, nil
	}
	pub, registered := s.keys.PublicKeyFor(journalKey)
	if !registered {
		return nil, fmt.Errorf("spendproxy: the dispatch was %s, which %s does not register, and the signing seed is key %s: reconcile with the seed that signed it, or give the journal key reason (--journal-key-reason) the line records", signedBy(journalKey), TrustedKeyFileName, signer)
	}
	if err := verifyDetached(pub, p.Journal.Payload(), p.Journal.PayloadSignature); err != nil {
		return nil, fmt.Errorf("spendproxy: the journal line of intent %s does not verify against key %q, which %s registers: %v; give the journal key reason (--journal-key-reason) to clear it anyway", p.Quote.SpendIntentID, journalKey, TrustedKeyFileName, err)
	}
	return notes, nil
}

// signedBy says which key signed a journal line.
func signedBy(keyID string) string {
	if keyID == "" {
		return "journalled unsigned"
	}
	return fmt.Sprintf("signed by key %q", keyID)
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

// settlementRecords are the usage and settlement lines of a settlement. The
// settlement line names the envelope windows the usage receipt closed.
func settlementRecords(usage *economic.UsageReceipt, settlement *economic.SettlementReceipt, balanceAfter int64, note string) []*ReceiptRecord {
	settled := &ReceiptRecord{Kind: RecordSettlement, TenantID: settlement.TenantID, SpendIntentID: usage.SpendIntentID, Settlement: settlement}
	if closed := closedWindows(usage.Metadata); len(closed) > 0 {
		settled.EnvelopeClosed, settled.EnvelopeClosedWindows = usage.Metadata[inferencegateway.MetadataEnvelopeClosed], closed
	}
	return []*ReceiptRecord{
		{Kind: RecordUsage, TenantID: usage.TenantID, SpendIntentID: usage.SpendIntentID, BalanceAfterCents: balanceAfter, Note: note, Usage: usage},
		settled,
	}
}
