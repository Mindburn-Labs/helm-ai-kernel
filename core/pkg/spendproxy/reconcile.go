// quantum_posture: reconcile signs the receipt lines it appends with the
// spend proxy's classical Ed25519 issuer key (issuer.go); no post-quantum
// primitive is used in this file.

package spendproxy

import (
	"errors"
	"fmt"
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
	// must be signed by the key that signed the dispatch.
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
	Logf   func(format string, args ...any)
}

// ReconcileResult reports one reconciled dispatch.
type ReconcileResult struct {
	SpendIntentID string `json:"spend_intent_id"`
	Action        string `json:"action"`
	HoldCents     int64  `json:"hold_cents"`
	DebitedCents  int64  `json:"debited_cents"`
	Reason        string `json:"reason"`
}

// The metadata keys of a reconciled settlement's usage receipt.
const (
	MetadataReconciledBy     = "reconciled_by"
	MetadataReconcileReason  = "reconcile_reason"
	reconciledByOperator     = "operator"
	reconcileActionSettled   = "settled"
	reconcileActionReleased  = "released"
	reconcileReleasePrefix   = "operator: "
	reconcileProviderIDStart = "reconciled-"
)

// PendingDispatches lists the dispatches a start would hold again, pending
// reconciliation, from the config and the receipt log.
func PendingDispatches(opts ReconcileOptions) ([]PendingDispatch, error) {
	st, err := rebuildState(ServerOptions{Config: opts.Config, SourceHash: opts.SourceHash, ReceiptsDir: opts.ReceiptsDir, Logf: opts.Logf})
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
// replays it. Run it while the proxy is stopped: a running proxy does not see
// the lines until it restarts.
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
	// Check the intent and the key before anything is written.
	pendingList, err := PendingDispatches(opts)
	if err != nil {
		return nil, err
	}
	found, err := findPending(pendingList, opts)
	if err != nil {
		return nil, err
	}
	issuer, _, err := NewIssuer(opts.SigningSecret)
	if err != nil {
		return nil, err
	}
	if signer := journalSigner(opts.ReceiptsDir, found.Quote); signer != issuer.KeyID() {
		return nil, fmt.Errorf("spendproxy: the dispatch was signed by key %q and the signing seed is key %s: reconcile with the proxy's own seed", signer, issuer.KeyID())
	}
	s, err := openServer(ServerOptions{Config: opts.Config, SourceHash: opts.SourceHash, ReceiptsDir: opts.ReceiptsDir, SigningSecret: opts.SigningSecret, Logf: opts.Logf})
	if err != nil {
		return nil, err
	}
	defer s.Close()
	pending, err := findPending(s.pending, opts)
	if err != nil {
		return nil, err
	}
	quote := pending.Quote
	result := &ReconcileResult{SpendIntentID: opts.SpendIntentID, HoldCents: pending.AmountCents, Reason: opts.Reason}
	if opts.Release {
		if _, err := s.engine.ReleaseReservation(quote); err != nil {
			return nil, fmt.Errorf("spendproxy: release %s: %w", opts.SpendIntentID, err)
		}
		if err := s.appendSigned(releaseRecord(quote, reconcileReleasePrefix+opts.Reason)); err != nil {
			return nil, err
		}
		result.Action = reconcileActionReleased
		return result, nil
	}
	settled, err := s.engine.SettleUsage(quote, inferencegateway.Usage{
		ProviderRequestID: reconcileProviderIDStart + quote.ID,
		ProviderCostCents: opts.SettleCents,
		Notes:             map[string]string{MetadataReconciledBy: reconciledByOperator, MetadataReconcileReason: opts.Reason},
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

func findPending(list []PendingDispatch, opts ReconcileOptions) (*PendingDispatch, error) {
	for i := range list {
		if list[i].Quote.SpendIntentID == opts.SpendIntentID {
			return &list[i], nil
		}
	}
	return nil, fmt.Errorf("spendproxy: intent %s holds no pending dispatch in %s", opts.SpendIntentID, opts.ReceiptsDir)
}

// journalSigner is the key id that signed the dispatch's journal line.
func journalSigner(receiptsDir string, quote *economic.RouteQuote) string {
	records, err := LoadRecords(receiptLogPath(receiptsDir))
	if err != nil {
		return ""
	}
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
