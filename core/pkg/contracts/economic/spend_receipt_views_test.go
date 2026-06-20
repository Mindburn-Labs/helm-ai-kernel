package economic

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// sensitivePrompt is a synthetic prompt body that must NEVER reach a business
// view or EvidencePack under the default redaction profile.
const sensitivePrompt = "PATIENT SSN 123-45-6789 diagnosis confidential"

func buildRouteQuoteWithPromptMetadata(t *testing.T) *RouteQuote {
	t.Helper()
	now := time.Date(2026, 6, 20, 12, 0, 0, 0, time.UTC)
	decision := newSpendAuthorityDecision(BudgetVerdictAllow, SpendReasonOKWithinEnvelope, "within envelope", 50_000, "sha256:env")
	q := NewRouteQuote(
		"rq-1", "tenant-1", "intent-1", "env-1", "agent-1",
		ModelRoute{ProviderID: "openai", ModelID: "gpt-4o", PriceSnapshotHash: "sha256:price"},
		1_500, 3_000, "USD", "sha256:route-policy", now.Add(time.Hour), decision,
	)
	q.PrincipalID = "user:alice"
	q.RequestedProviderID = "openai"
	q.FallbackChain = []ModelRoute{{ProviderID: "anthropic", ModelID: "claude-haiku", PriceSnapshotHash: "sha256:price-ah"}}
	// Operator metadata that includes a prompt body plus a benign key. The
	// benign key must survive; the prompt-bearing keys must be redacted.
	q.Metadata = map[string]string{
		"prompt_body":     sensitivePrompt,
		"prompt":          sensitivePrompt,
		"messages":        sensitivePrompt,
		"request_body":    sensitivePrompt,
		"workspace_label": "finance-q2",
	}
	q.Reseal()
	return q
}

func TestDefaultRedactionProfile_KeepsPromptBodyOffGraph(t *testing.T) {
	q := buildRouteQuoteWithPromptMetadata(t)
	view := NewRouteReceiptView(q, DefaultRedactionProfile())

	// Benign metadata survives.
	if view.Metadata["workspace_label"] != "finance-q2" {
		t.Fatalf("expected benign metadata to survive, got %#v", view.Metadata)
	}
	// Prompt-bearing keys are stripped.
	for _, banned := range []string{"prompt_body", "prompt", "messages", "request_body"} {
		if _, ok := view.Metadata[banned]; ok {
			t.Fatalf("metadata key %q must be redacted, view metadata: %#v", banned, view.Metadata)
		}
	}
	// The redacted-fields audit trail records exactly what was stripped.
	if len(view.RedactedFields) != 4 {
		t.Fatalf("expected 4 redacted fields, got %v", view.RedactedFields)
	}

	// Hard guarantee: the marshaled view must not contain the prompt body bytes.
	blob, err := json.Marshal(view)
	if err != nil {
		t.Fatalf("marshal view: %v", err)
	}
	if strings.Contains(string(blob), "123-45-6789") {
		t.Fatalf("prompt body leaked into RouteReceiptView JSON: %s", blob)
	}
	if view.RedactionPolicy != "default-prompt-off-graph" {
		t.Fatalf("unexpected redaction policy name: %s", view.RedactionPolicy)
	}
}

func TestUsageReceiptView_RedactsPromptMetadataAndDerivesSettlement(t *testing.T) {
	r := NewUsageReceipt("ur-1", "tenant-1", "rq-1", "intent-1", "env-1", "agent-1", "openai", "gpt-4o", 1_500, 1_000, 100, "USD", "sha256:policy", "evidence://ur-1")
	r.ProviderRequestID = "prov-req-1"
	r.ProviderPriceSnapshotHash = "sha256:price"
	r.Metadata = map[string]string{
		"completion_body": sensitivePrompt,
		"region":          "us-east-1",
	}
	r.Reseal()

	view := NewUsageReceiptView(r, DefaultRedactionProfile())
	if view.SettledVia != "BALANCE_DEBIT" {
		t.Fatalf("expected BALANCE_DEBIT, got %s", view.SettledVia)
	}
	if view.ProviderCostCents != 1_000 || view.PlatformFeeCents != 100 || view.ActualAmountCents != 1_100 {
		t.Fatalf("cost breakdown wrong: %+v", view)
	}
	if _, ok := view.Metadata["completion_body"]; ok {
		t.Fatalf("completion_body must be redacted: %#v", view.Metadata)
	}
	if view.Metadata["region"] != "us-east-1" {
		t.Fatalf("benign region metadata must survive: %#v", view.Metadata)
	}
	blob, _ := json.Marshal(view)
	if strings.Contains(string(blob), "123-45-6789") {
		t.Fatalf("prompt body leaked into UsageReceiptView: %s", blob)
	}
}

func TestUsageReceiptView_InvoiceAccrualWhenNoDebit(t *testing.T) {
	r := NewUsageReceipt("ur-2", "tenant-1", "rq-2", "intent-2", "env-1", "agent-1", "openai", "gpt-4o", 1_500, 1_000, 100, "USD", "sha256:policy", "evidence://ur-2")
	r.BalanceDebitCents = 0 // invoice accrual path
	r.Reseal()
	view := NewUsageReceiptView(r, DefaultRedactionProfile())
	if view.SettledVia != "INVOICE_ACCRUAL" {
		t.Fatalf("expected INVOICE_ACCRUAL when no balance debit, got %s", view.SettledVia)
	}
}

func TestBudgetVerdictView_EscalateSurfacesApprovers(t *testing.T) {
	decision := newSpendAuthorityDecision(BudgetVerdictEscalate, SpendReasonApprovalRequired, "needs approval", 0, "sha256:env")
	r := NewBudgetVerdictReceipt("bv-1", "tenant-1", "intent-1", "env-1", "agent-1", "openai", "gpt-4o", 1_500, 3_000, "USD", "sha256:price", "sha256:route-policy", "evidence://bv-1", decision)
	r.PrincipalID = "user:alice"

	view := NewBudgetVerdictView(r, []string{"role:finance-approver"}, DefaultRedactionProfile())
	if view.Verdict != "ESCALATE" {
		t.Fatalf("expected ESCALATE, got %s", view.Verdict)
	}
	if !view.ApprovalNeeded {
		t.Fatalf("expected ApprovalNeeded for ESCALATE")
	}
	if len(view.Approvers) != 1 || view.Approvers[0] != "role:finance-approver" {
		t.Fatalf("expected approver surfaced, got %v", view.Approvers)
	}
	if view.EnvelopeHash != "sha256:env" || view.RoutePolicyHash != "sha256:route-policy" {
		t.Fatalf("policy/envelope hashes not surfaced: %+v", view)
	}
	if view.DecisionHash != decision.ContentHash {
		t.Fatalf("decision hash not bound: %s vs %s", view.DecisionHash, decision.ContentHash)
	}
}

func TestSettlementReceiptView_SumsMovementsAndCorrectionRefs(t *testing.T) {
	entries := []SettlementLedgerEntry{
		{ID: "le-1", AccountID: "balance-1", Direction: SettlementDebit, AmountCents: 1_100, Currency: "USD", Reference: "usage:ur-1"},
		{ID: "le-2", AccountID: "treasury-1", Direction: SettlementCredit, AmountCents: 1_100, Currency: "USD", Reference: "usage:ur-1"},
	}
	s := NewSettlementReceipt("st-1", "tenant-1", "ur-1", "rq-1", "treasury-1", "sha256:usage", "USD", "evidence://st-1", entries)

	view := NewSettlementReceiptView(s, DefaultRedactionProfile())
	if !view.Balanced {
		t.Fatalf("expected balanced settlement view")
	}
	if view.TotalDebits != 1_100 || view.TotalCredits != 1_100 {
		t.Fatalf("debit/credit totals wrong: %+v", view)
	}
	if len(view.LedgerMovements) != 2 {
		t.Fatalf("expected 2 ledger movements, got %d", len(view.LedgerMovements))
	}
	// Correction reference: the source usage receipt hash links the settlement
	// back to the usage it settles (the audit "what proves it" anchor).
	if view.SourceUsageReceiptHash != "sha256:usage" || view.UsageReceiptID != "ur-1" {
		t.Fatalf("correction/source refs not surfaced: %+v", view)
	}
}

// TestWiderProfile_PromptOffByPolicyChoice documents that a non-default profile
// (for an internal, access-controlled surface) can keep metadata the default
// strips, but explicitly denied keys still go regardless.
func TestWiderProfile_PromptOffByPolicyChoice(t *testing.T) {
	q := buildRouteQuoteWithPromptMetadata(t)
	// A profile that does NOT redact prompt body: only explicitly denied keys go.
	wide := RedactionProfile{Name: "internal-wide", RedactPromptBody: false, DeniedMetadataKeys: []string{"prompt_body"}}
	view := NewRouteReceiptView(q, wide)
	if _, ok := view.Metadata["prompt_body"]; ok {
		t.Fatalf("explicitly denied key must still be stripped")
	}
	// Substring-only keys are retained under the wide profile by policy choice.
	if _, ok := view.Metadata["messages"]; !ok {
		t.Fatalf("wide profile should retain messages metadata, got %#v", view.Metadata)
	}
}
