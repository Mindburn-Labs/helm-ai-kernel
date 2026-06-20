package evidencepack

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts/economic"
)

// buildSpendReceiptSet builds a fully-linked, valid set of SPEND3/5 receipts the
// same way the inferencegateway engine does (mutual settlement<->usage hash
// binding), so the offline verifier is exercised against realistic receipts.
func buildSpendReceiptSet(t *testing.T) SpendReceiptSet {
	t.Helper()
	now := time.Date(2026, 6, 20, 12, 0, 0, 0, time.UTC)

	decision := economicAllow(50_000, "sha256:env")
	quote := economic.NewRouteQuote(
		"rq-1", "tenant-1", "intent-1", "env-1", "agent-1",
		economic.ModelRoute{ProviderID: "openai", ModelID: "gpt-4o", PriceSnapshotHash: "sha256:price"},
		1_500, 3_000, "USD", "sha256:route-policy", now.Add(time.Hour), decision,
	)
	quote.PrincipalID = "user:alice"
	quote.Reseal()

	budget := economic.NewBudgetVerdictReceipt(
		"bv-1", "tenant-1", "intent-1", "env-1", "agent-1", "openai", "gpt-4o",
		1_500, 3_000, "USD", "sha256:price", "sha256:route-policy", "evidence://pack-1", decision,
	)

	usage := economic.NewUsageReceipt(
		"ur-1", "tenant-1", "rq-1", "intent-1", "env-1", "agent-1", "openai", "gpt-4o",
		1_500, 1_000, 100, "USD", "sha256:policy", "evidence://pack-1",
	)
	usage.ProviderRequestID = "prov-req-1"
	usage.ProviderPriceSnapshotHash = "sha256:price"

	entries := []economic.SettlementLedgerEntry{
		{ID: "sle-ur-1-debit", AccountID: "balance-1", Direction: economic.SettlementDebit, AmountCents: usage.BalanceDebitCents, Currency: "USD", Reference: "balance:balance-1"},
		{ID: "sle-ur-1-credit", AccountID: "treasury-1", Direction: economic.SettlementCredit, AmountCents: usage.BalanceDebitCents, Currency: "USD", Reference: "treasury:treasury-1"},
	}
	settlement := economic.NewSettlementReceipt("settle-ur-1", "tenant-1", "ur-1", "rq-1", "treasury-1", usage.ContentHash, "USD", "evidence://pack-1", entries)

	// Mirror the engine's mutual binding order.
	usage.LedgerEntryIDs = []string{entries[0].ID, entries[1].ID}
	usage.SettlementReceiptHash = settlement.ContentHash
	usage.Reseal()
	settlement.SourceUsageReceiptHash = usage.ContentHash
	settlement.Reseal()

	return SpendReceiptSet{RouteQuote: quote, Budget: budget, Usage: usage, Settlement: settlement}
}

// economicAllow builds an ALLOW spend decision with a canonical content hash.
func economicAllow(remaining int64, envHash string) economic.SpendAuthorityDecision {
	d := economic.SpendAuthorityDecision{
		Verdict:        economic.BudgetVerdictAllow,
		ReasonCode:     economic.SpendReasonOKWithinEnvelope,
		Reason:         "within envelope",
		RemainingCents: remaining,
		EnvelopeHash:   envHash,
	}
	d.ContentHash = d.CanonicalContentHash()
	return d
}

func TestBuildAndVerifySpendEvidenceOffline(t *testing.T) {
	set := buildSpendReceiptSet(t)
	manifest, contents, err := BuildSpendEvidencePack("pack-1", "did:helm:agent-1", "intent-1", "sha256:route-policy", set, economic.DefaultRedactionProfile())
	if err != nil {
		t.Fatalf("build pack: %v", err)
	}
	if manifest.ManifestHash == "" {
		t.Fatalf("expected manifest hash")
	}

	res, err := VerifySpendEvidenceOffline(contents)
	if err != nil {
		t.Fatalf("offline verify failed: %v", err)
	}
	if !res.OK || !res.Offline || !res.PromptBodyOffGraph {
		t.Fatalf("unexpected verification result: %+v", res)
	}
	if len(res.ReceiptsVerified) != 4 {
		t.Fatalf("expected 4 receipts verified, got %v", res.ReceiptsVerified)
	}
	// Financial invariants must have been re-checked offline.
	mustContain(t, res.InvariantsChecked, "usage.actual==provider_cost+platform_fee")
	mustContain(t, res.InvariantsChecked, "settlement.debits==credits")
	mustContain(t, res.InvariantsChecked, "settlement.binds_usage_receipt_hash")
}

func TestVerifySpendEvidenceOffline_DeterministicArchiveRoundTrip(t *testing.T) {
	set := buildSpendReceiptSet(t)
	_, contents, err := BuildSpendEvidencePack("pack-1", "did:helm:agent-1", "intent-1", "sha256:route-policy", set, economic.DefaultRedactionProfile())
	if err != nil {
		t.Fatalf("build pack: %v", err)
	}

	// Round-trip through the deterministic tar archive (the offline artifact).
	tarA, err := Archive(contents)
	if err != nil {
		t.Fatalf("archive: %v", err)
	}
	tarB, err := Archive(contents)
	if err != nil {
		t.Fatalf("archive 2: %v", err)
	}
	if !bytes.Equal(tarA, tarB) {
		t.Fatalf("archive is not deterministic")
	}

	restored, err := Unarchive(tarA)
	if err != nil {
		t.Fatalf("unarchive: %v", err)
	}
	res, err := VerifySpendEvidenceOffline(restored)
	if err != nil {
		t.Fatalf("verify after round-trip: %v", err)
	}
	if !res.OK {
		t.Fatalf("expected OK after round-trip")
	}
}

func TestVerifySpendEvidenceOffline_DetectsTamper(t *testing.T) {
	set := buildSpendReceiptSet(t)
	_, contents, err := BuildSpendEvidencePack("pack-1", "did:helm:agent-1", "intent-1", "sha256:route-policy", set, economic.DefaultRedactionProfile())
	if err != nil {
		t.Fatalf("build pack: %v", err)
	}

	// Tamper with the usage receipt amount AFTER the pack was sealed. The content
	// hash recorded in the manifest no longer matches the tampered bytes.
	var usage economic.UsageReceipt
	if err := json.Unmarshal(contents[spendUsageReceiptPath], &usage); err != nil {
		t.Fatalf("decode usage: %v", err)
	}
	usage.ProviderCostCents = 999_999
	tampered, _ := json.MarshalIndent(&usage, "", "  ")
	contents[spendUsageReceiptPath] = tampered

	if _, err := VerifySpendEvidenceOffline(contents); err == nil {
		t.Fatalf("expected tamper to be detected")
	} else if !strings.Contains(err.Error(), "content hash mismatch") {
		t.Fatalf("expected content hash mismatch error, got: %v", err)
	}
}

func TestVerifySpendEvidenceOffline_RejectsPromptBodyInView(t *testing.T) {
	set := buildSpendReceiptSet(t)
	_, contents, err := BuildSpendEvidencePack("pack-1", "did:helm:agent-1", "intent-1", "sha256:route-policy", set, economic.DefaultRedactionProfile())
	if err != nil {
		t.Fatalf("build pack: %v", err)
	}

	// Forge a view that smuggles a prompt body and re-seal the manifest so the
	// content-hash layer passes; the prompt-body guard must still reject it.
	forged := []byte(`{"kind":"USAGE_RECEIPT","prompt_body":"PATIENT SSN 123-45-6789"}`)
	contents[spendUsageViewPath] = forged
	resealManifest(t, contents)

	if _, err := VerifySpendEvidenceOffline(contents); err == nil {
		t.Fatalf("expected prompt-body guard to reject forged view")
	} else if !strings.Contains(err.Error(), "prompt-body marker") {
		t.Fatalf("expected prompt-body marker error, got: %v", err)
	}
}

func TestBuildSpendEvidencePack_PreDispatchOnly(t *testing.T) {
	set := buildSpendReceiptSet(t)
	// Pre-dispatch pack: route + budget only.
	pre := SpendReceiptSet{RouteQuote: set.RouteQuote, Budget: set.Budget}
	_, contents, err := BuildSpendEvidencePack("pack-pre", "did:helm:agent-1", "intent-1", "sha256:route-policy", pre, economic.DefaultRedactionProfile())
	if err != nil {
		t.Fatalf("build pre-dispatch pack: %v", err)
	}
	res, err := VerifySpendEvidenceOffline(contents)
	if err != nil {
		t.Fatalf("verify pre-dispatch: %v", err)
	}
	if len(res.ReceiptsVerified) != 2 {
		t.Fatalf("expected 2 receipts for pre-dispatch pack, got %v", res.ReceiptsVerified)
	}
}

// resealManifest recomputes the manifest entry hashes + manifest hash for the
// current contents so a forged-content test can isolate a specific guard.
func resealManifest(t *testing.T, contents map[string][]byte) {
	t.Helper()
	var manifest Manifest
	if err := json.Unmarshal(contents["manifest.json"], &manifest); err != nil {
		t.Fatalf("decode manifest: %v", err)
	}
	for i := range manifest.Entries {
		data, ok := contents[manifest.Entries[i].Path]
		if !ok {
			continue
		}
		manifest.Entries[i].ContentHash = HashContent(data)
		manifest.Entries[i].Size = int64(len(data))
	}
	manifest.ManifestHash = ""
	h, err := ComputeManifestHash(&manifest)
	if err != nil {
		t.Fatalf("recompute manifest hash: %v", err)
	}
	manifest.ManifestHash = h
	out, _ := json.MarshalIndent(&manifest, "", "  ")
	contents["manifest.json"] = out
}

func mustContain(t *testing.T, haystack []string, needle string) {
	t.Helper()
	for _, h := range haystack {
		if h == needle {
			return
		}
	}
	t.Fatalf("expected %q in %v", needle, haystack)
}
