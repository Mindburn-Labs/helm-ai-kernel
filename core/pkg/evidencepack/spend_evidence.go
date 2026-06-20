// spend_evidence.go exports HELM spend receipts (SPEND3/5: RouteQuote,
// BudgetVerdictReceipt, UsageReceipt, SettlementReceipt) into a deterministic,
// content-addressed EvidencePack and verifies that pack OFFLINE — with no
// provider console, no network, and no live ledger.
//
// The pack carries two layers that align with Kernel ProofGraph/EvidencePack
// semantics:
//
//   - receipts/*.json  — the source-owned receipts (hashes + metadata only).
//     These back the cryptographic proof: every receipt is re-hashed offline
//     against its own canonical content hash.
//   - views/*.json     — the business-readable VIEWS rendered under a
//     RedactionProfile. By default the prompt body stays OFF-graph: views never
//     contain a prompt body, and prompt-bearing metadata keys are stripped.
//
// Offline verification re-derives the manifest hash from the pack bytes, checks
// each receipt's canonical content hash, re-validates the cross-receipt
// financial invariants (debit == provider cost + platform fee; settlement
// debits == credits; settlement binds the usage-receipt hash), and proves no
// prompt body leaked into the business views. None of this touches a provider.
package evidencepack

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts/economic"
)

// Spend pack entry paths. Receipts and views are kept in distinct trees so a
// verifier can prove the receipt layer cryptographically while a business reader
// consumes the view layer.
const (
	spendRouteReceiptPath      = "receipts/route_quote.json"
	spendBudgetReceiptPath     = "receipts/budget_verdict.json"
	spendUsageReceiptPath      = "receipts/usage.json"
	spendSettlementReceiptPath = "receipts/settlement.json"

	spendRouteViewPath      = "views/route_receipt_view.json"
	spendBudgetViewPath     = "views/budget_verdict_view.json"
	spendUsageViewPath      = "views/usage_receipt_view.json"
	spendSettlementViewPath = "views/settlement_receipt_view.json"

	spendRedactionProfilePath = "views/redaction_profile.json"
)

// SpendReceiptSet is the full set of SPEND3/5 receipts for one governed spend.
// RouteQuote and BudgetVerdictReceipt are produced pre-dispatch; UsageReceipt
// and SettlementReceipt post-dispatch. A pack may be built pre-dispatch (route
// + budget only) or for the completed lifecycle (all four).
type SpendReceiptSet struct {
	RouteQuote *economic.RouteQuote
	Budget     *economic.BudgetVerdictReceipt
	Usage      *economic.UsageReceipt
	Settlement *economic.SettlementReceipt
	// Approvers carries required approver roles/ids for an ESCALATE verdict so
	// the BudgetVerdict view can answer "who must approve". May be nil.
	Approvers []string
}

// BuildSpendEvidencePack renders the receipt set into a deterministic
// EvidencePack manifest + content map using the given redaction profile. The
// business views never contain a prompt body. Pass packID/actorDID/intentID and
// the governing policy hash so the pack manifest binds to the kernel intent.
func BuildSpendEvidencePack(packID, actorDID, intentID, policyHash string, set SpendReceiptSet, profile economic.RedactionProfile) (*Manifest, map[string][]byte, error) {
	if set.RouteQuote == nil && set.Budget == nil && set.Usage == nil && set.Settlement == nil {
		return nil, nil, errors.New("spend evidence pack: at least one receipt is required")
	}

	b := NewBuilder(packID, actorDID, intentID, policyHash)

	// Receipt layer (cryptographic proof) + view layer (business readable).
	if set.RouteQuote != nil {
		if err := addJSON(b, spendRouteReceiptPath, set.RouteQuote); err != nil {
			return nil, nil, err
		}
		if err := addJSON(b, spendRouteViewPath, economic.NewRouteReceiptView(set.RouteQuote, profile)); err != nil {
			return nil, nil, err
		}
	}
	if set.Budget != nil {
		if err := addJSON(b, spendBudgetReceiptPath, set.Budget); err != nil {
			return nil, nil, err
		}
		if err := addJSON(b, spendBudgetViewPath, economic.NewBudgetVerdictView(set.Budget, set.Approvers, profile)); err != nil {
			return nil, nil, err
		}
	}
	if set.Usage != nil {
		if err := addJSON(b, spendUsageReceiptPath, set.Usage); err != nil {
			return nil, nil, err
		}
		if err := addJSON(b, spendUsageViewPath, economic.NewUsageReceiptView(set.Usage, profile)); err != nil {
			return nil, nil, err
		}
	}
	if set.Settlement != nil {
		if err := addJSON(b, spendSettlementReceiptPath, set.Settlement); err != nil {
			return nil, nil, err
		}
		if err := addJSON(b, spendSettlementViewPath, economic.NewSettlementReceiptView(set.Settlement, profile)); err != nil {
			return nil, nil, err
		}
	}

	// Record the redaction profile so a verifier can confirm which profile
	// governed the export (and that prompt-body redaction was on).
	if err := addJSON(b, spendRedactionProfilePath, profile); err != nil {
		return nil, nil, err
	}

	return b.Build()
}

func addJSON(b *Builder, path string, v interface{}) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("spend evidence pack: marshal %s: %w", path, err)
	}
	b.AddRawEntry(path, "application/json", data)
	return nil
}

// SpendVerificationResult is the structured outcome of an offline verification.
// It is itself deterministic and content-addressable, so it can be attached to
// a run as the offline-verify artifact.
type SpendVerificationResult struct {
	PackID       string `json:"pack_id"`
	ManifestHash string `json:"manifest_hash"`
	// ReceiptsVerified lists each receipt path whose canonical content hash matched.
	ReceiptsVerified []string `json:"receipts_verified"`
	// InvariantsChecked lists the financial invariants that were re-validated.
	InvariantsChecked []string `json:"invariants_checked"`
	// PromptBodyOffGraph is true when no business view contained a prompt body.
	PromptBodyOffGraph bool `json:"prompt_body_off_graph"`
	// Offline is always true: verification used only the pack bytes.
	Offline bool `json:"offline"`
	OK      bool `json:"ok"`
}

// promptBodyMarkers are field substrings that must never appear in a business
// view. They mirror the default RedactionProfile's denied keys. Offline
// verification scans every view JSON for these to prove the prompt body stayed
// off-graph by default.
var promptBodyMarkers = []string{
	"prompt_body", "prompt_text", "\"prompt\"", "system_prompt",
	"request_body", "response_body", "completion_body", "messages",
}

// VerifySpendEvidenceOffline verifies a spend EvidencePack using only the pack
// content map — no provider console, no network, no live ledger. It:
//
//  1. recomputes the manifest hash from the manifest entries and confirms it
//     matches the embedded manifest_hash and every entry's content hash;
//  2. re-hashes each receipt against its own canonical content hash;
//  3. re-validates the cross-receipt financial invariants;
//  4. proves no business view contains a prompt body.
//
// It returns a structured result and an error describing the first failure.
func VerifySpendEvidenceOffline(contents map[string][]byte) (*SpendVerificationResult, error) {
	manifestJSON, ok := contents["manifest.json"]
	if !ok {
		return nil, errors.New("spend evidence verify: manifest.json missing")
	}
	var manifest Manifest
	if err := json.Unmarshal(manifestJSON, &manifest); err != nil {
		return nil, fmt.Errorf("spend evidence verify: decode manifest: %w", err)
	}

	res := &SpendVerificationResult{PackID: manifest.PackID, ManifestHash: manifest.ManifestHash, Offline: true}

	// (1) Manifest hash + per-entry content-hash integrity.
	if err := verifyManifestIntegrity(&manifest, contents); err != nil {
		return res, err
	}

	// (2)+(3) Per-receipt canonical content-hash checks and financial invariants.
	verified, err := verifySpendReceipts(contents, &res.InvariantsChecked)
	if err != nil {
		return res, err
	}
	sort.Strings(verified)
	res.ReceiptsVerified = verified

	// (4) Prompt body must not appear in any view.
	if err := verifyNoPromptBody(contents); err != nil {
		return res, err
	}
	res.PromptBodyOffGraph = true

	res.OK = true
	return res, nil
}

// verifyManifestIntegrity recomputes the manifest hash and checks every listed
// entry's content hash against the bytes actually present in the pack.
func verifyManifestIntegrity(manifest *Manifest, contents map[string][]byte) error {
	recomputed, err := ComputeManifestHash(manifest)
	if err != nil {
		return fmt.Errorf("spend evidence verify: recompute manifest hash: %w", err)
	}
	if recomputed != manifest.ManifestHash {
		return fmt.Errorf("spend evidence verify: manifest hash mismatch: embedded %s, recomputed %s", manifest.ManifestHash, recomputed)
	}
	for _, entry := range manifest.Entries {
		data, ok := contents[entry.Path]
		if !ok {
			return fmt.Errorf("spend evidence verify: manifest entry %s missing from pack", entry.Path)
		}
		if got := HashContent(data); got != entry.ContentHash {
			return fmt.Errorf("spend evidence verify: content hash mismatch for %s: manifest %s, actual %s", entry.Path, entry.ContentHash, got)
		}
	}
	return nil
}

// verifySpendReceipts re-hashes each receipt present in the pack against its own
// canonical content hash and re-validates the cross-receipt invariants.
func verifySpendReceipts(contents map[string][]byte, invariants *[]string) ([]string, error) {
	var verified []string

	if raw, ok := contents[spendRouteReceiptPath]; ok {
		route := &economic.RouteQuote{}
		if err := json.Unmarshal(raw, route); err != nil {
			return nil, fmt.Errorf("spend evidence verify: decode route quote: %w", err)
		}
		if !route.HasCanonicalContentHash() {
			return nil, fmt.Errorf("spend evidence verify: route quote content hash mismatch (have %s, want %s)", route.ContentHash, route.CanonicalContentHash())
		}
		verified = append(verified, spendRouteReceiptPath)
	}

	if raw, ok := contents[spendBudgetReceiptPath]; ok {
		budget := &economic.BudgetVerdictReceipt{}
		if err := json.Unmarshal(raw, budget); err != nil {
			return nil, fmt.Errorf("spend evidence verify: decode budget verdict: %w", err)
		}
		if !budget.HasCanonicalContentHash() {
			return nil, fmt.Errorf("spend evidence verify: budget verdict content hash mismatch (have %s, want %s)", budget.ContentHash, budget.CanonicalContentHash())
		}
		verified = append(verified, spendBudgetReceiptPath)
	}

	var usage *economic.UsageReceipt
	if raw, ok := contents[spendUsageReceiptPath]; ok {
		usage = &economic.UsageReceipt{}
		if err := json.Unmarshal(raw, usage); err != nil {
			return nil, fmt.Errorf("spend evidence verify: decode usage receipt: %w", err)
		}
		if !usage.HasCanonicalContentHash() {
			return nil, fmt.Errorf("spend evidence verify: usage receipt content hash mismatch (have %s, want %s)", usage.ContentHash, usage.CanonicalContentHash())
		}
		// Debit invariant: actual == provider cost + platform fee == balance debit.
		if usage.ActualAmountCents != usage.ProviderCostCents+usage.PlatformFeeCents {
			return nil, fmt.Errorf("spend evidence verify: usage debit invariant broken: actual %d != provider %d + fee %d", usage.ActualAmountCents, usage.ProviderCostCents, usage.PlatformFeeCents)
		}
		if usage.BalanceDebitCents != usage.ActualAmountCents {
			return nil, fmt.Errorf("spend evidence verify: usage balance debit %d != actual %d", usage.BalanceDebitCents, usage.ActualAmountCents)
		}
		*invariants = append(*invariants, "usage.actual==provider_cost+platform_fee", "usage.balance_debit==actual")
		verified = append(verified, spendUsageReceiptPath)
	}

	if raw, ok := contents[spendSettlementReceiptPath]; ok {
		settlement := &economic.SettlementReceipt{}
		if err := json.Unmarshal(raw, settlement); err != nil {
			return nil, fmt.Errorf("spend evidence verify: decode settlement receipt: %w", err)
		}
		if !settlement.HasCanonicalContentHash() {
			return nil, fmt.Errorf("spend evidence verify: settlement receipt content hash mismatch (have %s, want %s)", settlement.ContentHash, settlement.CanonicalContentHash())
		}
		if !settlement.Balanced() {
			return nil, errors.New("spend evidence verify: settlement ledger is not balanced (debits != credits)")
		}
		*invariants = append(*invariants, "settlement.debits==credits")
		// Settlement must bind the usage receipt it settles. This is the
		// authoritative direction: source_usage_receipt_hash is sealed AFTER the
		// usage receipt's final hash, so it is a stable link. The reverse field
		// (usage.SettlementReceiptHash) is sealed mutually and is intentionally
		// not required to equal the final settlement hash.
		if usage != nil {
			if settlement.SourceUsageReceiptHash != usage.ContentHash {
				return nil, fmt.Errorf("spend evidence verify: settlement source_usage_receipt_hash %s does not bind usage receipt hash %s", settlement.SourceUsageReceiptHash, usage.ContentHash)
			}
			if settlement.UsageReceiptID != "" && usage.ID != "" && settlement.UsageReceiptID != usage.ID {
				return nil, fmt.Errorf("spend evidence verify: settlement usage_receipt_id %s does not match usage receipt id %s", settlement.UsageReceiptID, usage.ID)
			}
			*invariants = append(*invariants, "settlement.binds_usage_receipt_hash")
		}
		verified = append(verified, spendSettlementReceiptPath)
	}

	if len(verified) == 0 {
		return nil, errors.New("spend evidence verify: pack contains no spend receipts")
	}
	return verified, nil
}

// verifyNoPromptBody scans every business view in the pack for prompt-body
// markers, proving the prompt body stayed off-graph by default.
func verifyNoPromptBody(contents map[string][]byte) error {
	for path, data := range contents {
		if !strings.HasPrefix(path, "views/") {
			continue
		}
		// The redaction profile is a policy document that names the keys it
		// redacts (e.g. "prompt_body"); it is not a spend view and must be
		// exempt from the marker scan, otherwise it would self-trip.
		if path == spendRedactionProfilePath {
			continue
		}
		lower := strings.ToLower(string(data))
		for _, marker := range promptBodyMarkers {
			if strings.Contains(lower, marker) {
				return fmt.Errorf("spend evidence verify: prompt-body marker %q found in business view %s", marker, path)
			}
		}
	}
	return nil
}
