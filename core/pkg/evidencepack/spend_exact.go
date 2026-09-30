package evidencepack

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts/economic"
)

const spendPriceV2Path = "receipts/provider_price.json"

func addExactSpendReceipts(b *Builder, set SpendReceiptSet) error {
	if set.UsageV2 == nil && set.SettlementV2 == nil && set.PriceV2 == nil {
		return nil
	}
	if set.Usage != nil || set.Settlement != nil || set.UsageV2 == nil || set.PriceV2 == nil {
		return errors.New("spend evidence pack: exact receipts require usage and tariff, without legacy receipts")
	}
	if !set.UsageV2.HasCanonicalContentHash() {
		return errors.New("spend evidence pack: invalid exact usage")
	}
	if err := set.UsageV2.VerifyPrice(set.PriceV2); err != nil {
		return err
	}
	if set.SettlementV2 != nil {
		if !set.SettlementV2.HasCanonicalContentHash() {
			return errors.New("spend evidence pack: invalid exact settlement")
		}
		if err := set.SettlementV2.VerifyUsage(set.UsageV2); err != nil {
			return err
		}
		if err := addJSON(b, spendSettlementReceiptPath, set.SettlementV2); err != nil {
			return err
		}
	}
	if err := addJSON(b, spendUsageReceiptPath, set.UsageV2); err != nil {
		return err
	}
	u := set.UsageV2
	if err := addJSON(b, spendUsageViewPath, map[string]any{
		"kind": "usage_v2", "cost_basis": u.CostBasis, "currency": u.Currency,
		"reserved_nano_cents": strconv.FormatInt(u.ReservedNanoCents, 10),
		"accrued_nano_cents":  strconv.FormatInt(u.AccruedNanoCents, 10),
		"provider_id":         u.ProviderID, "model_id": u.ModelID,
		"content_hash": u.ContentHash, "evidence_pack_ref": u.EvidencePackRef,
	}); err != nil {
		return err
	}
	if s := set.SettlementV2; s != nil {
		if err := addJSON(b, spendSettlementViewPath, map[string]any{
			"kind": "settlement_v2", "cost_basis": s.CostBasis, "currency": s.Currency,
			"reserved_nano_cents": strconv.FormatInt(s.ReservedNanoCents, 10),
			"accrued_nano_cents":  strconv.FormatInt(s.AccruedNanoCents, 10),
			"ledger_movements":    s.LedgerEntries, "content_hash": s.ContentHash,
			"source_usage_receipt_hash": s.SourceUsageReceiptHash,
		}); err != nil {
			return err
		}
	}
	return addJSON(b, spendPriceV2Path, set.PriceV2)
}

// Versions are selected before decoding money. An unknown version or a mixed
// legacy/exact pair must not verify as a zero-cent legacy receipt.
func verifyExactSpendReceipts(contents map[string][]byte, invariants *[]string) ([]string, error) {
	versions := make(map[string]string)
	for _, path := range []string{spendUsageReceiptPath, spendSettlementReceiptPath} {
		if raw, ok := contents[path]; ok {
			var header struct {
				SchemaVersion string `json:"schema_version"`
			}
			if err := json.Unmarshal(raw, &header); err != nil {
				return nil, err
			}
			versions[path] = header.SchemaVersion
		}
	}
	uVersion, sVersion := versions[spendUsageReceiptPath], versions[spendSettlementReceiptPath]
	if uVersion == "" && sVersion == "" {
		if _, ok := contents[spendPriceV2Path]; ok {
			return nil, errors.New("spend evidence verify: orphan exact tariff")
		}
		return nil, nil
	}
	if uVersion != economic.UsageReceiptSchemaV2 {
		return nil, errors.New("spend evidence verify: unsupported or mixed usage version")
	}
	if _, present := versions[spendSettlementReceiptPath]; present && sVersion != economic.SettlementReceiptSchemaV2 {
		return nil, errors.New("spend evidence verify: unsupported or mixed settlement version")
	}
	r, err := economic.DecodeUsageReceiptV2(contents[spendUsageReceiptPath])
	if err != nil || !r.HasCanonicalContentHash() {
		return nil, fmt.Errorf("spend evidence verify: invalid exact usage: %v", err)
	}
	price, err := economic.DecodeProviderPriceV2(contents[spendPriceV2Path])
	if err != nil {
		return nil, fmt.Errorf("spend evidence verify: missing or invalid tariff: %w", err)
	}
	if err := r.VerifyPrice(price); err != nil {
		return nil, err
	}
	verified := []string{spendUsageReceiptPath, spendPriceV2Path}
	*invariants = append(*invariants, "usage.accrual==exact_tariff", "usage.cost_basis==TARIFF_ESTIMATE")
	if sVersion != "" {
		s, err := economic.DecodeSettlementReceiptV2(contents[spendSettlementReceiptPath])
		if err != nil || !s.HasCanonicalContentHash() {
			return nil, fmt.Errorf("spend evidence verify: invalid exact settlement: %v", err)
		}
		if err := s.VerifyUsage(r); err != nil {
			return nil, err
		}
		verified = append(verified, spendSettlementReceiptPath)
		*invariants = append(*invariants, "settlement.debits==credits==exact_accrual", "settlement.binds_usage_receipt_hash")
	}
	if raw, ok := contents[spendRouteReceiptPath]; ok {
		var q economic.RouteQuote
		if err := json.Unmarshal(raw, &q); err != nil {
			return nil, err
		}
		reserved, err := economic.CentsToNanoCents(q.QuotedAmountCents)
		if err != nil || q.ID != r.RouteQuoteID || q.TenantID != r.TenantID || q.SpendIntentID != r.SpendIntentID || q.EnvelopeID != r.EnvelopeID || q.AgentID != r.AgentID || q.SelectedProviderID != r.ProviderID || q.SelectedModelID != r.ModelID || q.ProviderPriceSnapshotHash != r.ProviderPriceSnapshotHash || q.Currency != r.Currency || reserved != r.ReservedNanoCents {
			return nil, errors.New("spend evidence verify: exact usage differs from quote")
		}
	}
	return verified, nil
}
