package contracts_test

import (
	"testing"
	"time"
)

func TestSpendAuthorityContractsSchema(t *testing.T) {
	schema := compileSchema(t, "spend/spend_authority_contracts.v1.schema.json")
	now := time.Now().UTC().Format(time.RFC3339)

	validCreditLine := map[string]interface{}{
		"id":              "credit-1",
		"tenant_id":       "tenant-1",
		"currency":        "USD",
		"limit_cents":     0,
		"status":          "DEFERRED",
		"runtime_usable":  false,
		"deferral_reason": "ERR_PROVIDER_CONTRACT_NEEDED",
		"content_hash":    "sha256:aaaaaaaa",
	}
	if err := schema.Validate(validCreditLine); err != nil {
		t.Fatalf("valid deferred credit line rejected: %v", err)
	}

	runtimeCreditLine := map[string]interface{}{
		"id":              "credit-1",
		"tenant_id":       "tenant-1",
		"currency":        "USD",
		"limit_cents":     1000,
		"status":          "DEFERRED",
		"runtime_usable":  true,
		"deferral_reason": "ERR_PROVIDER_CONTRACT_NEEDED",
		"content_hash":    "sha256:aaaaaaaa",
	}
	if err := schema.Validate(runtimeCreditLine); err == nil {
		t.Fatal("runtime-usable credit line should be rejected by schema")
	}

	validProviderTerms := map[string]interface{}{
		"id":                                     "terms-1",
		"provider_id":                            "openai",
		"account_mode":                           "DIRECT",
		"terms_version":                          "2026-01-01",
		"legal_review_ref":                       "legal-review-1",
		"allows_usage_resale":                    false,
		"allows_provider_credit_transfer":        false,
		"allows_provider_credit_cash_redemption": false,
		"requires_contract_for_managed_billing":  false,
		"effective_at":                           now,
		"content_hash":                           "sha256:bbbbbbbb",
	}
	if err := schema.Validate(validProviderTerms); err != nil {
		t.Fatalf("valid provider terms rejected: %v", err)
	}

	resaleProviderTerms := map[string]interface{}{
		"id":                                     "terms-1",
		"provider_id":                            "openai",
		"account_mode":                           "DIRECT",
		"terms_version":                          "2026-01-01",
		"legal_review_ref":                       "legal-review-1",
		"allows_usage_resale":                    true,
		"allows_provider_credit_transfer":        false,
		"allows_provider_credit_cash_redemption": false,
		"requires_contract_for_managed_billing":  false,
		"effective_at":                           now,
		"content_hash":                           "sha256:bbbbbbbb",
	}
	if err := schema.Validate(resaleProviderTerms); err == nil {
		t.Fatal("provider terms allowing usage resale should be rejected by schema")
	}
}
