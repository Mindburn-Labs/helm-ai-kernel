# Exact provider tariff accrual

The v2 usage and settlement contracts record a provider tariff estimate in
integer nano-cents. One cent is 1,000,000,000 nano-cents. A reservation may round
up to whole cents; a posting never uses that rounded reservation as its cost.
For a synthetic tariff of 4,200 nano-cents per input token, 1,000 one-token calls
and one 1,000-token call both accrue 4,200,000 nano-cents.

`UsageReceiptV2` binds the tenant, workspace, request, quote, immutable price,
observed token counts and source observation digest. `VerifyPrice` recomputes
the estimate. `SettlementReceiptV2` binds the final usage hash and balanced
ledger movements in one direction, avoiding a circular receipt hash. Zero usage
has zero accrual and no ledger movements. An unknown outcome cannot produce a
settlement; an over-reservation result remains unresolved.

Amounts and token counts are decimal strings in the v2 JSON wire format, so
JavaScript clients do not lose integer precision. Closed schemas live under
`protocols/json-schemas/spend/`. Strict decoders reject missing fields, duplicate
keys, unknown fields, mixed cent fields and noncanonical decimal strings.
Content hashes establish integrity, not issuer identity or billing truth.

The existing Spend EvidencePack builder and offline verifier accept the v2
receipts at the existing receipt paths, with the bound tariff in
`receipts/provider_price.json`. They recompute cost and check scope, quote and
ledger bindings. Legacy wire bytes and hashes remain unchanged. The cent-only
savings comparison refuses v2 rather than reporting a zero-cent saving.

`ExactSpendBalance` supplies checked reservation and settlement arithmetic.
It is a value type, not a store or authority grant. Control Plane owns the
PostgreSQL transaction across the existing company account, project budget,
agent envelope, reservation, receipts and ledger. Admission, idempotency and
recovery remain separate from these arithmetic checks.

These contracts do not define platform fees, taxes, customer prices or provider
invoice adjustments. `TARIFF_ESTIMATE` must remain visible to consumers. They
also do not qualify a hosted model, deploy the Control Plane consumer or enable
new provider spending.
