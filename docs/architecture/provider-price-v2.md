# Exact provider prices

<!-- quantum_posture: classical SHA-256 content commitment; no new signature or authority. -->

`ProviderPriceSnapshot` v2 stores integer nano-cents per token. TypeSafe's published
USD 0.042 per million input tokens equals 4,200 nano-cents per token; it cannot be
represented by the legacy integer micro-cent rate without changing the tariff.
Provider price observations still require reviewed terms and a source record.

The v2 discriminator is `helm.provider-price-snapshot.v2`. Input, output and flat
request rates use `input_token_nano_cents`, `output_token_nano_cents` and
`request_nano_cents`. Legacy rate fields cannot be mixed with this representation.
Unversioned legacy prices retain their wire bytes, hash and whole-cent arithmetic.
Unknown versions are rejected. The v1 schema remains closed to v2 payloads.

`ExactCostNanoCents` computes the unrounded tariff cost with checked integer
arithmetic. Zero observed tokens can cost zero; no minimum charge is invented.
`QuoteCents` rounds a v2 tariff total up to whole cents for reservation. It must
not be reported as exact provider liability. The ledger and provider invoice may
have different rounding or aggregation; downstream settlement and reconciliation
must preserve both quantities explicitly before enabling v2 provider billing.

`Seal` validates and writes a content digest; it does not sign or authorize the
price. `CanonicalDigest` is the shared verification calculation. V2's digest covers
the schema version, identities, currency, three rates, terms reference, source URI
and hash, capture time, effective time and expiry. Mutations require a new digest.
The complete price record remains pinned by the existing native quote policy.

Source: `core/pkg/contracts/economic/provider_price_v2.go` and
`protocols/json-schemas/spend/provider_price_snapshot.v2.schema.json`.
Run `cd core && go test ./pkg/contracts/economic` and the JSON-schema gate.

This source contract alone does not activate hosted inference or upgrade an older
consumer. Roll out the protected Enterprise mirror and Control Plane consumer,
qualify exact settlement/recovery with PostgreSQL, then record the provider terms,
price evidence, data scope and operator-owned budget before activation.
