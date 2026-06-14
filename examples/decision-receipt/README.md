# Decision-receipt verification example

A signed external decision receipt (`helm_external.v1`) you can verify **offline**
with the kernel CLI — the smallest demonstration of HELM as a neutral receipt verifier.

## Files

- `helm_external_example.json` — a signed `external_decision_receipt_bundle.v1`
  (one receipt: an `allow` decision for `github.create_issue`).
- `public_key.hex` — the Ed25519 public key that signed it (a **throwaway demo key**,
  deterministic seed; not a secret).

## Verify it

```sh
helm-ai-kernel verify decision-receipt \
  examples/decision-receipt/helm_external_example.json \
  --public-key "$(cat examples/decision-receipt/public_key.hex)"
```

Expected:

```
VERIFIED  helm_external.v1  (1 receipt(s))  classification=crypto_conformant
  [ok  ] decision:edr-demo-0001:hash  sha256:...
  [ok  ] decision:edr-demo-0001:signature  Ed25519 verified
  [ok  ] decision:edr-demo-0001:classification  crypto_conformant
```

Run it **without** the trusted key and the same receipt is reported
`NOT VERIFIED … classification=unverified` (exit 1): HELM never treats an external
receipt as proof it cannot verify. The strongest level an external decision receipt
can reach is `crypto_conformant` (decision-level proof) — execution proof requires a
HELM verdict-bound effect permit, which these formats do not carry.

## Re-anchor it as an EvidencePack

Importing a verified external receipt turns it into a content-addressed,
tamper-evident HELM **EvidencePack** — the verbatim source, the normalized
receipt, and a `compatibility/import_manifest.json` that records the
classification and limitations (so it is never mistaken for execution proof):

```sh
helm-ai-kernel import receipt \
  examples/decision-receipt/helm_external_example.json \
  --out ./imported-pack \
  --public-key "$(cat examples/decision-receipt/public_key.hex)"
```

```
Imported helm_external.v1  classification=crypto_conformant
EvidencePack: ./imported-pack
  manifest_hash: sha256:...
  entries (4):
    compatibility/import_manifest.json
    host_evidence/helm_external.v1/source.json
    manifest.json
    receipts/external_edr-demo-0001.json
```

See `protocols/specs/receipts/HELM_RECEIPT_SPEC_v1.0.md` for the full taxonomy and
classification ladder.
