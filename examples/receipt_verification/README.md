# Receipt Verification Examples

> **These scripts are not offline verification.** They connect to a running
> kernel and call `verify_evidence`, so the thing being trusted is the same
> service that produced the evidence. They are *inspection* examples — useful
> for exploring receipts you already own, useless as proof to anyone who does
> not already trust the service.
>
> For verification that a third party can run without trusting us, use the
> offline verifier below.

## Offline verification (no HELM service in the trust path)

`helm-ai-kernel verify` reads an EvidencePack from disk and checks it locally.
It performs no network I/O unless you explicitly pass `--online`, and the
`core/pkg/verifier` package it is built on imports no HTTP client at all.

```bash
helm-ai-kernel verify /path/to/evidencepack --json
```

Verification is fail-closed in the way that matters for a counterparty: a pack
whose signing key is declared **inside the pack** is refused by default, because
a signer vouching for its own key proves only that it can sign. Accepting one is
an explicit decision:

```bash
# refused: the seal is self-attested
helm-ai-kernel verify reference_packs/launchpad/hermes-local-container

# accepted, because the operator said so
helm-ai-kernel verify reference_packs/launchpad/hermes-local-container --allow-self-attested
```

External trust roots are supplied by flag or environment, never read from the
bundle:

| Flag | Trust root |
| --- | --- |
| `--trusted-public-key` | conformance report signatures |
| `--managed-agent-receipt-public-key` | embedded managed-agent receipts |
| `--external-host-public-key` | external host evidence chains |
| `--profile` | `dev-local`, `team`, `customer`, `high-assurance` |
| `--require-eidas` | requires eIDAS-labelled anchor metadata and declared-time freshness; it does not cryptographically verify RFC 3161 or EU Trusted List qualification |
| `--require-tee` | requires declared TEE attestation metadata for the selected platform |

`--entry <path> --proof <file>` verifies a single redacted entry, so a
counterparty can check one claim without receiving the organization's private
state.

The end-to-end assertion that these properties hold — including that the
refusals actually refuse — is:

```bash
scripts/falsification/proof-stronger-than-platform-logs.sh
```

It runs three cases air-gapped (proxy pointed at a closed port) and exits
non-zero if any case behaves differently.

## The inspection scripts

- `verify_receipts.py`
- `verify_receipts.ts`

Both walk ProofGraph sessions on a running kernel, print receipt metadata, and
recompute one local hash over four fields. That local check is a demonstration,
not the receipt signature: the real preimage is canonicalized over the full
receipt, and `client.verify_evidence()` is a **server-side** call.

### Prerequisites

- A running kernel. `helm-ai-kernel serve --policy` defaults to
  `http://127.0.0.1:7714`; `helm-ai-kernel server` defaults to
  `http://127.0.0.1:8080`.
- Receipts already present in the ProofGraph store.
- Python package from `sdk/python`, or a JavaScript runtime with `fetch`.

```bash
cd examples/receipt_verification
PYTHONPATH=../../sdk/python python verify_receipts.py
npx tsx verify_receipts.ts
```

The retained fixture gate is:

```bash
make verify-fixtures
```
