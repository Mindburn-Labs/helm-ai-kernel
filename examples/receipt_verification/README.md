# Receipt Verification Examples

The Python and TypeScript scripts inspect receipts from a running kernel and
request verification against that kernel's signer. For independent
verification, use the offline CLI with a trusted public key.

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
# write a pack sealed with a dev-local key that the pack itself declares
helm-ai-kernel mcp proof --out /tmp/helm-mcp-proof --run-id demo

# refused: the seal is self-attested
helm-ai-kernel verify /tmp/helm-mcp-proof/demo/evidencepacks/demo

# accepted, because the operator said so
helm-ai-kernel verify /tmp/helm-mcp-proof/demo/evidencepacks/demo --allow-self-attested
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
| `--require-check` | names checks that must have run; a named check the pack gives no input to fails instead of being reported as not run. Repeat the flag or separate names with commas |

The accepted pack above prints `checks: 5 passed, 0 failed, 8 not run`: a
check the pack gives no input to (no receipt chain, no connector evidence, no
replay gate) is `NOT_RUN` and is never counted as passed. Exit 0 means no
check failed and every required check held, not that every check ran.

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

Both read the first ProofGraph session through the SDK, print up to three
receipts, and request server-side verification of the session's EvidencePack.
The displayed `blob_hash` identifies the input snapshot when one is available.
The scripts print the checks the server ran and exit with status 1 if the
bundle is `FAILED` or `UNVERIFIABLE`.

### Prerequisites

- A running kernel with receipts in the ProofGraph store. Set `HELM_URL` if
  the kernel uses an address other than `http://127.0.0.1:7714`.
- Set `HELM_ADMIN_API_KEY` (or `HELM_API_KEY`), `HELM_TENANT_ID`, and
  `HELM_PRINCIPAL_ID` for the runtime whose receipts you want to inspect.

Run either example from the repository root.

```bash
python -m pip install ./sdk/python
python examples/receipt_verification/verify_receipts.py
```

```bash
npm --prefix sdk/ts ci
npm --prefix sdk/ts run build
node --experimental-strip-types examples/receipt_verification/verify_receipts.ts
```

The retained fixture gate is:

```bash
make verify-fixtures
```
