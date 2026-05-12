# Receipt Verification Examples

Run offline receipt checks with the bundled examples:

- Python: `verify_receipts.py`
- TypeScript: `verify_receipts.ts`

Both scripts demonstrate verifying receipt integrity and expected reason codes
from exported HELM evidence data.

## Prerequisites

- HELM running in the mode that produced the receipts you are inspecting.
  `helm server` defaults to `http://127.0.0.1:7714`; `helm serve --policy`
  defaults to `http://localhost:7714`.
- Receipts already present in the ProofGraph store
- Python package from `sdk/python` or a JavaScript runtime with `fetch`

## Run

```bash
cd examples/receipt_verification
PYTHONPATH=../../sdk/python python verify_receipts.py
npx tsx verify_receipts.ts
```

The scripts are examples for receipt inspection. The retained verifier gate is:

```bash
make verify-fixtures
```
