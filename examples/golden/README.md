# Golden EvidencePack Example

This directory contains small static receipt and manifest examples for
documentation and demos. The canonical fixture roots used by the retained test
gate live under `fixtures/minimal/`.

## Contents

- `manifest.json` — Pack manifest with session metadata
- `receipt_allow.json` — Sample ALLOW receipt
- `receipt_deny.json` — Sample DENY receipt

## Usage

```bash
make verify-fixtures
```

## What This Proves

The example files show the shape of an allow receipt, a deny receipt, and a
small manifest. Use `fixtures/minimal/` and `make verify-fixtures` for the
source-backed verifier gate.
