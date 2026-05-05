# Receipt Schemas Source Owner

## Audience

Use this file when changing receipt, evidence envelope, authorization snapshot, sandbox grant, or MCP authorization profile schemas.

## Responsibility

`schemas/receipts` owns JSON Schemas for receipt-adjacent evidence that external tools may verify. Public docs should describe verification behavior and link to this directory for machine-readable contracts.

## Validation

Run:

```bash
make verify-fixtures
make docs-truth
```

Do not describe a receipt field as verifier-stable unless the schema and verifier path both support it.
