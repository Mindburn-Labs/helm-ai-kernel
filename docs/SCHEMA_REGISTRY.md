---
title: Schema Registry
---

# HELM Schema Registry

HELM defines 42+ JSON schemas covering all governance data structures. This guide explains how to discover, use, and integrate HELM schemas.

## Schema Inventory

All schemas live in `protocols/json-schemas/`:

| Category | Schemas | Description |
|---|---|---|
| **Core** | `receipt/`, `core/`, `kernel/` | Receipt, Decision, Intent |
| **Effects** | `effects/`, `effect_digest/`, `effect_type_definition/` | Effect boundary model |
| **Policy** | `policy/`, `packs/`, `profiles/` | Policy bundles and packs |
| **Trust** | `registry/`, `certification/`, `authority/`, `verification/` | Trust and identity |
| **Compliance** | `compliance/`, `jurisdiction/`, `retention_policy/` | Regulatory frameworks |
| **Audit** | `audit/`, `telemetry/` | Audit trail and observability |
| **Identity** | `identity/`, `actor_context/` | Agent identity |
| **Business** | `business/`, `orgdna/`, `data_class/` | Organizational governance |
| **Operations** | `intervention/`, `backpressure_policy/`, `safety/` | Runtime operations |
| **Advanced** | `corroborated_receipt/`, `module_provenance/`, `module_risk_score/` | Multi-party receipts, provenance |

See `protocols/json-schemas/SCHEMA_INDEX.md` for the complete index with descriptions.

## Using Schemas

### In Go

Schemas are embedded in the Go binary via `protocols/json-schemas/`. Use the `contracts/schemas` package for validation:

```go
import "github.com/Mindburn-Labs/helm-oss/core/pkg/contracts/schemas"

err := schemas.ValidateReceipt(receiptJSON)
```

### In TypeScript

Import from the generated SDK:

```typescript
import { Receipt, DecisionRecord } from '@mindburn/helm';
```

### In Python

Import from the generated SDK:

```python
from helm_sdk.types import Receipt, DecisionRecord
```

### Raw JSON Schema

Each schema directory contains a `*.schema.json` file that conforms to JSON Schema Draft 2020-12. These can be used with any JSON Schema validator:

```bash
# Validate a receipt against the schema
ajv validate -s protocols/json-schemas/receipt/receipt-v1.schema.json -d my-receipt.json
```

## Schema Versioning

Schemas follow HELM's version policy:
- **Major version** in the schema filename (e.g., `receipt-v1.schema.json`)
- **Backward compatible** changes within a major version
- **Breaking changes** require a new major version
- All schemas are synchronized with the `VERSION` file via `make codegen-check`

## Proto IDL → Schema Relationship

HELM's canonical type definitions live in Protobuf (`protocols/proto/helm/`). JSON schemas are derived from these definitions. The code generation pipeline ensures consistency:

```
protocols/proto/helm/*.proto
    │
    ├── make codegen-go    → sdk/go/gen/
    ├── make codegen-python → sdk/python/helm_sdk/generated/
    ├── make codegen-ts    → sdk/ts/src/generated/
    ├── make codegen-java  → sdk/java/src/main/java/
    └── make codegen-rust  → cargo build --features codegen
```

JSON schemas provide additional validation constraints (min/max values, patterns, required fields) beyond what Protobuf defines.

## Reason Code Registry

The canonical list of verdict reason codes is in `protocols/json-schemas/reason-codes/reason-codes-v1.json`. This file is the single source of truth — the Go constants in `contracts/verdict.go` must match. The CI gate `make codegen-check` enforces this.

## Discovery

### CLI

```bash
helm schema list              # List all schema types
helm schema show receipt      # Display receipt schema
helm schema validate receipt my-receipt.json  # Validate file
```

### Programmatic

The schema index is available at `protocols/json-schemas/SCHEMA_INDEX.md` and can be parsed programmatically for tooling integration.
