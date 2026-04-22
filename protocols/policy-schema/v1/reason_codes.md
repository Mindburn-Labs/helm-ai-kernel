# ReasonCode Registry v0

> Authoritative registry of all ReasonCode strings emitted by the CPI VM.
> Every code MUST have an entry here before shipping.

## Format

`LAYER.DOMAIN.CATEGORY.CAUSE[.SPEC]` — uppercase A-Z, 0-9, underscore. Dot-separated.

## Stability Rules

- Codes are **stable forever** once shipped (no renames)
- Deprecation = stop emitting in new CPI versions; parsers accept indefinitely
- No free-form prose in codes — ever

---

## Registry

### CPI (Compile-Time Policy Inference)

| Code                                                | Severity | Required Args                                           | Description                                              |
| --------------------------------------------------- | -------- | ------------------------------------------------------- | -------------------------------------------------------- |
| `CPI.DATA.MISSING_PRIMITIVE.GDPR_SHIELD`            | BLOCK    | `target_node_id`                                        | Node handles PII without GDPR shield transformer         |
| `CPI.DATA.INVALID_SCOPE.PII_OUTSIDE_EU_CONTROLS`    | BLOCK    | `target_node_id`, `jurisdiction_id`                     | PII data flows outside EU control scope                  |
| `CPI.LICENSE.MISSING_PRIMITIVE.MICA`                | BLOCK    | `target_node_id`, `jurisdiction_id`                     | MiCA license required for crypto operations              |
| `CPI.JURISDICTION.FORBIDDEN.HFT_IN_EE_WITHOUT_MICA` | CRITICAL | `target_node_id`, `jurisdiction_id`                     | HFT in EEA requires MiCA authorization                   |
| `CPI.TAX.REQUIRES_TRANSFORMER.TRANSFER_PRICING_FX`  | BLOCK    | `edge_id`, `source_jurisdiction`, `target_jurisdiction` | Cross-border capital flow needs transfer pricing adapter |
| `CPI.TAX.NEEDS_FACTS.WITHHOLDING_RATE_TABLE`        | WARN     | `source_jurisdiction`, `target_jurisdiction`            | Withholding rate data missing for tax computation        |
| `CPI.TOOLS.FORBIDDEN.TOOL_NOT_IN_ALLOWLIST`         | BLOCK    | `tool_id`, `role_id`                                    | Tool not permitted for this role                         |

### PEP (Runtime Enforcement)

| Code                                          | Severity | Required Args                               | Description                       |
| --------------------------------------------- | -------- | ------------------------------------------- | --------------------------------- |
| `PEP.TREASURY.LIMIT_EXCEEDED.MAX_DAILY_SPEND` | BLOCK    | `current_cents`, `limit_cents`, `currency`  | Daily spending limit exceeded     |
| `PEP.TREASURY.LIMIT_EXCEEDED.PER_VENDOR_CAP`  | BLOCK    | `vendor_id`, `current_cents`, `limit_cents` | Per-vendor spending cap exceeded  |
| `PEP.TOOLS.FORBIDDEN.RUNTIME_TOOL_DENIED`     | BLOCK    | `tool_id`, `agent_id`                       | Tool invocation denied at runtime |

### AUTH (Approvals)

| Code                                                  | Severity | Required Args                                 | Description                        |
| ----------------------------------------------------- | -------- | --------------------------------------------- | ---------------------------------- |
| `AUTH.CONTRACT.NEEDS_APPROVAL.SIGNATURE_REQUIRED`     | BLOCK    | `contract_id`, `required_role`                | Contract action requires signature |
| `AUTH.TREASURY.NEEDS_APPROVAL.PAYMENT_OVER_THRESHOLD` | BLOCK    | `amount_cents`, `threshold_cents`, `currency` | Payment exceeds approval threshold |

### FACT (Missing Facts)

| Code                                           | Severity | Required Args                  | Description                        |
| ---------------------------------------------- | -------- | ------------------------------ | ---------------------------------- |
| `FACT.BANKING.NEEDS_FACTS.KYC_STATUS`          | WARN     | `principal_id`                 | KYC verification status unknown    |
| `FACT.TAX.NEEDS_FACTS.VAT_REGISTRATION_STATUS` | WARN     | `entity_id`, `jurisdiction_id` | VAT registration status unverified |

### SCHEMA (Schema/Concurrency)

| Code                                               | Severity | Required Args                  | Description                               |
| -------------------------------------------------- | -------- | ------------------------------ | ----------------------------------------- |
| `SCHEMA.MERGE.CONFLICT.BASE_SNAPSHOT_MISMATCH`     | BLOCK    | `expected_hash`, `actual_hash` | Base governance config hash doesn't match |
| `SCHEMA.SCHEMA.INVARIANT_BREACH.UNKNOWN_NODE_TYPE` | CRITICAL | `node_type`                    | Unknown node type in delta                |

### EXEC (Post-Allow Failures)

| Code                                              | Severity | Required Args                | Description                      |
| ------------------------------------------------- | -------- | ---------------------------- | -------------------------------- |
| `EXEC.BANKING.EFFECT_FAILED.ACCOUNT_PROVISIONING` | BLOCK    | `account_id`, `error_class`  | Bank account provisioning failed |
| `EXEC.DOMAIN.EFFECT_FAILED.DOMAIN_REGISTRATION`   | BLOCK    | `domain_name`, `error_class` | Domain registration failed       |

---

## Reserved Ranges

- `CPI.*` — codes 001–499
- `PEP.*` — codes 500–699
- `AUTH.*` — codes 700–799
- `FACT.*` — codes 800–849
- `SCHEMA.*` — codes 850–899
- `EXEC.*` — codes 900–999
