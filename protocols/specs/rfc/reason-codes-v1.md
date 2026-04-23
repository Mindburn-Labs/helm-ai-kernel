---
title: Reason Code Registry v1
status: final
version: 1.0.0
date: 2026-03-06
authors:
  - HELM Core Team
---

# RFC: HELM Reason Code Registry v1

## 1. Abstract

This document defines the normative registry of reason codes for HELM governance
verdicts. Reason codes provide machine-readable, jurisdiction-aware rationale for
`DENY` and `ESCALATE` verdicts emitted by the Policy Decision Point (PDP) and
Guardian components.

## 2. Motivation

A standardized reason code vocabulary enables:

- **Machine-actionable denial handling** — clients can switch on reason codes
- **Cross-language consistency** — SDKs in all languages use the same codes
- **Compliance mapping** — reason codes connect to regulatory requirements
- **Audit trail clarity** — receipts carry unambiguous denial rationale

## 3. Registry Format

Each reason code is a `SCREAMING_SNAKE_CASE` string. The canonical Go type is
`contracts.ReasonCode` (see `core/pkg/contracts/verdict.go`). The protobuf
representation is the `ReasonCode` enum in `protocols/proto/helm/kernel/v1/helm.proto`.

## 4. Normative Reason Code Registry

### 4.1 Policy-Domain Codes

| Code                   | Applies To | Description                                |
| ---------------------- | ---------- | ------------------------------------------ |
| `POLICY_VIOLATION`     | DENY       | Effect violates an active policy rule      |
| `NO_POLICY_DEFINED`    | DENY       | No policy covers this effect type          |
| `PRG_EVALUATION_ERROR` | DENY       | Policy Requirement Graph evaluation failed |
| `SCHEMA_VIOLATION`     | DENY       | Request does not conform to schema         |

### 4.2 PDP Codes

| Code        | Applies To | Description                                     |
| ----------- | ---------- | ----------------------------------------------- |
| `PDP_DENY`  | DENY       | External PDP returned deny                      |
| `PDP_ERROR` | DENY       | PDP unavailable or returned error (fail-closed) |

### 4.3 Requirement Codes

| Code                  | Applies To | Description                         |
| --------------------- | ---------- | ----------------------------------- |
| `MISSING_REQUIREMENT` | DENY       | Required precondition not satisfied |

### 4.4 Budget Codes

| Code              | Applies To | Description                             |
| ----------------- | ---------- | --------------------------------------- |
| `BUDGET_EXCEEDED` | DENY       | Operation exceeds allocated budget      |
| `BUDGET_ERROR`    | DENY       | Budget system unavailable (fail-closed) |

### 4.5 Temporal Codes

| Code                    | Applies To | Description                       |
| ----------------------- | ---------- | --------------------------------- |
| `TEMPORAL_INTERVENTION` | ESCALATE   | Time-based intervention triggered |
| `TEMPORAL_THROTTLE`     | ESCALATE   | Rate limit or cooldown active     |

### 4.6 Envelope and Provenance Codes

| Code                   | Applies To | Description                             |
| ---------------------- | ---------- | --------------------------------------- |
| `ENVELOPE_INVALID`     | DENY       | Effect envelope failed validation       |
| `PROVENANCE_FAILURE`   | DENY       | Provenance chain broken or unverifiable |
| `VERIFICATION_FAILURE` | DENY       | Cryptographic verification failed       |

### 4.7 Isolation Codes

| Code                | Applies To | Description                     |
| ------------------- | ---------- | ------------------------------- |
| `SANDBOX_VIOLATION` | DENY       | Effect exceeds sandbox boundary |
| `TENANT_ISOLATION`  | DENY       | Cross-tenant access violation   |

### 4.8 Jurisdiction Codes

| Code                     | Applies To | Description                               |
| ------------------------ | ---------- | ----------------------------------------- |
| `JURISDICTION_VIOLATION` | DENY       | Effect violates jurisdictional constraint |

## 5. Extension Mechanism

### 5.1 Jurisdiction-Prefixed Codes

Jurisdiction packs MAY define extended reason codes using the pattern:

```
DENY_{JURISDICTION}_{SPECIFIC_REASON}
```

Examples:

- `DENY_GDPR_RIGHT_TO_ERASURE`
- `DENY_SOX_SEGREGATION_OF_DUTIES`
- `DENY_APPI_CROSS_BORDER_TRANSFER`
- `DENY_PIPL_CONSENT_REQUIRED`
- `DENY_HIPAA_PHI_EXPOSURE`
- `DENY_DORA_CRITICAL_FUNCTION`

Jurisdiction codes MUST be registered in the jurisdiction pack manifest.
They MUST NOT conflict with core codes.

### 5.2 Industry-Prefixed Codes

Industry packs MAY define extended reason codes using the pattern:

```
DENY_{INDUSTRY}_{SPECIFIC_REASON}
```

Examples:

- `DENY_FINANCE_AML_CHECK_REQUIRED`
- `DENY_HEALTHCARE_PATIENT_CONSENT`

## 6. Machine-Readable Schema

The JSON Schema for reason codes is published at:

```
protocols/json-schemas/reason-codes/reason-codes-v1.schema.json
```

The protobuf enum is defined at:

```
protocols/proto/helm/kernel/v1/helm.proto
```

## 7. Versioning

This registry follows semantic versioning:

- **PATCH**: clarification of existing codes
- **MINOR**: addition of new codes (backward-compatible)
- **MAJOR**: removal or semantic change of existing codes

## 8. Conformance

An implementation is conformant with this registry if:

1. It recognizes all codes in §4
2. It emits only registered codes (core or extension)
3. Extension codes follow the naming patterns in §5
4. Receipts carry the reason code in the `reason_code` field
