---
title: "HELM Identifier and URN Grammar"
status: final
version: "1.0.0"
created: 2026-03-06
finalized: 2026-03-07
authors:
  - HELM Core Team
---

# RFC: HELM Identifier and URN Grammar v1.0

## Abstract

This document specifies the canonical grammar for all identifiers used in HELM
governance artifacts: receipt IDs, decision IDs, effect IDs, bundle IDs,
principal IDs, and key IDs.

## Status

Final — Normative Standard

## 1. Introduction

### 1.1 Requirements Language

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in RFC 2119.

### 1.2 Motivation

A canonical identifier system ensures:

- Machine-parseable, collision-resistant naming
- Deterministic derivation where possible
- Unambiguous reference across systems, SDKs, and languages
- Offline-verifiable identifier integrity

## 2. URN Format

### 2.1 General Schema

All structured HELM identifiers SHOULD use the URN format:

```
urn:helm:{type}:{identifier}
```

Where:

- `urn:helm:` — fixed namespace prefix.
- `{type}` — one of the registered identifier types (§3).
- `{identifier}` — type-specific opaque string.

### 2.2 Character Set

Identifiers MUST consist of printable ASCII characters. The `{identifier}`
portion MUST match the regex:

```
[a-zA-Z0-9._-]{1,255}
```

### 2.3 Case Sensitivity

All HELM identifiers are **case-sensitive**. Implementations MUST NOT
perform case-folding during comparison.

## 3. Identifier Types

### 3.1 Content-Addressed Identifiers

These identifiers are deterministically derived from content:

| Type            | URN Example                        | Derivation                               |
| --------------- | ---------------------------------- | ---------------------------------------- |
| `receipt`       | `urn:helm:receipt:a1b2c3...`       | `hex(SHA-256(canonical_json(receipt)))`  |
| `decision`      | `urn:helm:decision:d4e5f6...`      | `hex(SHA-256(canonical_json(decision)))` |
| `pgnode`        | `urn:helm:pgnode:1a2b3c...`        | `hex(SHA-256(node_content))`             |
| `effect-digest` | `urn:helm:effect-digest:7e8f9a...` | `hex(SHA-256(effect_params))`            |
| `bundle-hash`   | `urn:helm:bundle-hash:b1c2d3...`   | `hex(SHA-256(manifest + policies))`      |

Content-addressed identifiers MUST be reproducible: the same input MUST
always produce the same identifier.

### 3.2 Assigned Identifiers

These identifiers are assigned at creation time:

| Type        | URN Example                          | Generation                    |
| ----------- | ------------------------------------ | ----------------------------- |
| `effect`    | `urn:helm:effect:eff-01J...`         | UUIDv7 or equivalent          |
| `principal` | `urn:helm:principal:agent-42`        | Assigned by identity provider |
| `key`       | `urn:helm:key:key-corp-2026`         | Assigned by key administrator |
| `bundle`    | `urn:helm:bundle:corporate-baseline` | Assigned by bundle author     |
| `pack`      | `urn:helm:pack:eu-gdpr-v1`           | Assigned by pack registrar    |
| `session`   | `urn:helm:session:ses-01J...`        | UUIDv7 or equivalent          |

### 3.3 Composite Identifiers

For artifacts referencing multiple entities:

| Type                | Example                                     |
| ------------------- | ------------------------------------------- |
| `tenant:principal`  | `urn:helm:principal:tenant-a.agent-42`      |
| `jurisdiction:pack` | `urn:helm:pack:eu-gdpr.finance.engineering` |

Composite identifiers use `.` as the namespace separator.

## 4. Short Form

### 4.1 Bare Identifiers

In contexts where the type is unambiguous (e.g., `receipt_id` field in a
receipt JSON), the URN prefix MAY be omitted:

```json
{
  "receipt_id": "a1b2c3d4e5f6..."
}
```

is equivalent to:

```json
{
  "receipt_id": "urn:helm:receipt:a1b2c3d4e5f6..."
}
```

### 4.2 Resolution

Implementations MUST accept both bare and URN-prefixed forms. When
normalizing, implementations SHOULD expand to full URN form.

## 5. Content Addressing

### 5.1 Hash Algorithm

All content-addressed identifiers MUST use SHA-256:

```
id = hex(SHA-256(canonical_bytes))
```

### 5.2 Canonical Serialization

For JSON artifacts, canonical serialization follows RFC 8785 (JSON
Canonicalization Scheme): deterministic JSON with sorted keys, no
whitespace, and normalized number representations.

### 5.3 Self-Exclusion

When computing a content-addressed ID for an artifact that contains
an ID field (e.g., `receipt_id`), the ID field MUST be excluded from
the hash input:

```
receipt_id = SHA-256(canonical_json(receipt_without_receipt_id))
```

## 6. Collision Resistance

### 6.1 Content-Addressed

SHA-256 provides 128-bit collision resistance. Implementations MUST
reject any artifact where the declared ID does not match the computed hash.

### 6.2 Assigned

UUIDv7 identifiers provide 122 bits of uniqueness with embedded
timestamps. Implementations SHOULD use UUIDv7 for assigned identifiers
to ensure temporal ordering and uniqueness.

### 6.3 Duplicate Detection

Implementations MUST detect duplicate content-addressed identifiers
within a single kernel instance and reject the later submission.

## 7. Wire Format

### 7.1 JSON

Identifiers MUST be serialized as JSON strings:

```json
{ "receipt_id": "a1b2c3d4e5f6..." }
```

### 7.2 Protobuf

Identifiers MUST be `string` fields in protobuf messages:

```protobuf
string receipt_id = 2;
```

### 7.3 Display

For human display, identifiers SHOULD be truncated to the first 12
hex characters followed by `...`:

```
a1b2c3d4e5f6...
```

## 8. Conformance

An implementation is conformant with this specification if:

1. Content-addressed identifiers are deterministically derived per §5.
2. Assigned identifiers follow the generation rules per §3.2.
3. Both bare and URN-prefixed forms are accepted per §4.
4. Identifier comparison is case-sensitive per §2.3.
5. SHA-256 is used for all content addressing per §5.1.
6. Duplicate content-addressed identifiers are rejected per §6.3.

## 9. References

- RFC 2119 — Key Words for use in RFCs
- RFC 4122 — A Universally Unique IDentifier (UUID) URN Namespace
- RFC 8785 — JSON Canonicalization Scheme
- UUIDv7 — https://www.ietf.org/archive/id/draft-peabody-dispatch-new-uuid-format-04.html
- HELM Receipt Format v1.0
