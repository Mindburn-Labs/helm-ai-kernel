---
title: "HELM Artifact Versioning Specification"
status: final
version: "1.0.0"
created: 2026-03-06
finalized: 2026-03-07
authors:
  - HELM Core Team
---

# RFC: HELM Artifact Versioning v1.0

## Abstract

This document specifies the canonical versioning rules for all HELM protocol
artifacts: schemas, receipts, bundles, packs, RFCs, and evidence packs.

## Status

Final — Normative Standard

## 1. Introduction

### 1.1 Requirements Language

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in RFC 2119.

### 1.2 Scope

This specification applies to every artifact emitted, consumed, or stored
by a HELM-compliant system. No public artifact may be emitted without an
explicit version identifier.

## 2. Version Format

### 2.1 Semantic Versioning

All HELM artifacts MUST use Semantic Versioning 2.0.0:

```
MAJOR.MINOR.PATCH[-PRERELEASE][+BUILD]
```

- **MAJOR** — incremented for breaking changes in schema or contract shape.
- **MINOR** — incremented for additive, backward-compatible changes.
- **PATCH** — incremented for clarifications or bug fixes that do not change
  the contract shape.

### 2.2 Pre-release

Pre-release versions use the following labels:

| Label     | Meaning                                              |
| --------- | ---------------------------------------------------- |
| `alpha.N` | Early draft; may change without notice               |
| `beta.N`  | Feature complete; shape is stable but not committed  |
| `rc.N`    | Release candidate; shape is final pending validation |

Example: `1.0.0-alpha.1`, `2.1.0-rc.2`

### 2.3 Spec Version File

The file `protocols/specs/SPEC_VERSION` MUST contain the current canonical
spec version as a single line (e.g. `1.0.0`). All artifacts generated in
a release cycle MUST reference this version.

## 3. apiVersion Field

### 3.1 Schema Artifacts

JSON Schema files MUST include a `version` property at the top level:

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "version": "1.0.0",
  ...
}
```

### 3.2 Policy Bundles and Packs

YAML-based artifacts MUST include an `apiVersion` field:

```yaml
apiVersion: helm.mindburn.run/v1
kind: PolicyBundle
metadata:
  version: "1.2.0"
```

The `apiVersion` prefix (`helm.mindburn.run/vN`) indicates the API surface major
version. It MUST be incremented only on breaking changes.

### 3.3 Protobuf and Wire Formats

Protobuf packages MUST be versioned by their package path:

```protobuf
package helm.kernel.v1;
```

A new major version creates a new package: `helm.kernel.v2`.

### 3.4 RFC Documents

RFCs MUST carry a `version` field in YAML frontmatter:

```yaml
---
title: "..."
status: draft | final | deprecated
version: "1.0.0"
---
```

## 4. Compatibility Rules

### 4.1 Backward Compatibility

Within the same MAJOR version:

1. New OPTIONAL fields MAY be added (MINOR bump).
2. Existing fields MUST NOT be removed or renamed.
3. Enum values MUST NOT be removed; new values MAY be added.
4. Default values MUST NOT change.

### 4.2 Forward Compatibility

Consumers MUST ignore unknown fields they do not recognize. Consumers
MUST NOT reject an artifact solely because it contains fields added in
a newer MINOR version.

### 4.3 Breaking Changes

A MAJOR version bump is REQUIRED when:

- A required field is removed or renamed.
- A field type changes.
- An enum value's semantic meaning changes.
- Wire format or serialization rules change.

## 5. Deprecation Policy

### 5.1 Deprecation Notice

Before removing a field or artifact shape:

1. The field MUST be marked `deprecated` for at least one MINOR release.
2. Deprecation MUST be documented in the CHANGELOG and SCHEMA_INDEX.

### 5.2 Sunset

A deprecated element MAY be removed in the next MAJOR version. The
sunset date SHOULD be communicated at least 90 days before removal.

## 6. Version Embedding in Artifacts

### 6.1 Receipts

The `receipt_version` field in every receipt MUST match the spec version
of the receipt format (e.g. `"1.0"`).

### 6.2 EvidencePack

The EvidencePack manifest MUST include:

```json
{
  "schema_version": "1.0.0",
  "active_bundles": [...],
  "spec_version": "1.0.0"
}
```

### 6.3 Proof Report

Proof Reports MUST embed the spec version of every artifact they reference.

## 7. Schema Index

All schemas MUST be registered in `protocols/json-schemas/SCHEMA_INDEX.md`.
Schemas not in the index MUST be tagged `informational` or `deprecated`.

## 8. Conformance

An implementation is conformant with this specification if:

1. Every emitted artifact carries a version identifier.
2. Version identifiers follow Semantic Versioning 2.0.0.
3. Backward compatibility rules are honored within MAJOR versions.
4. Unknown fields are tolerated per §4.2.
5. Deprecation follows the policy in §5.

## 9. References

- Semantic Versioning 2.0.0 — https://semver.org/
- RFC 2119 — Key Words for use in RFCs
- HELM Receipt Format v1.0
- HELM Reason Code Registry v1.0
