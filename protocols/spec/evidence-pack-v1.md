---
title: "HELM Evidence Pack Format Specification"
status: draft
version: "1.0.0"
created: 2026-04-13
authors:
  - HELM Core Team
references:
  - "arXiv:2511.17118 — Constant-Size Evidence Tuples for Regulated AI"
  - "arXiv:2604.04604 — Deterministic Audit Trails for Autonomous Agents"
---

# Evidence Pack Format Specification v1.0

## Abstract

This document specifies the canonical format for HELM Evidence Packs.
An evidence pack is a content-addressed, tamper-evident archive that bundles
all governance receipts, policy decisions, tool transcripts, and provenance
data produced during a single AI agent execution. The format guarantees
offline verification, deterministic hashing, and constant-size summaries
for regulatory compliance workflows.

## Status

Draft -- Normative Standard

## 1. Introduction

HELM is a fail-closed AI execution firewall. Every tool call, policy decision,
and side effect produces auditable evidence. The evidence pack is the
fundamental archival unit that binds this evidence together with cryptographic
integrity guarantees.

### 1.1 Requirements Language

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in RFC 2119.

### 1.2 Design Goals

1. **Tamper-evidence**: Any modification to pack contents is detectable.
2. **Offline verification**: Packs verify without network access.
3. **Determinism**: The same logical content always produces the same archive bytes.
4. **Constant-size summaries**: Pack completeness is provable in O(1) space (per arXiv 2511.17118).
5. **Non-equivocation**: A publisher cannot produce two valid packs with the same ID but different contents.

### 1.3 Scope

This specification covers:
- The manifest schema and its computation
- Entry types and their required fields
- Hash and canonicalization algorithms
- Signing algorithms
- Archive format
- Verification algorithm
- Constant-size evidence summaries
- Conformance requirements

## 2. Format Version

The format version for this specification is `1.0.0` and follows Semantic
Versioning 2.0.0. The version string MUST appear in the manifest's `version`
field.

Implementations MUST reject manifests with a major version they do not support.
Implementations SHOULD accept manifests with a higher minor or patch version
within the same major version.

## 3. Manifest Schema

The manifest is the root document of an evidence pack. It MUST be serialized
as JSON and stored at the archive path `manifest.json`.

### 3.1 Manifest Fields

```json
{
  "version":       "<semver string, REQUIRED>",
  "pack_id":       "<unique identifier, REQUIRED>",
  "created_at":    "<RFC 3339 timestamp, REQUIRED>",
  "actor_did":     "<DID of the acting agent, REQUIRED>",
  "intent_id":     "<intent identifier, REQUIRED>",
  "policy_hash":   "<SHA-256 hash of active policy, REQUIRED>",
  "entries":       [ "<ManifestEntry[]>, REQUIRED" ],
  "manifest_hash": "<SHA-256 hash of the manifest, REQUIRED>"
}
```

| Field          | Type     | Description                                              |
|----------------|----------|----------------------------------------------------------|
| `version`      | string   | Format version. MUST be `"1.0.0"` for this specification.|
| `pack_id`      | string   | Globally unique pack identifier (UUID recommended).      |
| `created_at`   | string   | RFC 3339 timestamp of pack creation in UTC.              |
| `actor_did`    | string   | Decentralized Identifier of the agent that produced the evidence. |
| `intent_id`    | string   | Identifier of the governance intent that triggered evidence collection. |
| `policy_hash`  | string   | `sha256:<hex>` hash of the policy bundle active at creation time. |
| `entries`      | array    | Ordered list of ManifestEntry objects (see Section 3.2).  |
| `manifest_hash`| string   | `sha256:<hex>` hash of the manifest (see Section 5.1).   |

### 3.2 Manifest Entry Fields

Each entry describes a single file in the evidence pack.

```json
{
  "path":         "<relative path within archive, REQUIRED>",
  "content_hash": "<sha256:hex of file content, REQUIRED>",
  "size":         "<file size in bytes, REQUIRED>",
  "content_type": "<MIME type, REQUIRED>"
}
```

| Field          | Type    | Description                                        |
|----------------|---------|----------------------------------------------------|
| `path`         | string  | Relative path within the archive. MUST use forward slashes. MUST NOT start with `/` or contain `..`. |
| `content_hash` | string  | `sha256:<hex>` digest of the raw file content.     |
| `size`         | integer | File size in bytes. MUST be non-negative.          |
| `content_type` | string  | IANA media type (e.g., `application/json`, `text/plain`). |

### 3.3 Entry Path Conventions

Evidence packs use path prefixes to categorize entries:

| Prefix          | Node Type      | Description                           |
|-----------------|----------------|---------------------------------------|
| `receipts/`     | ATTESTATION    | Governance decision receipts          |
| `policy/`       | INTENT         | Policy evaluation documents           |
| `transcripts/`  | EFFECT         | Tool execution transcripts            |
| `network/`      | EFFECT         | Network activity logs                 |
| `diffs/`        | EFFECT         | Git diffs and code changes            |
| `secrets/`      | TRUST_EVENT    | Secret access audit logs              |
| `ports/`        | EFFECT         | Port exposure events                  |
| `replay/`       | CHECKPOINT     | Replay manifests                      |
| `signatures/`   | --             | Detached signatures                   |

Implementations MAY define additional path prefixes. Unrecognized prefixes
MUST NOT cause verification failure.

## 4. Entry Types

### 4.1 Receipts (ATTESTATION)

Governance decision receipts. Each receipt MUST be a JSON document conforming
to the HELM Receipt Format Specification v1.0. REQUIRED fields:

- `receipt_id` (string)
- `decision_id` (string)
- `verdict` (string: `ALLOW`, `DENY`, or `ESCALATE`)
- `timestamp` (RFC 3339)
- `signature` (base64-encoded Ed25519 signature)

### 4.2 Policy Decisions (INTENT)

Policy evaluation documents recording which rules were evaluated and their
outcomes. MUST be JSON. REQUIRED fields:

- `policy_id` (string)
- `evaluated_at` (RFC 3339)
- `rules_evaluated` (integer)
- `outcome` (string)

### 4.3 Tool Transcripts (EFFECT)

Records of tool executions including inputs, outputs, and timing. MUST be JSON.
REQUIRED fields:

- `tool_id` (string)
- `action` (string)
- `started_at` (RFC 3339)
- `completed_at` (RFC 3339)
- `status` (string: `success`, `failure`, `timeout`)

### 4.4 Network Logs (EFFECT)

Plaintext logs of network activity during execution. MUST use `text/plain`
content type. Each line SHOULD contain: timestamp, source, destination,
protocol, and verdict.

### 4.5 Secret Access Logs (TRUST_EVENT)

JSON records of secret material access during execution. REQUIRED fields:

- `action` (string: `issue`, `revoke`, `access`, `rotate`)
- `token_id` (string)
- `timestamp` (RFC 3339)

### 4.6 Replay Manifests (CHECKPOINT)

JSON documents capturing the inputs and expected outputs for deterministic
replay verification. REQUIRED fields:

- `manifest_id` (string)
- `run_id` (string)
- `mode` (string: `dry`, `live`, `shadow`)

## 5. Hash Algorithm

All hashes in an evidence pack MUST use SHA-256 (FIPS 180-4). Hash values
MUST be encoded as lowercase hexadecimal strings prefixed with `sha256:`.

Example: `sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`

### 5.1 Manifest Hash Computation

The manifest hash MUST be computed as follows:

1. Construct a JSON object containing all manifest fields EXCEPT `manifest_hash`.
2. Sort the `entries` array lexicographically by the `path` field.
3. Serialize the object using JCS (Section 6).
4. Compute SHA-256 of the serialized bytes.
5. Encode as `sha256:<hex>`.

### 5.2 Content Hash Computation

For each entry, the content hash is the SHA-256 of the raw file bytes:

1. Read the complete file content as bytes.
2. Compute SHA-256 of those bytes.
3. Encode as `sha256:<hex>`.

## 6. Canonicalization

All JSON serialization for hashing purposes MUST use JCS (JSON Canonicalization
Scheme) as defined in RFC 8785.

JCS requirements:

- Object keys MUST be sorted lexicographically by their UTF-8 byte representation.
- No whitespace between tokens.
- HTML escaping MUST be disabled.
- Numbers MUST use the shortest representation that preserves the value.
- Strings MUST use standard JSON escaping (no HTML entity escaping).

Implementations MUST NOT use language-default JSON serializers for hash
computation without verifying JCS compliance. The canonical form is the
sole input to all hash computations.

## 7. Signing

### 7.1 Primary Signature: Ed25519

Evidence packs MUST support Ed25519 signatures (RFC 8032). The signature
is computed over the `manifest_hash` value (the hash string bytes, not the
raw hash bytes).

Signature fields:

- `signer_id`: Identifier of the signing entity
- `signature`: Hex-encoded Ed25519 signature
- `algorithm`: MUST be `"Ed25519"`
- `signed_at`: RFC 3339 timestamp
- `key_id`: Public key identifier for key rotation

### 7.2 Post-Quantum Hybrid: ML-DSA-65

For post-quantum readiness, implementations SHOULD additionally support
ML-DSA-65 (FIPS 204, formerly Dilithium3) as a secondary signature. When
both signatures are present, BOTH MUST verify for the pack to be considered
valid.

Hybrid signature fields follow the same schema as Section 7.1 with
`algorithm` set to `"ML-DSA-65"`.

### 7.3 Signature Placement

Signatures MAY be:

1. **Embedded**: In the manifest's `signatures` array (if the manifest schema
   supports it).
2. **Detached**: As separate files under `signatures/` in the archive.

Detached signatures MUST reference the `manifest_hash` they cover.

## 8. Archive Format

An evidence pack archive MUST be a tar archive (POSIX.1-2001 / pax format)
with the following deterministic properties:

### 8.1 Determinism Requirements

1. **Sorted paths**: Entries MUST be sorted lexicographically by path.
2. **Epoch mtime**: All file modification times MUST be set to Unix epoch
   (1970-01-01T00:00:00Z).
3. **Zero ownership**: UID and GID MUST both be 0.
4. **No user/group names**: Owner and group name fields MUST be empty.
5. **Mode**: Regular files MUST use mode 0644. Directories MUST use mode 0755.
6. **No extended attributes**: PAX extended headers for OS-specific attributes
   MUST NOT be included.

### 8.2 Archive Structure

```
manifest.json             # Root manifest (always first)
policy/                   # Policy evaluation documents
receipts/                 # Governance decision receipts
transcripts/              # Tool execution transcripts
network/                  # Network activity logs
secrets/                  # Secret access audit logs
ports/                    # Port exposure events
diffs/                    # Git diffs
replay/                   # Replay manifests
signatures/               # Detached signatures (optional)
```

`manifest.json` MUST be the first entry in the archive.

### 8.3 Compression

Archives MAY be compressed with gzip (RFC 1952). When compressed, the file
extension SHOULD be `.tar.gz` or `.tgz`. Uncompressed archives SHOULD use
`.tar`. Implementations MUST support both compressed and uncompressed archives.

## 9. Verification Algorithm

A compliant verifier MUST perform the following steps in order. Verification
is fail-closed: any step failure MUST cause the entire verification to fail.

### 9.1 Step-by-Step Verification

1. **Extract archive**: Unpack the tar archive. Verify deterministic ordering
   (sorted paths, epoch mtime, uid=0).

2. **Parse manifest**: Read and parse `manifest.json`. Verify the `version`
   field is supported.

3. **Verify manifest hash**:
   a. Construct the hashable object (all fields except `manifest_hash`).
   b. Sort entries by path.
   c. Serialize via JCS (RFC 8785).
   d. Compute SHA-256.
   e. Compare with stored `manifest_hash`. MUST match exactly.

4. **Verify entry content hashes**: For each entry in the manifest:
   a. Read the file at the entry's `path`.
   b. Compute SHA-256 of the file content.
   c. Compare with the entry's `content_hash`. MUST match exactly.

5. **Verify entry sizes**: For each entry, the file size MUST equal the
   entry's `size` field.

6. **Verify completeness**: Every file in the archive (except `manifest.json`)
   MUST have a corresponding manifest entry. Every manifest entry MUST have a
   corresponding file in the archive.

7. **Verify signatures** (if present):
   a. For each signature, retrieve the signer's public key by `key_id`.
   b. Verify the signature over the `manifest_hash` string bytes.
   c. At least one valid signature from a trusted signer MUST be present.

8. **Result**: If all steps pass, the pack is VALID. Otherwise, the verifier
   MUST report the first failing step and reject the pack.

## 10. Constant-Size Evidence Summaries

Per arXiv 2511.17118, a compliant implementation SHOULD support generating
constant-size evidence summaries. A summary is a fixed-size tuple that proves
pack completeness without requiring the full pack contents.

### 10.1 Summary Schema

```json
{
  "pack_id":         "<string>",
  "manifest_hash":   "<sha256:hex>",
  "entry_count":     "<integer>",
  "total_bytes":     "<integer>",
  "node_types":      ["<string>"],
  "first_event":     "<RFC 3339>",
  "last_event":      "<RFC 3339>",
  "signature_count": "<integer>",
  "policy_hash":     "<sha256:hex>",
  "summary_hash":    "<sha256:hex>",
  "generated_at":    "<RFC 3339>"
}
```

### 10.2 Summary Hash Computation

The `summary_hash` MUST be computed as follows:

1. Construct a JSON object containing all summary fields EXCEPT `summary_hash`.
2. Serialize using JCS (RFC 8785).
3. Compute SHA-256 of the serialized bytes.
4. Encode as `sha256:<hex>`.

### 10.3 Summary Verification

A summary can be verified independently of the full pack:

1. Recompute the summary hash using the algorithm in Section 10.2.
2. Compare with the stored `summary_hash`. MUST match exactly.
3. If a manifest is available, verify that `manifest_hash` and `entry_count`
   match the manifest.

## 11. Conformance Requirements

### 11.1 Compliant Producer

A compliant evidence pack producer MUST:

1. Generate a unique `pack_id` for each pack.
2. Set `version` to a supported format version.
3. Compute all content hashes using SHA-256.
4. Compute the manifest hash using the algorithm in Section 5.1.
5. Use JCS (RFC 8785) for all canonicalization.
6. Produce deterministic archives per Section 8.1.
7. Sign the manifest hash with at least Ed25519.
8. Include accurate `size` fields for all entries.

A compliant producer SHOULD:

1. Also sign with ML-DSA-65 for post-quantum readiness.
2. Generate a constant-size evidence summary.
3. Set `created_at` to UTC.

### 11.2 Compliant Verifier

A compliant evidence pack verifier MUST:

1. Perform all steps in Section 9.1.
2. Reject packs with unsupported major versions.
3. Reject packs with any hash mismatch (fail-closed).
4. Reject packs with missing entries or extra files.
5. Verify at least one Ed25519 signature from a trusted signer.

A compliant verifier SHOULD:

1. Verify archive determinism (sorted paths, epoch mtime, uid=0).
2. Verify ML-DSA-65 signatures when present.
3. Verify evidence summary integrity when a summary is provided.

### 11.3 Compliant Archive

A compliant evidence pack archive MUST:

1. Contain `manifest.json` as the first entry.
2. Use sorted paths.
3. Use epoch mtime, uid=0, gid=0.
4. Contain exactly the files listed in the manifest (plus `manifest.json`).

## 12. Security Properties

### 12.1 Evidence Binding

The manifest hash cryptographically binds all entries together. Modifying,
adding, or removing any entry invalidates the manifest hash. The signature
over the manifest hash extends this binding to the publisher's identity.

### 12.2 Tamper Detection

SHA-256 content hashes provide collision-resistant tamper detection for
individual entries. The manifest hash provides tamper detection for the
manifest itself. The signature provides tamper detection for the entire pack.

An attacker cannot modify pack contents without either:
- Breaking SHA-256 collision resistance, or
- Forging an Ed25519 signature.

### 12.3 Non-Equivocation (per arXiv 2511.17118)

The combination of unique `pack_id`, deterministic manifest hashing, and
publisher signatures ensures non-equivocation: a publisher cannot produce
two valid packs with the same `pack_id` but different contents without
being detected.

If two packs share the same `pack_id` but have different `manifest_hash`
values, at least one has been tampered with. Verifiers SHOULD flag this
as an equivocation violation.

### 12.4 Forward Secrecy Considerations

Evidence packs are archival documents. Private signing keys SHOULD be
rotated periodically. Key rotation does not invalidate previously signed
packs, as verification uses the public key identified by `key_id`.

## 13. IANA Considerations

This specification anticipates registration of the following media types
with IANA in a future revision:

- `application/vnd.helm.evidence-pack+tar` for uncompressed evidence packs
- `application/vnd.helm.evidence-pack+tar+gzip` for compressed evidence packs
- `application/vnd.helm.evidence-manifest+json` for standalone manifests
- `application/vnd.helm.evidence-summary+json` for constant-size summaries

File extensions:

- `.helmpack.tar` for uncompressed packs
- `.helmpack.tar.gz` for compressed packs

## 14. References

### 14.1 Normative References

- **RFC 2119**: Key words for use in RFCs to Indicate Requirement Levels
- **RFC 8785**: JSON Canonicalization Scheme (JCS)
- **RFC 8032**: Edwards-Curve Digital Signature Algorithm (Ed25519)
- **RFC 3339**: Date and Time on the Internet: Timestamps
- **FIPS 180-4**: Secure Hash Standard (SHA-256)
- **FIPS 204**: Module-Lattice-Based Digital Signature Standard (ML-DSA-65)

### 14.2 Informative References

- **arXiv 2511.17118**: Constant-size evidence tuples for regulated AI workflows.
  Establishes the theoretical foundation for O(1) evidence summaries and
  non-equivocation properties used in Section 10 and Section 12.3.

- **arXiv 2604.04604**: Deterministic audit trails for autonomous agents.
  Provides the formal model for tamper-evident, content-addressed evidence
  archives that informed the design of this specification.

- **HELM Receipt Format Specification v1.0**: Defines the canonical receipt
  format referenced by ATTESTATION entries in Section 4.1.

- **HELM Governance Protocol Specification v1.0**: Defines the governance
  execution model that produces evidence packs.

## Appendix A: Example Manifest

```json
{
  "version": "1.0.0",
  "pack_id": "550e8400-e29b-41d4-a716-446655440000",
  "created_at": "2026-04-13T12:00:00Z",
  "actor_did": "did:helm:agent-7f3a",
  "intent_id": "intent-2026-04-13-001",
  "policy_hash": "sha256:a1b2c3d4e5f67890abcdef1234567890abcdef1234567890abcdef1234567890",
  "entries": [
    {
      "path": "policy/gate-evaluation.json",
      "content_hash": "sha256:1111111111111111111111111111111111111111111111111111111111111111",
      "size": 512,
      "content_type": "application/json"
    },
    {
      "path": "receipts/decision-001.json",
      "content_hash": "sha256:2222222222222222222222222222222222222222222222222222222222222222",
      "size": 1024,
      "content_type": "application/json"
    },
    {
      "path": "transcripts/tool-exec-001.json",
      "content_hash": "sha256:3333333333333333333333333333333333333333333333333333333333333333",
      "size": 2048,
      "content_type": "application/json"
    }
  ],
  "manifest_hash": "sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
}
```

## Appendix B: Example Evidence Summary

```json
{
  "pack_id": "550e8400-e29b-41d4-a716-446655440000",
  "manifest_hash": "sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
  "entry_count": 3,
  "total_bytes": 3584,
  "node_types": ["ATTESTATION", "EFFECT", "INTENT"],
  "first_event": "2026-04-13T12:00:00Z",
  "last_event": "2026-04-13T12:00:00Z",
  "signature_count": 0,
  "policy_hash": "sha256:a1b2c3d4e5f67890abcdef1234567890abcdef1234567890abcdef1234567890",
  "summary_hash": "sha256:fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321",
  "generated_at": "2026-04-13T12:01:00Z"
}
```
