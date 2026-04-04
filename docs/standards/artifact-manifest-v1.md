# Artifact Manifest Standard

**Version:** 1.0.0
**Status:** DRAFT
**Owner:** Mindburn Labs / HELM Core
**Last Updated:** 2026-04-04

---

## Abstract

This standard defines the canonical metadata structure for artifacts stored in
HELM's content-addressed artifact layer. An `ArtifactManifest` is the
authoritative descriptor that binds a stored blob — identified by its SHA-256
content hash — to its governance provenance, policy state, and namespace
classification.

Every artifact produced or consumed within the HELM runtime MUST have a
corresponding `ArtifactManifest`. The manifest is stored alongside the artifact
in the artifact registry and is referenced by skill bundles (skill-bundle-v1),
channel envelopes (channel-envelope-v1), and knowledge promotion claims
(knowledge-promotion-v1). Because the manifest embeds the `policy_hash` of the
active policy at write time, it is possible to retroactively evaluate whether an
artifact was produced under a policy that has since been revoked.

---

## Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
"SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be
interpreted as described in RFC 2119.

| Term | Definition |
|---|---|
| **ArtifactManifest** | The canonical metadata descriptor for a stored artifact. |
| **Content Hash** | SHA-256 digest of the raw artifact bytes in the format `sha256:{hex}`. |
| **ArtifactNamespace** | Classification of the artifact's origin and visibility scope. |
| **Payload Class** | Risk classification of the artifact's content (R0-R3, per ADR-005). |
| **Provenance Ref** | Reference to the ProofGraph node that records the artifact's production event. |
| **Policy Hash** | Content-addressed hash of the active policy at artifact write time. |
| **Parent Artifact** | An artifact that directly contributed to this artifact's content. |
| **Created By** | The HELM principal ID or skill ID responsible for producing the artifact. |
| **Source Envelope** | The `ChannelEnvelope` that carried the artifact into the HELM runtime (inbound uploads). |
| **CAS** | Content-Addressed Storage — the underlying storage layer keyed by content hash. |

---

## Wire Format

### ArtifactManifest

```json
{
  "schema": "https://helm.mindburn.org/schemas/artifacts/artifact_manifest.v1.json",
  "artifact_id": "artifacts/outputs/2026/04/04/summary-q1-board-v3.pdf",
  "tenant_id": "tenant_acme_corp",
  "namespace": "outputs",
  "path": "summaries/q1-board-2026/v3/summary.pdf",
  "media_type": "application/pdf",
  "size_bytes": 204800,
  "content_hash": "sha256:d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5",
  "payload_class": "R2",
  "created_by": "skills/org.mindburn.document-summarizer@2.1.0",
  "created_at_unix_ms": 1743765700000,
  "source_envelope_id": "env_01HX9Z3K7B2NVTPQRS4A6WMCDE",
  "parent_artifact_ids": [
    "artifacts/uploads/q1-board-packet-2026.pdf"
  ],
  "provenance_ref": "proofgraph/nodes/effect_01HX9ZA1B2C3D4E5F6G7H8I9JK",
  "policy_hash": "sha256:1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b"
}
```

### Field Descriptions

| Field | Type | Constraints | Description |
|---|---|---|---|
| `schema` | string (URI) | REQUIRED | JSON Schema `$id` for this manifest version. |
| `artifact_id` | string | REQUIRED, globally unique | Stable logical path within the artifact store. Format: `artifacts/{namespace}/{path}`. |
| `tenant_id` | string | REQUIRED | Owning HELM tenant. |
| `namespace` | ArtifactNamespace | REQUIRED | Origin/visibility classification. |
| `path` | string | REQUIRED | Relative path within the namespace. MUST be a valid POSIX path. |
| `media_type` | string | REQUIRED | IANA media type. MUST NOT be `application/octet-stream` unless content type cannot be determined. |
| `size_bytes` | integer | REQUIRED, > 0 | Exact size of the artifact in bytes. |
| `content_hash` | string | REQUIRED, format `sha256:{64 hex chars}` | SHA-256 of the raw artifact bytes. This is the CAS key. |
| `payload_class` | string | REQUIRED, enum R0/R1/R2/R3 | Risk class of the artifact's content (ADR-005). |
| `created_by` | string | REQUIRED | HELM principal ID or skill bundle ID that produced this artifact. |
| `created_at_unix_ms` | integer | REQUIRED | Unix millisecond timestamp of artifact creation. |
| `source_envelope_id` | string | OPTIONAL | `envelope_id` of the inbound `ChannelEnvelope` if artifact entered via a channel upload. |
| `parent_artifact_ids` | string[] | OPTIONAL | Ordered list of `artifact_id` values that this artifact was derived from. |
| `provenance_ref` | string | REQUIRED | ProofGraph node ID of the EFFECT event that produced this artifact. |
| `policy_hash` | string | REQUIRED, format `sha256:{hex}` | Content hash of the active policy bundle at write time. |

### ArtifactNamespace Enum

| Value | Scope | Description |
|---|---|---|
| `uploads` | Inbound | Content received via channel attachments or external uploads. Always treated as untrusted until scanned. |
| `workspace` | Internal | Working files created by agents during active execution. Subject to session TTL. |
| `outputs` | Outbound | Finalized artifacts intended for delivery to users or external systems. |
| `evidence` | Governance | Artifacts produced as part of an EvidencePack or ProofGraph node. Immutable once written. |

---

## Content Hash Format

The `content_hash` field uses the following canonical format:

```
"sha256:" + lowercase hex-encoded SHA-256 digest (64 characters)
```

Example: `sha256:d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5`

No other hash algorithms are permitted in v1. Future versions MAY introduce
additional algorithms using the same prefix pattern (e.g., `blake3:{hex}`).

Implementations MUST verify the `content_hash` by re-hashing the stored blob
before returning the artifact to any caller. A mismatch MUST be treated as
storage corruption and MUST trigger a `STORAGE_INTEGRITY_VIOLATION` alert.

---

## Validation Rules

1. **MUST** — `content_hash` MUST be computed by the HELM artifact writer
   immediately before the blob is committed to CAS. It MUST NOT be supplied
   externally by the producing skill or agent.

2. **MUST** — `provenance_ref` MUST point to an existing ProofGraph node of type
   `EFFECT`. Any manifest without a resolvable `provenance_ref` MUST be treated
   as an orphaned artifact and MUST be quarantined.

3. **MUST** — `policy_hash` MUST be captured at write time from the currently
   active policy epoch. It MUST NOT be set retroactively.

4. **MUST** — Artifacts in the `evidence` namespace MUST be immutable. Write
   operations targeting an existing `artifact_id` in the `evidence` namespace
   MUST be rejected with `IMMUTABLE_ARTIFACT_VIOLATION`.

5. **MUST** — `payload_class` MUST be at least as restrictive as the skill's
   declared `outputs[].trust_class` for the producing skill. Upgrades (less
   restrictive) require an explicit operator policy override.

6. **SHOULD** — `parent_artifact_ids` SHOULD be populated whenever an artifact
   is derived from or transforms another artifact. This creates the provenance
   chain for evidence replay.

7. **MUST** — `uploads` namespace artifacts MUST be virus-scanned and
   content-classified before `payload_class` is set. The default for unscanned
   uploads is `R3` (maximum restriction).

8. **MUST NOT** — `artifact_id` MUST NOT be mutable after creation. Rename or
   move operations MUST create a new manifest with a `parent_artifact_ids`
   reference to the original.

9. **SHOULD** — Artifacts with `payload_class: R2` or higher SHOULD have access
   controlled by the tenant's data classification policy. The manifest SHOULD
   include a `data_classification_ref` in extended metadata.

10. **MUST** — Manifests MUST be stored atomically with their associated blobs.
    A blob without a manifest or a manifest without a blob MUST be treated as
    an incomplete write and automatically garbage-collected after a configurable
    grace period.

---

## Provenance Chain

The `parent_artifact_ids` field enables forward tracing of artifact lineage:

```
uploads/source-document.pdf
         │
         ▼  (skill: document-extractor@1.0)
workspace/extracted-text.txt
         │
         ▼  (skill: document-summarizer@2.1)
outputs/summary.pdf
         │
         ▼  (knowledge-promotion-v1 workflow)
evidence/promotion-claim-abc123.json
```

Each step in this chain MUST be backed by a ProofGraph `EFFECT` node. Promotion
claims (knowledge-promotion-v1) MUST reference the full artifact chain via
`source_artifact_ids` to enable dual-source verification.

---

## Versioning Policy

- `ArtifactManifest` v1 is a stable, immutable schema per ADR-006.
- Future versions MAY add OPTIONAL fields; existing readers MUST ignore unknown
  fields.
- Breaking changes (field removal, type change) require a new schema version
  (`artifact_manifest.v2.json`). The `schema` field MUST be updated accordingly.
- The CAS layer is version-agnostic — it stores raw bytes keyed by content hash
  regardless of manifest version.

---

## Security Considerations

- **Tamper detection.** Re-hashing on every read ensures storage-layer tampering
  is detected. This check MUST be performed even when serving artifacts from
  cache.

- **Policy binding.** The `policy_hash` field ties every artifact to the exact
  policy epoch under which it was produced. Auditors can replay EvidencePacks
  using the archived policy version to verify that the artifact was legitimately
  produced.

- **Namespace isolation.** The `evidence` namespace is governance-critical.
  Write access MUST be restricted to the HELM kernel, not to skill bundles
  directly. Skills write to `workspace` or `outputs`; the kernel promotes to
  `evidence` during EvidencePack construction.

- **Orphan prevention.** Every manifest MUST have a `provenance_ref`. Orphaned
  artifacts (no ProofGraph linkage) are governance gaps and MUST be flagged for
  operator review.

---

## References

- ADR-005: R0-R3 Action Risk Class Taxonomy
- ADR-006: Schema Namespace Organization
- channel-envelope-v1.md (this standard set) — `attachments[].artifact_id`
- skill-bundle-v1.md (this standard set) — `artifact_manifest_ref`
- knowledge-promotion-v1.md (this standard set) — `source_artifact_ids`
- EXECUTION_SECURITY_MODEL.md
- GOVERNANCE_SPEC.md
