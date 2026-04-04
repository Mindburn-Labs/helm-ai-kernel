# Knowledge Promotion Standard

**Version:** 1.0.0
**Status:** DRAFT
**Owner:** Mindburn Labs / HELM Core
**Last Updated:** 2026-04-04

---

## Abstract

This standard defines the canonical workflow for promoting knowledge from the
Local Knowledge Store (LKS) to the Certified Knowledge Store (CKS) within a
HELM tenant. LKS knowledge is ephemeral, session-scoped, and agent-produced;
CKS knowledge is certified, tenant-persistent, and governance-approved.

Promotion is fail-closed: a claim that fails any validation step remains in LKS
and MUST NOT advance. The promotion workflow produces an `PromotionReceipt`
that is recorded in the ProofGraph, ensuring that the provenance of every CKS
entry is cryptographically traceable to the evidence that justified it.

This standard defines the wire formats for `KnowledgeClaim`, the state machine
for promotion, and the multi-source evidence and multi-signer approval
requirements that guard the CKS boundary.

---

## Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
"SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be
interpreted as described in RFC 2119.

| Term | Definition |
|---|---|
| **LKS** | Local Knowledge Store — agent-writable, session-scoped, unverified claims. |
| **CKS** | Certified Knowledge Store — governance-approved, tenant-persistent facts. |
| **KnowledgeClaim** | A structured claim proposed for promotion from LKS to CKS. |
| **PromotionRequirement** | The set of validation gates a claim must pass to be promoted. |
| **Dual-Source Requirement** | A claim must be backed by 2 or more independent evidence sources. |
| **ProvenanceScore** | A floating-point quality signal (0.0–1.0) derived from source independence and citation depth. |
| **PromotionReceipt** | The signed, ProofGraph-linked artifact produced upon successful promotion. |
| **Signer** | An authorized HELM principal whose Ed25519 signature counts toward `min_signer_count`. |
| **Approval Profile** | A named configuration that specifies the full set of promotion requirements. |
| **Evidence Source** | An artifact or external reference that independently supports the claim body. |

---

## Wire Format

### KnowledgeClaim

```json
{
  "schema": "https://helm.mindburn.org/schemas/knowledge/knowledge_claim.v1.json",
  "claim_id": "claim_01HX9ZB2C3D4E5F6G7H8I9J0KL",
  "tenant_id": "tenant_acme_corp",
  "store_class": "lks",
  "title": "ACME Q1 2026 revenue missed consensus by 8%",
  "body": "Per the Q1 board packet (p. 4) and the CFO commentary transcript, ACME's Q1 2026 revenue of $42.1M was 8% below analyst consensus of $45.8M. The miss is attributed to delayed enterprise contract renewals in APAC.",
  "source_artifact_ids": [
    "artifacts/uploads/q1-board-packet-2026.pdf",
    "artifacts/uploads/cfo-commentary-q1-2026.txt"
  ],
  "source_hashes": [
    "sha256:d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5",
    "sha256:a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2"
  ],
  "provenance_score": 0.87,
  "promotion_req": {
    "dual_source_required": true,
    "min_signer_count": 1,
    "approval_profile_ref": "approval-profiles/standard-lks-cks.yaml"
  },
  "status": "pending",
  "created_by": "skills/org.mindburn.research-assistant@2.3.1",
  "created_at_unix_ms": 1743765800000,
  "proofgraph_ref": "proofgraph/nodes/intent_01HX9ZB2C3D4E5F6G7H8I9J0KM"
}
```

### Field Descriptions

| Field | Type | Constraints | Description |
|---|---|---|---|
| `schema` | string (URI) | REQUIRED | JSON Schema `$id`. |
| `claim_id` | string | REQUIRED, globally unique | Stable identifier. Format: `claim_{ULID}`. |
| `tenant_id` | string | REQUIRED | Owning HELM tenant. |
| `store_class` | KnowledgeStoreClass | REQUIRED | MUST be `lks` at creation; becomes `cks` on successful promotion. |
| `title` | string | REQUIRED, 1–256 chars | Short, factual headline of the claim. |
| `body` | string | REQUIRED, 1–8192 chars | Full claim body. MUST cite specific source passages where possible. |
| `source_artifact_ids` | string[] | REQUIRED, min 1 item | `artifact_id` values from artifact-manifest-v1 that evidence the claim. |
| `source_hashes` | string[] | REQUIRED, length MUST equal `source_artifact_ids` | Content hashes of each source artifact at time of claim creation. |
| `provenance_score` | float | REQUIRED, 0.0–1.0 | Automated provenance quality signal. Computed from source independence, citation depth, and recency. |
| `promotion_req` | PromotionRequirement | REQUIRED | The gates the claim must pass. |
| `status` | PromotionStatus | REQUIRED | Current lifecycle status (see State Machine). |
| `created_by` | string | REQUIRED | HELM principal or skill ID that submitted the claim. |
| `created_at_unix_ms` | integer | REQUIRED | Unix millisecond timestamp of claim submission. |
| `proofgraph_ref` | string | REQUIRED | ProofGraph node ID of the INTENT that triggered the promotion attempt. |

### PromotionRequirement

| Field | Type | Constraints | Description |
|---|---|---|---|
| `dual_source_required` | bool | REQUIRED | If `true`, the claim MUST be backed by 2 or more independent source artifacts. |
| `min_signer_count` | integer | REQUIRED, ≥ 1 | Minimum number of authorized signers whose approvals MUST be collected before promotion. |
| `approval_profile_ref` | string | REQUIRED | Reference to the named approval profile governing this promotion path. |

### KnowledgeStoreClass Enum

| Value | Description |
|---|---|
| `lks` | Local Knowledge Store — ephemeral, unverified, session-scoped. |
| `cks` | Certified Knowledge Store — approved, tenant-persistent, governance-backed. |

### PromotionStatus Enum

| Value | Description |
|---|---|
| `pending` | Submitted, awaiting validation and approval. |
| `approved` | All gates passed; claim is being promoted to CKS. |
| `rejected` | One or more gates failed; claim remains in LKS. |
| `expired` | Claim was not resolved within `policy.promotion_ttl_seconds`. Equivalent to `rejected`. |

---

## Validation Rules

1. **MUST** — The promotion pipeline MUST verify each `source_hashes[i]` against
   the stored artifact at `source_artifact_ids[i]`. Any hash mismatch MUST
   immediately set `status: rejected` with reason `SOURCE_INTEGRITY_FAILURE`.

2. **MUST** — If `dual_source_required: true`, the claim MUST have at least 2
   entries in `source_artifact_ids`, and those entries MUST resolve to artifacts
   with distinct `created_by` principals. Sources from the same skill instance
   MUST NOT count as independent.

3. **MUST** — `min_signer_count` MUST be satisfied before the claim transitions
   to `approved`. Each signer MUST hold the `knowledge.promote` HELM permission
   and MUST be a distinct principal.

4. **MUST** — `provenance_score` MUST be computed by the HELM kernel, not
   supplied by the submitting skill. Skills MUST NOT be able to inflate their
   claims' provenance scores.

5. **MUST** — All approvals MUST produce signed `ApprovalReceipt` objects
   recorded in the ProofGraph before the `status` transitions to `approved`.

6. **MUST** — A claim in `rejected` or `expired` status MUST NOT be re-submitted
   with the same `claim_id`. A corrected claim MUST receive a new `claim_id` and
   MUST reference the original via `parent_claim_id` (OPTIONAL extended field).

7. **MUST** — CKS entries MUST be immutable once written. Any update to a CKS
   fact requires deprecating the original claim and submitting a new one through
   the full promotion workflow.

8. **SHOULD** — Claims with `provenance_score < 0.5` SHOULD require an elevated
   `min_signer_count` (≥ 2). The approval profile SHOULD encode this rule.

9. **MUST** — The `proofgraph_ref` MUST be set before the claim enters the
   approval workflow. Claims without a valid `proofgraph_ref` MUST be rejected
   as ungoverned.

10. **MAY** — The HELM runtime MAY auto-reject claims that have been pending for
    longer than `policy.promotion_ttl_seconds`. Auto-rejection MUST produce a
    `PromotionExpiredEvent` in the ProofGraph.

---

## State Machine

```
[skill submits via memory.promote]
              │
              ▼
           pending
              │
     ┌────────┼────────┐
     │        │        │
  (hash    (dual   (low
  fail)   source   score,
     │    check)  no signers)
     │        │        │
  rejected ◀──┴────────┘
              │ (all gates pass,
              │  min_signer_count met,
              │  approval receipts recorded)
              ▼
           approved
              │
     (kernel writes to CKS, issues PromotionReceipt)
              │
              ▼
      [CKS entry — immutable]
```

---

## PromotionReceipt

Upon successful promotion, the HELM kernel issues a `PromotionReceipt`:

```json
{
  "receipt_id": "rcpt_01HX9ZC2D3E4F5G6H7I8J9K0LM",
  "claim_id": "claim_01HX9ZB2C3D4E5F6G7H8I9J0KL",
  "tenant_id": "tenant_acme_corp",
  "promoted_at_unix_ms": 1743765900000,
  "cks_entry_id": "cks/tenant_acme_corp/facts/acme-q1-2026-revenue-miss",
  "signer_principal_ids": ["principal_cfo_alice", "principal_manager_bob"],
  "policy_hash": "sha256:1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b",
  "proofgraph_ref": "proofgraph/nodes/effect_01HX9ZC2D3E4F5G6H7I8J9K0LN",
  "signature": "base64url:..."
}
```

The `PromotionReceipt` is the sole authoritative proof that a claim reached CKS.
Absence of a `PromotionReceipt` means the claim is still in LKS or was rejected.

---

## Versioning Policy

- The `KnowledgeClaim` schema is versioned per ADR-006.
- CKS entries written under v1 MUST remain readable after schema updates.
- Approval profiles are versioned independently and referenced by name.
- The approval profile version in effect at approval time MUST be recorded in
  the `PromotionReceipt`.

---

## Security Considerations

- **Fail-closed by design.** Any error in the validation pipeline (hash
  mismatch, signer resolution failure, ProofGraph write failure) MUST leave the
  claim in `pending` or move it to `rejected`. There is no path from an error
  state to `approved`.

- **Signer collusion.** `min_signer_count` is a minimum; deployment policies
  MAY require signers from distinct HELM organizational units to prevent
  collusion. The approval profile encodes this constraint.

- **Source independence.** The dual-source check using distinct `created_by`
  principals prevents a single compromised skill from bootstrapping false facts
  into CKS through circular self-citation.

- **CKS immutability.** Once in CKS, an entry cannot be silently replaced. Only
  explicit deprecation + re-promotion is possible, producing a full audit trail
  in the ProofGraph.

---

## References

- ADR-004: All Runtime Mutation Goes Through Forge
- ADR-005: R0-R3 Action Risk Class Taxonomy
- ADR-006: Schema Namespace Organization
- artifact-manifest-v1.md (this standard set) — `source_artifact_ids`
- skill-bundle-v1.md (this standard set) — `memory.promote` capability
- HELM ARC Integration Standard — LKS/CKS integration
- MAMA AI Canonical Standard — memory and retrieval model
- GOVERNANCE_SPEC.md
