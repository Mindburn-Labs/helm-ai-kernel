# Connector Release Standard

**Version:** 1.0.0
**Status:** DRAFT
**Owner:** Mindburn Labs / HELM Core
**Last Updated:** 2026-04-04

---

## Abstract

This standard defines the canonical structure, certification requirements,
schema drift policy, and lifecycle management for HELM Connector Releases. A
Connector Release is the versioned, signed, sandbox-enforced package that
bridges the HELM Effects Gateway to an external system — whether digital (an
API, database, or message bus) or analog (a phone call, physical device, or
human workflow step).

Connectors are execution endpoints: they receive `EffectPermit` tokens from
the Guardian, perform exactly the permitted action, and return a signed
`ConnectorReceipt`. Any connector that executes outside the boundary defined
by its certified `ConnectorRelease` is in violation of this standard. Fail-closed
semantics apply throughout: a connector that cannot verify its `EffectPermit`
MUST abort the operation and MUST NOT produce a receipt.

---

## Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
"SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be
interpreted as described in RFC 2119.

| Term | Definition |
|---|---|
| **ConnectorRelease** | The canonical versioned descriptor of a certified connector package. |
| **ConnectorReleaseState** | Lifecycle state of the release: `candidate`, `certified`, `revoked`. |
| **ConnectorExecutorKind** | Whether the connector interfaces with digital or analog systems. |
| **EffectPermit** | Single-use, scoped, Ed25519-signed authorization token issued by the Guardian. |
| **ConnectorReceipt** | Signed proof that a connector executed (or refused) a permitted action. |
| **Schema Ref** | A versioned JSON Schema reference declaring the connector's input/output contract. |
| **Drift Policy** | Rules governing acceptable deviation between the connector's declared and runtime schemas. |
| **Sandbox Profile** | Named runtime isolation configuration applied during connector execution. |
| **Binary Hash** | SHA-256 of the connector executable or container image. |
| **Certification Ref** | Reference to the signed conformance certificate from the HELM certification authority. |

---

## Wire Format

### ConnectorRelease

```json
{
  "schema": "https://helm.mindburn.org/schemas/connectors/connector_release.v1.json",
  "connector_id": "connectors/org.mindburn.slack",
  "name": "Slack Connector",
  "version": "1.4.2",
  "state": "certified",
  "schema_refs": [
    "schemas/effects/send_chat_message_effect.v1.json",
    "schemas/receipts/outbound_comm_receipt.v1.json"
  ],
  "executor_kind": "digital",
  "sandbox_profile": "network-egress-slack-only",
  "drift_policy_ref": "drift-policies/strict-no-additional-fields.yaml",
  "certification_ref": "certifications/connectors/org.mindburn.slack@1.4.2.cert",
  "binary_hash": "sha256:b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2",
  "signature_ref": "signatures/connectors/org.mindburn.slack@1.4.2.sig",
  "published_at_unix_ms": 1743765000000,
  "published_by": "principal_helm_release_authority"
}
```

### Field Descriptions

| Field | Type | Constraints | Description |
|---|---|---|---|
| `schema` | string (URI) | REQUIRED | JSON Schema `$id`. |
| `connector_id` | string | REQUIRED, format `connectors/{reverse-domain}.{name}` | Globally unique, stable connector identifier. |
| `name` | string | REQUIRED, 1–128 chars | Human-readable display name. |
| `version` | string | REQUIRED, semver | Version of this release. |
| `state` | ConnectorReleaseState | REQUIRED | Current lifecycle state. |
| `schema_refs` | string[] | REQUIRED, min 1 item | Versioned JSON Schema references for all effect input/output types this connector handles. |
| `executor_kind` | ConnectorExecutorKind | REQUIRED | Whether the connector interfaces with digital or analog systems. |
| `sandbox_profile` | string | REQUIRED | Named sandbox profile restricting the connector's execution environment. |
| `drift_policy_ref` | string | REQUIRED | Reference to schema drift detection policy. |
| `certification_ref` | string | REQUIRED for `certified` state | Path to signed conformance certificate. |
| `binary_hash` | string | REQUIRED, format `sha256:{hex}` | SHA-256 of the connector binary or container image digest. |
| `signature_ref` | string | REQUIRED | Path to Ed25519 signature over `binary_hash`. |
| `published_at_unix_ms` | integer | REQUIRED | Unix millisecond timestamp of release publication. |
| `published_by` | string | REQUIRED | HELM principal that published the release. |

### ConnectorReleaseState Enum

```
candidate  →  certified
     │              │
     └──────────────┴──▶ revoked
```

| State | Meaning |
|---|---|
| `candidate` | Under review; MUST NOT be used in production environments. MAY be used in sandbox lanes. |
| `certified` | Passed conformance; MAY be installed and invoked in any HELM environment. |
| `revoked` | Withdrawn; MUST NOT be invoked. All deployments MUST be removed within the tenant's revocation SLA. |

### ConnectorExecutorKind Enum

| Value | Description | Governance Implications |
|---|---|---|
| `digital` | Interfaces with APIs, databases, message queues, files. | Standard `EffectPermit` flow. |
| `analog` | Interfaces with phone calls, physical hardware, human workflows, physical mail. | Escalates to R3 by default (ADR-005). Full approval ceremony required unless explicitly downgraded by policy. |

---

## Validation Rules

1. **MUST** — `binary_hash` MUST be verified against the connector executable or
   container image on every deployment. A mismatch MUST prevent installation and
   MUST produce a `BINARY_INTEGRITY_VIOLATION` alert.

2. **MUST** — The Ed25519 signature at `signature_ref` MUST verify against the
   HELM release authority public key. An invalid signature MUST abort
   installation.

3. **MUST** — A connector MUST NOT transition to `certified` without a valid
   `certification_ref`. The certification artifact MUST be verifiable against
   the HELM conformance certification key.

4. **MUST** — A `revoked` connector MUST NOT receive `EffectPermit` tokens. The
   Effects Gateway MUST check connector state on every invocation, not only at
   install time.

5. **MUST** — Each `EffectPermit` presented to a connector MUST be validated:
   (a) the permit's `connector_id` MUST match the connector's own `connector_id`,
   (b) the Ed25519 signature on the permit MUST verify against the Guardian's key,
   (c) the permit MUST NOT be expired (`expires_at_unix_ms`),
   (d) the permit MUST NOT have been previously consumed (NonceStore check).
   Failure of any check MUST abort with no execution and no receipt.

6. **MUST** — `analog` connectors MUST enforce a mandatory approval ceremony gate
   (R3 per ADR-005) unless the tenant's policy explicitly grants a lower risk
   class for the specific action type.

7. **SHOULD** — Connectors MUST validate inbound effect payloads against the
   declared `schema_refs` before execution. Schema validation failures SHOULD be
   reported as `SCHEMA_VALIDATION_FAILURE` connector errors rather than silent
   data corruption.

8. **MUST** — The `ConnectorReceipt` MUST be signed by the connector's Ed25519
   key and MUST include the `EffectPermit.nonce` to prove the permit was consumed
   exactly once.

9. **MUST** — `sandbox_profile` MUST be enforced by the HELM runtime before the
   connector process is started. The connector MUST NOT be able to modify its own
   sandbox constraints.

10. **SHOULD** — Connectors SHOULD emit structured telemetry events (latency,
    error codes, retry counts) to the HELM observability bus. Absence of
    telemetry SHOULD be treated as a health signal degradation.

---

## Certification Requirements

A `ConnectorRelease` transitions from `candidate` to `certified` only after
passing the HELM Connector Conformance Suite:

| Gate | Description |
|---|---|
| **L1: EffectPermit validation** | Connector correctly accepts valid permits and rejects invalid, expired, or replayed permits. |
| **L2: Schema conformance** | All effect inputs and outputs match declared `schema_refs`. No undeclared fields are passed to external systems. |
| **L3: Sandbox enforcement** | Connector cannot escape its declared `sandbox_profile`. Syscall and network egress are verified. |
| **L4: Receipt integrity** | Every execution produces a syntactically and cryptographically valid `ConnectorReceipt`. |
| **L5: Failure semantics** | Connector correctly handles external system failures (timeout, 5xx, network error) without partial effects. |

Conformance is attested by a signed `CertificationArtifact` stored at
`certification_ref`. The certification MUST specify the exact connector version
and the conformance suite version used.

---

## Schema Drift Detection

The `drift_policy_ref` references a policy that governs acceptable runtime
schema deviations. Drift is detected by comparing the connector's declared
`schema_refs` against the schemas actually observed in production traffic.

| Drift Category | Example | Default Action |
|---|---|---|
| `ADDITIONAL_FIELD` | External API adds a new response field. | Log and ignore (MAY be promoted to error by policy). |
| `MISSING_REQUIRED_FIELD` | External API removes a required response field. | `CONNECTOR_SCHEMA_DRIFT` alert; operator review required. |
| `TYPE_CHANGE` | External API changes a field from string to integer. | Immediate `CONNECTOR_SCHEMA_DRIFT_CRITICAL`; connector suspended. |
| `REMOVED_OPERATION` | External API removes an operation the connector depends on. | Immediate suspension; rollback to prior certified version. |

Drift events MUST be recorded in the ProofGraph and MUST be visible in Mission
Control.

---

## Marketplace Listing

A `ConnectorRelease` in `certified` state MAY be published to the HELM connector
marketplace. Listing requirements:

- MUST have a valid `certification_ref`.
- MUST include a `README` and connector-specific documentation bundle.
- MUST declare all external network destinations (for `digital` connectors) so
  that tenants can pre-approve egress in their sandbox profiles.
- MUST pass a marketplace security review for connectors with
  `executor_kind: analog`.

---

## Versioning Policy

- Connector versions follow semver 2.0.
- A new **major** version MUST be treated as a new connector; the old version
  MUST be deprecated before the new `certified` release enters general
  availability.
- Patch releases MUST NOT change `schema_refs` or `sandbox_profile`.
- Published `certified` releases are immutable. Corrections require a new semver.

---

## Security Considerations

- **Single-use permits.** The NonceStore guarantee ensures each `EffectPermit`
  is consumed at most once. Connectors MUST enforce this check; double-spend
  must be impossible even under retry.

- **Binary integrity.** The `binary_hash` + `signature_ref` pair prevents
  substitution attacks where a malicious binary is installed under a certified
  connector's identity.

- **Analog escalation.** Analog connectors have real-world side effects
  (phone calls, physical mail, hardware commands) that are irreversible. The
  mandatory R3 escalation ensures no analog action executes without explicit
  human approval unless explicitly policy-overridden.

- **Revocation propagation.** Revoked connector IDs MUST be propagated to all
  HELM nodes in the tenant within the revocation SLA. The Effects Gateway MUST
  deny `EffectPermit` tokens for revoked connectors even if locally cached state
  has not yet been updated (fail-closed preference: deny on uncertainty).

---

## References

- ADR-001: HELM Is Execution Authority, Not Assistant Shell
- ADR-005: R0-R3 Action Risk Class Taxonomy
- ADR-006: Schema Namespace Organization
- skill-bundle-v1.md (this standard set) — `connector.invoke` capability
- channel-envelope-v1.md (this standard set) — channel connectors
- EXECUTION_SECURITY_MODEL.md
- GOVERNANCE_SPEC.md
- CONFORMANCE.md
