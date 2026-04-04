# Channel Envelope Standard

**Version:** 1.0.0
**Status:** DRAFT
**Owner:** Mindburn Labs / HELM Core
**Last Updated:** 2026-04-04

---

## Abstract

This standard defines the canonical envelope format for inbound and outbound
messages across all HELM-governed messaging channels: Slack, Telegram, Lark,
WhatsApp, and Signal. The Channel Envelope normalizes the heterogeneous wire
formats of each provider into a single, policy-evaluable structure that flows
through the HELM Effects Gateway and produces standard HELM receipts.

Every message entering a HELM tenant MUST be wrapped in a `ChannelEnvelope`
before it is evaluated by the PEP or dispatched to an agent. Every outbound
message sent through a channel connector MUST carry an `envelope_id` traceable
to a `KernelVerdict` and an `EffectPermit`. The envelope is an immutable unit —
once created it MUST NOT be mutated in transit.

---

## Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
"SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be
interpreted as described in RFC 2119.

| Term | Definition |
|---|---|
| **ChannelEnvelope** | The normalized inbound or outbound message container. |
| **ChannelKind** | The messaging provider identity (slack, telegram, lark, whatsapp, signal). |
| **SenderTrustClass** | Classification of the sender's identity confidence level. |
| **ChannelAttachmentRef** | A content-addressed reference to a message attachment. |
| **Identity Binding Ref** | Reference to a verified identity assertion linking `sender_id` to a HELM principal. |
| **Session** | A coherent conversational context within a channel and thread. |
| **Payload Class** | Risk classification of the attachment content (per ADR-005 R-classes). |
| **Signature Ref** | Reference to the Ed25519 signature covering the envelope's canonical hash. |
| **Anti-Spoof Validation** | The process of verifying that a message originated from the claimed channel provider. |
| **Effects Gateway** | The single execution chokepoint through which all HELM external effects transit. |

---

## Wire Format

### ChannelEnvelope

```json
{
  "schema": "https://helm.mindburn.org/schemas/channels/channel_envelope.v1.json",
  "envelope_id": "env_01HX9Z3K7B2NVTPQRS4A6WMCDE",
  "channel": "slack",
  "tenant_id": "tenant_acme_corp",
  "session_id": "sess_01HX9Z3K7B2NVTPQRS4A6WMCDF",
  "message_id": "T1234567890.123456",
  "thread_id": "T1234567890.000001",
  "sender_id": "U01ABC123DE",
  "sender_handle": "@alice",
  "sender_trust": "verified",
  "identity_binding_ref": "bindings/helm_principal_alice.json",
  "received_at_unix_ms": 1743765600000,
  "text": "Please summarize the Q1 board packet and send to the team.",
  "attachments": [
    {
      "artifact_id": "artifacts/uploads/q1-board-packet-2026.pdf",
      "media_type": "application/pdf",
      "content_hash": "sha256:f4a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1",
      "payload_class": "R1"
    }
  ],
  "metadata": {
    "channel_workspace_id": "T01WORKSPACE",
    "bot_user_id": "B01HELMBOT",
    "event_ts": "1743765600.123456"
  },
  "signature_ref": "signatures/env_01HX9Z3K7B2NVTPQRS4A6WMCDE.sig"
}
```

### Field Descriptions

| Field | Type | Constraints | Description |
|---|---|---|---|
| `schema` | string (URI) | REQUIRED | JSON Schema `$id` for this envelope version. |
| `envelope_id` | string | REQUIRED, globally unique | Stable, opaque identifier assigned at ingestion. Format: `env_{ULID}`. |
| `channel` | ChannelKind | REQUIRED | Originating messaging provider. |
| `tenant_id` | string | REQUIRED | HELM tenant that owns this envelope. |
| `session_id` | string | REQUIRED | Session identifier for routing and context grouping. |
| `message_id` | string | REQUIRED | Provider-native message ID. MUST be preserved verbatim. |
| `thread_id` | string | OPTIONAL | Provider-native thread or conversation ID. |
| `sender_id` | string | REQUIRED | Provider-native sender identifier (user ID, phone number, etc). |
| `sender_handle` | string | OPTIONAL | Human-readable sender display name or handle. |
| `sender_trust` | SenderTrustClass | REQUIRED | Trust classification of the sender identity. |
| `identity_binding_ref` | string | OPTIONAL | Path to verified HELM principal binding for this sender. |
| `received_at_unix_ms` | integer | REQUIRED | Unix millisecond timestamp of ingestion by the HELM channel adapter. |
| `text` | string | OPTIONAL, max 65535 chars | Normalized message body. MUST be UTF-8. |
| `attachments` | ChannelAttachmentRef[] | OPTIONAL | Content-addressed attachment references. |
| `metadata` | object | OPTIONAL | Provider-specific supplemental fields, MUST be treated as untrusted. |
| `signature_ref` | string | OPTIONAL | Path to Ed25519 signature covering the canonical envelope hash. |

### ChannelKind Enum

| Value | Provider |
|---|---|
| `slack` | Slack (Events API or Socket Mode) |
| `telegram` | Telegram Bot API |
| `lark` | Lark / Feishu |
| `whatsapp` | WhatsApp Business API |
| `signal` | Signal Protocol (self-hosted gateway) |

### SenderTrustClass Enum

| Value | Meaning | Policy Effect |
|---|---|---|
| `verified` | Sender identity is bound to a HELM principal with active credential. | Full capability grant per policy. |
| `known_low` | Sender is recognized but not HELM-principal-bound. | Reduced capability set; R2+ actions require elevation. |
| `unknown` | First contact; no prior binding. | Restricted to R0 interactions; identity binding REQUIRED before any effects. |
| `suspicious` | Prior anti-spoof or rate-limit violation. | Quarantine routing; operator review REQUIRED. |

### ChannelAttachmentRef

| Field | Type | Constraints | Description |
|---|---|---|---|
| `artifact_id` | string | REQUIRED | Stable path in content-addressed artifact storage (artifact-manifest-v1). |
| `media_type` | string | REQUIRED | IANA media type of the attached content. |
| `content_hash` | string | REQUIRED, format `sha256:{hex}` | SHA-256 of raw attachment bytes. MUST be verified before use. |
| `payload_class` | string | REQUIRED, enum R0/R1/R2/R3 | Risk class of attachment content (ADR-005). |

---

## Validation Rules

1. **MUST** — `envelope_id` MUST be generated by the HELM channel adapter at
   ingestion time. Envelopes that arrive without a valid `envelope_id` MUST be
   rejected before any policy evaluation.

2. **MUST** — `received_at_unix_ms` MUST be set to the HELM-side ingestion
   timestamp. Provider-supplied timestamps MAY be stored in `metadata` but MUST
   NOT be used as the authoritative time.

3. **MUST** — Each `attachments[].content_hash` MUST be verified against the
   stored artifact before the attachment is made available to any skill or agent.
   Hash mismatch MUST prevent access and MUST be logged as a security event.

4. **MUST** — Senders with `sender_trust: unknown` MUST NOT trigger any effect
   with `risk_class` above R0 until an identity binding is established.

5. **MUST** — Senders with `sender_trust: suspicious` MUST be routed to a
   quarantine queue; effects MUST NOT be dispatched until an operator reviews
   and clears the sender.

6. **MUST** — Anti-spoof validation MUST be performed for every inbound envelope.
   Provider-specific validation methods are defined in the connector release for
   each channel (see connector-release-v1). A failed anti-spoof check MUST
   elevate `sender_trust` to `suspicious`.

7. **SHOULD** — Envelopes carrying attachments with `payload_class: R2` or
   higher SHOULD trigger a `memory.read.cks` + policy check before the
   attachment content is forwarded to any agent.

8. **MUST NOT** — The `metadata` field MUST NOT be used to override any
   first-class envelope field. Adapters MUST NOT read governance-relevant data
   from `metadata`.

9. **MUST** — `text` MUST be normalized to NFC Unicode form before storage. The
   raw provider payload MAY be stored separately for forensic purposes but MUST
   NOT be used in policy evaluation.

10. **SHOULD** — `signature_ref` SHOULD be present for all outbound envelopes
    emitted by HELM on behalf of a virtual employee, to provide a verifiable
    attribution chain.

---

## Session Routing Rules

Sessions group related envelopes for context management and agent handoff.

- A `session_id` MUST be stable for the duration of a conversational thread. It
  MUST be derived from `tenant_id + channel + thread_id` (or `message_id` if
  `thread_id` is absent) using a deterministic hash.

- Agents MAY read prior envelopes in the same session from the LKS session store.
  Cross-session reads MUST require explicit `memory.read.cks` capability.

- Session expiry is governed by `policy_profile.session_ttl_seconds`. Expired
  sessions MUST be archived and MUST NOT be auto-resumed by an agent.

- If a session spans more than one channel (e.g., Slack DM → Slack channel), a
  new `session_id` MUST be created and the original `session_id` linked as
  `parent_session_id` in the session metadata record.

---

## Anti-Spoof Validation

Each channel kind has a required validation method:

| Channel | Method |
|---|---|
| `slack` | Verify `X-Slack-Signature` HMAC-SHA256 header against signing secret. |
| `telegram` | Verify Bot API secret token header; validate `chat.id` against registered bot. |
| `lark` | Verify Lark event verification token and message signature. |
| `whatsapp` | Validate Meta webhook signature (`X-Hub-Signature-256`). |
| `signal` | Validate Signal message MAC against registered device identity. |

Failure of any channel-specific validation MUST set `sender_trust: suspicious`
and log a `SECURITY_EVENT` in the ProofGraph before further processing.

---

## Versioning Policy

- The envelope schema is versioned independently of channel connector releases.
- Fields added in minor versions are OPTIONAL; existing consumers MUST NOT
  reject envelopes containing unknown fields.
- Field removals and type changes require a new major schema version.
- Published v1 schemas are immutable per ADR-006.

---

## Security Considerations

- **Integrity.** The canonical hash of an envelope (JCS-serialized, SHA-256) MUST
  be stored in the ProofGraph at ingestion. Any downstream modification of the
  envelope MUST invalidate this hash and MUST be treated as a tampering event.

- **PII in attachments.** Attachments with `payload_class: R2+` or containing
  inferred PII MUST have their `artifact_id` access-controlled via the tenant's
  data classification policy.

- **Replay protection.** `envelope_id` values MUST be stored in a deduplication
  store and checked at ingestion. Duplicate `envelope_id` values MUST be dropped
  with a `DUPLICATE_ENVELOPE` error code logged.

- **Spoofing via metadata.** The `metadata` field is untrusted user-controlled
  data. Governance decisions MUST never depend on `metadata` contents.

---

## References

- ADR-001: HELM Is Execution Authority, Not Assistant Shell
- ADR-005: R0-R3 Action Risk Class Taxonomy
- ADR-006: Schema Namespace Organization
- artifact-manifest-v1.md (this standard set)
- connector-release-v1.md (this standard set)
- skill-bundle-v1.md (this standard set) — `channel.send` capability
- EXECUTION_SECURITY_MODEL.md
- CAPABILITY_MANIFESTS.md
