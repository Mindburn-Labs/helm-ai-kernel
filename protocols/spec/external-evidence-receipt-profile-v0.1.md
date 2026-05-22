---
title: "HELM External Evidence Receipt Profile"
status: draft
version: "0.1"
created: 2026-05-21
---

# HELM External Evidence Receipt Profile v0.1

## Purpose

This profile defines the vendor-neutral envelope HELM accepts for externally
produced host and network evidence. It is designed for evidence import,
offline verification, and correlation with HELM authority receipts.

The profile does not require a specific recorder implementation. eBPF, syscall
recorders, host agents, cloud workload monitors, and hardware-backed systems
can all emit compatible chains when they provide the required fields and
signature material.

## Non-Goals

This profile does not claim HELM records packets, attaches eBPF programs,
performs seccomp enforcement, validates TPM quotes, or blocks network traffic at
the host boundary. HELM consumes and correlates external host evidence unless a
separate, tested verifier implements a stronger hardware-rooted check.

## Chain Envelope

An external receipt chain is a JSON object or JSONL stream containing
`ExternalHostReceipt` entries. JSON envelopes SHOULD include:

```json
{
  "schema_version": "external_receipt_chain.v1",
  "chain_id": "host-chain-2026-05-21",
  "source_vendor": "example-recorder",
  "source_profile": "external-evidence-receipt-profile-v0.1",
  "event_schema_hash": "sha256:<hex>",
  "receipt_chain_hash": "sha256:<hex>",
  "public_keys": [
    {
      "key_id": "host-key-1",
      "algorithm": "Ed25519",
      "public_key_hex": "<hex>"
    }
  ],
  "receipts": []
}
```

HELM verifiers MUST NOT fetch keys from the network during offline verification.
Public keys must be embedded in the chain, passed on the CLI, or provided from a
local trust store.

## Receipt Fields

Each `ExternalHostReceipt` records a single host-observed event. Required
fields:

| Field | Description |
| --- | --- |
| `receipt_id` | Stable receipt identifier from the source system. |
| `host_id` | Stable host, node, VM, or workload host identity. |
| `event.destination_ip` or `event.destination_host` | Destination observed by the host recorder. |
| `event.destination_port` | Destination port. |
| `event.protocol` | Network protocol such as `tcp`, `udp`, or `tls`. |
| `event.timestamp` | RFC 3339 timestamp of observation. |
| `receipt_hash` | SHA-256 hash of the canonical receipt with `receipt_hash` and `signature` blank. |

Recommended fields:

| Field | Description |
| --- | --- |
| `process_identity` | Stable process identity or executable fingerprint. |
| `process_ancestry` | Parent process identities from the recorder. |
| `agent_id`, `workload_id`, `sandbox_lease_id` | Correlation hints for HELM authority receipts. |
| `bytes_sent`, `bytes_received` | Egress volume evidence. |
| `prev_receipt_hash` | Previous receipt hash in source order. |
| `signing_key_id`, `signature_algorithm`, `signature` | Offline signature material. |
| `hardware_root` | Structural root-of-trust claim, if present. |

## Hashing and Signatures

Receipt hashes use JCS canonical JSON and SHA-256:

1. Set `receipt_hash` and `signature` to empty strings.
2. Canonicalize the receipt with JCS.
3. Compute SHA-256 and encode as `sha256:<hex>`.

Ed25519 signatures, when present, sign the canonical receipt after
`receipt_hash` is populated and `signature` is blank. Signatures MAY be hex or
base64 encoded.

`prev_receipt_hash` links receipts in source order. The chain hash is the
SHA-256 hash of newline-joined receipt hashes, encoded as `sha256:<hex>`.

## Hardware Root Claims

`hardware_root` stores fields such as:

```text
kernel_measurement_sha256
execution_profile
hardware_root_type
quote_format
quote_blob_b64
quote_verifier
signing_key_nonexportable
measurement_time
boot_sequence_ref
verification_status
```

In this v0.1 profile, HELM structurally checks these fields and reports
unsupported or unverified hardware roots as `not_verified`. Cryptographic TPM2,
TEE, or cloud attestation validation is not successful unless a real verifier is
implemented and exercised against real artifacts.

## EvidencePack Layout

Native EvidencePack v1 bundles store imported host evidence under:

```text
host_evidence/<source>/<chain-file>
```

Launchpad numbered bundles store the same evidence under:

```text
11_HOST_EVIDENCE/<source>/<chain-file>
```

Verifiers MUST accept both layouts.

## Correlation Results

HELM correlates host evidence to authority receipts using deterministic
precedence:

1. Exact `workload_id`, `sandbox_lease_id`, or `agent_id`.
2. Process identity or process ancestry.
3. Destination, protocol, and timestamp window.
4. Byte-volume and policy ceiling checks.

Correlation results use `HostCorrelationResult` and may emit a
`BOUNDARY_DRIFT` receipt when observed host behavior conflicts with HELM
authority.
