---
title: Hosted Metering Contract
last_reviewed: 2026-07-12
---

# Hosted Metering Contract

The OSS kernel is free and makes no metering network calls by default. Hosted
metering remains disabled unless an operator provides the server-owned settings
below and explicitly sets `HELM_METERING_ACTIVATE=1`:

- `HELM_METERING_URL`
- `HELM_METERING_SERVICE_TOKEN`
- `HELM_METERING_ACTIVATE=1`

With no activation flag, the local/OSS kernel stays network-free even if a URL
is present. A partial activated configuration is a startup error. Once enabled,
an unavailable authorization or settlement fails the request closed; it never
falls back to an unmetered effect or a user/session credential.

Hosted mode also requires explicit server-owned `HELM_RUNTIME_TENANT_ID`,
`HELM_RUNTIME_WORKSPACE_ID`, and `HELM_RUNTIME_PRINCIPAL_ID` bindings. HTTP
ingresses must match those bindings through authenticated context. The HTTP MCP
gateway receives the provisioned binding only after the matching runtime
tenant/workspace/principal authentication check; standalone MCP HTTP must also
enable authentication. Unauthenticated MCP stdio refuses to start in hosted
mode rather than becoming an unmetered bypass.

## Service contract

The kernel uses a service Bearer token. The control plane derives its
tenant/workspace/principal scope solely from that validated bearer, never from
caller or kernel-supplied scope headers. The kernel never forwards a caller
credential, plan, price, credit quantity, monetary value, connector
attestation, OEM share, or pricing version.

| Phase | Method and path |
| --- | --- |
| Pre-dispatch authorization | `POST /api/v1/metering/authorize` |
| Post-receipt settlement | `POST /api/v1/metering/settle` |

Required request headers are:

```text
Authorization: Bearer <server-owned service token>
Idempotency-Key: authorize:<decision_receipt_id> | settle:<settlement_receipt_id>
```

The only authorization body is:

```json
{
  "ingress": "api.evaluate | openai.proxy | mcp.gateway | cli.proxy | adapter",
  "decision_receipt_id": "rcpt_…"
}
```

The settlement body binds the server-issued authorization to the durable
completion receipt:

```json
{
  "authorization_id": "auth_…",
  "settlement_receipt_id": "rcpt_…"
}
```

The control plane verifies the referenced receipt and derives the commercial
classification, credits, cents, pricing version, connector attestation, and
OEM allocation. Positive cents are accepted only for source-owned,
receipt/connector-attested `value_weighted` claims. The kernel has no field by
which an agent or ingress can select any of those values.

## Credit catalogue and approval lifecycle

The source-owned control-plane catalogue is:

| Event | Credits | Lifecycle |
| --- | ---: | --- |
| Routine `ALLOW` | 0 | Authorize and settle the verified receipt. |
| `DENY` | 1 | Authorize and settle the verified refusal receipt. |
| `ESCALATE` routing transition | 0 | Record as routing only; do not settle a ceremony from this transition. |
| `approval_ceremony` | 10 | Reserve once when a durable ceremony begins; settle once on a durable completion receipt, or release on expiry/rejection. |

An `ESCALATE` never receives an extra one-credit charge and must not be settled
as a completed ceremony. The completion receipt, not the initial escalation,
is the billable proof for the single 10-credit `approval_ceremony` event.

## Current activation boundary

The control plane now exposes the service-auth compatibility adapter at the
two paths above. It is default-off and derives scope solely from a validated
server-configured bearer. Its required Control Plane bindings are
`HELM_COMMERCIAL_METERING_SERVICE_TOKEN`,
`HELM_COMMERCIAL_METERING_SERVICE_TENANT_ID`,
`HELM_COMMERCIAL_METERING_SERVICE_WORKSPACE_ID`, and
`HELM_COMMERCIAL_METERING_SERVICE_PRINCIPAL_ID`; a partial configuration is a
startup error and an all-empty configuration registers no route. It also needs
an enabled commercial meter and a trusted receipt verifier before a call can
succeed. A kernel with
`HELM_METERING_ACTIVATE=1` but an unconfigured adapter fails closed at
authorization; it never bridges through the older session-scoped workspace
routes.

The legacy kernel approval endpoint (`POST /api/v1/kernel/approve`) currently
returns an approval status but does not carry the initial escalation receipt,
create a hosted reservation, or emit a control-plane settlement receipt. It is
therefore not a safe implementation point for ceremony billing yet. The future
adapter/approval owner must link the durable initial and completion receipts;
the kernel must not fabricate that association from request JSON.

Hosted OpenAI proxying rejects streaming responses until a receipt-aware
streaming settlement protocol exists. Hosted MCP requires a trusted
pre-dispatch decision-receipt provider and a durable executor settlement
receipt; the local MCP runtime has neither provider wiring and refuses hosted
activation instead of generating a synthetic ID. The standalone CLI proxy has
the same limitation: it can write a post-effect receipt but has no trusted
pre-dispatch decision provider, so it also refuses hosted activation. Compatibility
activation remains blocked until the adapter can verify each ingress's
source-owned receipts.
