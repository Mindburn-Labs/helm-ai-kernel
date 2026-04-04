# ADR-006: Schema Namespace Organization

**Status:** Accepted
**Date:** 2026-04-04

## Context

HELM already has JSON schemas in `schemas/` (research, connectors, receipts) and `protocols/json-schemas/` (kernel, effects, tooling, policy). The final-state features require new schema directories for signals, work items, workforce, approvals, and business effects.

## Decision

New schemas are organized under `helm-oss/schemas/` in the following namespace:

```
schemas/
  signals/              # Signal ingestion
    signal_envelope.v1.json
    signal_cluster.v1.json
    program_watch.v1.json
    person_watch.v1.json

  work/                 # Action proposals and work items
    action_proposal.v1.json
    action_bundle.v1.json
    draft_artifact.v1.json
    context_slice.v1.json

  workforce/            # Virtual employees
    virtual_employee.v1.json
    manager_assignment.v1.json
    capability_grant.v1.json
    budget_envelope.v1.json

  approvals/            # Approval ceremonies
    approval_request.v1.json
    approval_decision.v1.json
    approval_ceremony_record.v1.json

  effects/              # Business effect schemas
    send_email_effect.v1.json
    send_chat_message_effect.v1.json
    create_calendar_event_effect.v1.json
    screen_candidate_effect.v1.json
    request_purchase_effect.v1.json

  receipts/             # (extends existing)
    outbound_comm_receipt.v1.json
    approval_receipt.v1.json
    connector_effect_receipt.v1.json
    runtime_adapter_receipt.v1.json
```

### Conventions

- All schemas use JSON Schema draft 2020-12.
- `$id` follows pattern: `https://helm.mindburn.org/schemas/{dir}/{name}.v1.json`
- File naming: `{snake_case_name}.v1.json`
- Breaking changes require a new version (`v2.json`); published `v1` schemas are immutable.

## Consequences

- Clear separation between signal/work/workforce/approval/effect/receipt concerns.
- Existing `schemas/research/` and `schemas/connectors/` are untouched.
- SDKs can generate types from these schemas.
