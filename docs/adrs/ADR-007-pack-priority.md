# ADR-007: Reference Pack Priority

**Status:** Accepted
**Date:** 2026-04-04

## Context

Reference packs are workspace templates that pre-configure programs, virtual employees, capability grants, budget envelopes, and signal watches. They create immediate product legibility by proving end-to-end workflows.

## Decision

Pack priority order:

| Priority | Pack | Primary User | Key Flows |
|---|---|---|---|
| 1 | **Executive Ops** | Founder / CEO / CoS | Meeting follow-ups, email triage, scheduling, doc summaries |
| 2 | **Recruiting** | Hiring manager / recruiter | Resume triage, candidate comms, interview scheduling |
| 3 | **Revenue / Customer Ops** | Account exec / CSM | Customer follow-ups, CRM sync, escalation routing |
| 4 | **Procurement / Spend** | Ops / finance | Vendor intake, spend requests, budget checks |

### Pack composition

Each pack includes:
- Pre-defined **programs** (signal routing categories)
- Pre-configured **virtual employees** with roles and budgets
- **Capability grants** binding employees to specific connectors and tools
- **Budget envelopes** with daily spend caps
- **Signal watches** (filter rules for ingestion routing)
- Optional **policy overlay** (pack-specific governance rules)

### Installation

Packs are installed via `POST /api/v1/workspaces/{id}/reference-packs/install`, which atomically creates all resources and returns an installation receipt.

## Consequences

- Executive Ops is built first because it exercises the widest connector surface (email, calendar, chat, meetings, docs).
- Each subsequent pack reuses infrastructure from the previous pack.
- Packs are the primary sales and demo artifact for enterprise buyers.
- Pack installation is idempotent (re-installing updates, does not duplicate).
