# ADR-002: First Battlefield Is Enterprise Comms and Executive Ops

**Status:** Accepted
**Date:** 2026-04-04

## Context

HELM could target developer tooling, infrastructure automation, customer support, or executive operations as its first productized domain. The strongest signal is that enterprise operators (founders, executives, chiefs of staff) have the highest pain from ungoverned automation touching email, calendar, hiring, and customer communications.

## Decision

The first battlefield is **enterprise communications and executive operations**.

Target workflows:
- Meeting follow-ups and action item extraction
- Email triage, drafting, and sending
- Calendar scheduling and availability management
- Recruiting pipeline (resume screening, candidate outreach, interview scheduling)
- Customer relationship follow-ups
- Procurement and spend requests

## Consequences

- Signal ingestion prioritizes email, chat, calendar, meeting transcripts, and documents.
- Consumer messaging channels (WhatsApp, iMessage, SMS) are deferred.
- Reference packs are built for executive-ops, recruiting, revenue-ops, and procurement.
- Product legibility comes from "a founder can use this daily" not "a developer can integrate this."
