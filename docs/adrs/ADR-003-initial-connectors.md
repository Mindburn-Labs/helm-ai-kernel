# ADR-003: Initial Connector Set

**Status:** Accepted
**Date:** 2026-04-04

## Context

Connector sprawl is a trap. Enterprise-grade execution authority requires deep, well-governed connectors over breadth.

## Decision

Initial connector set is restricted to the **core enterprise stack**:

| Priority | Connector | ID | Auth | Primary Effects |
|---|---|---|---|---|
| 1 | Gmail | `gmail-v1` | Google OAuth2 | send, read_thread, list, draft |
| 2 | Slack | `slack-v1` | Bot Token (xoxb-) | send_message, read_channel, list |
| 3 | Google Calendar | `gcalendar-v1` | Google OAuth2 | create_event, read_availability, update |
| 4 | Google Docs/Drive | `gdocs-drive-v1` | Google OAuth2 | read_doc, create_doc, list_files |
| 5 | Meeting Transcripts | `meetings-v1` | Varies | list_transcripts, get_transcript (READ-only) |
| 6 | GitHub | `github-v1` | GitHub App | list_prs, read_pr, create_issue, comment |
| 7 | Linear | `linear-v1` | API Key | create_issue, update_issue, list |

Shared: `connectors/oauth2/` for Google API token management.

## Deferred

- WhatsApp, iMessage, SMS, consumer messaging
- Salesforce, HubSpot CRM (until revenue-ops pack matures)
- Jira (Linear preferred; Jira adapter later)

## Consequences

- Google OAuth2 token management is centralized in a shared package.
- Each connector implements `effects.Connector` interface with ZeroTrust policy.
- Write connectors require VERIFIED trust level; read-only connectors may use RESTRICTED.
- Rate limits enforced per-connector via `connector.TrustPolicy`.
