# Standards Submissions — Status Tracker

Active submissions to external standards bodies. One row per target. Each row tracks status, latest action, and next action.

Primary contact for all external standards inbound: `conformance@mindburn.org`.

## Active submissions

| # | Target | Artifact | Status | Latest action | Next action | Owner |
|---|--------|----------|--------|---------------|-------------|-------|
| 1 | OWASP Agentic AI Security WG | [owasp-agentic-top10-helm-proposal.md](./owasp-agentic-top10-helm-proposal.md) | Draft ready | 2026-04-15: draft completed | Email OWASP Agentic AI WG chair + post to WG mailing list | conformance-lead |
| 2 | Coalition for Secure AI (CoSAI) — Security of AI Agents | [cosai-proofgraph-taxonomy.md](./cosai-proofgraph-taxonomy.md) | Draft ready | 2026-04-15: draft completed | Contact CoSAI secretariat for workstream onboarding | conformance-lead |
| 3 | LF AI & Data — TAC | [lfai-conformance-profile-v1.md](./lfai-conformance-profile-v1.md) | Draft ready, blocked on CLA | 2026-04-15: draft completed | Execute CCLA per [ADR-0004](../../decisions/0004-lfai-cla-signatory.md) before intake | conformance-lead + ceo |

## Status legend

- **Draft ready** — document written, ready for external submission.
- **Submitted** — submission sent (date + channel recorded in this table).
- **In review** — body is actively reviewing.
- **Accepted / Published** — body adopted as draft or official doc.
- **Rejected / Withdrawn** — body declined or we withdrew.
- **Blocked on <X>** — cannot proceed until X.

## Submission hygiene

Every submission document at `docs/standards/submissions/*.md` must carry a YAML front-matter block including:

```yaml
---
title: "..."
target: "OWASP Agentic AI WG" | "CoSAI Security of AI Agents" | "LF AI & Data TAC"
submission_status: "draft" | "submitted_YYYY-MM-DD" | "in_review" | "accepted" | "rejected"
submission_thread: "<url>"
last_updated: "YYYY-MM-DD"
---
```

This allows automated tracking — see `scripts/standards/audit-submissions.sh` (TBD) which parses frontmatter and updates this file.

## Draft inbound emails (ready to send)

### Email 1 — OWASP Agentic AI Security WG intro

```
To:       owasp-agentic-ai@owasp.org  (or current WG list)
Cc:       chair-address, secretary-address
Bcc:      conformance@mindburn.org
Subject:  Proposal: enforcement-layer reference implementation for OWASP Agentic Top 10

Dear OWASP Agentic AI Security Working Group,

I'm writing on behalf of Mindburn Labs, maintainers of HELM OSS (Apache-2.0,
github.com/Mindburn-Labs/helm-oss), a fail-closed AI execution governance kernel
in production use since Q1 2026.

We've prepared a submission proposing:

1. Code-level enforcement references for each ASI-01 through ASI-10 risk, with
   file:line citations and machine-checkable invariants.
2. A six-axis Conformance Profile v1 acceptance suite that defines the minimum
   verifiable surface for "Agentic-Top-10-mitigating" implementations.

The proposal (Apache-2.0) is at:
https://github.com/Mindburn-Labs/helm-oss/blob/main/docs/standards/submissions/owasp-agentic-top10-helm-proposal.md

We're not proposing HELM become the canonical implementation — we offer its
code as the anchor that removes ambiguity about what "covered" means at the
enforcement level.

We'd welcome a 30-minute WG presentation slot or async discussion, whichever
fits the group's cadence. I'll follow up with a WG-GitHub PR separately.

Primary contact: conformance@mindburn.org
Backup: research@mindburn.org

Thanks,
[Signatory]
Mindburn Labs
```

### Email 2 — CoSAI Security of AI Agents workstream

```
To:       info@cosai.dev  (or workstream-specific alias when identified)
Cc:       security-of-agents-chair@...
Bcc:      conformance@mindburn.org
Subject:  Contribution offer: ProofGraph node-type taxonomy for cross-org AI audit

Hello CoSAI Secretariat,

Mindburn Labs (maintainers of HELM OSS) would like to contribute a proposed
ProofGraph node-type taxonomy as a candidate interchange vocabulary for
cross-organizational AI action auditing.

The taxonomy has been in production use for ~6 months, is formally specified
in TLA+, and is released under Apache-2.0. We believe it's the right fit for
the Security of AI Agents workstream.

Full proposal (4,000 words):
https://github.com/Mindburn-Labs/helm-oss/blob/main/docs/standards/submissions/cosai-proofgraph-taxonomy.md

Specifically seeking:
1. Workstream-membership onboarding call.
2. Workstream-meeting agenda slot (15–30 min).
3. Path to formal contribution review.

Primary contact: conformance@mindburn.org

Thanks,
[Signatory]
Mindburn Labs
```

### Email 3 — LF AI & Data TAC

```
To:       info@lfaidata.foundation
Cc:       tac-chairs@...
Bcc:      conformance@mindburn.org
Subject:  Proposal: HELM Conformance Profile v1 as LFAI working-group draft

Dear LF AI & Data Foundation,

Mindburn Labs proposes contributing HELM Conformance Profile v1 (Apache-2.0)
as a working-group draft under LFAI governance. The profile defines a six-axis
acceptance suite for AI execution governance implementations, with a
machine-readable YAML checklist and TLA+-verified invariants.

Our goal is neutral standards hosting so adoption across competing frameworks
can be coordinated through a trusted body rather than any single vendor.

Full proposal (4,500 words):
https://github.com/Mindburn-Labs/helm-oss/blob/main/docs/standards/submissions/lfai-conformance-profile-v1.md

Our CEO is the designated signatory for the Corporate CLA; counsel review is
underway with expected signing by 2026-06-10 (per our internal ADR-0004).

Specifically seeking:
1. Acknowledgment of receipt.
2. Routing to the appropriate TAC or committee.
3. Technical deep-dive meeting slot.
4. Venue + IP decision within a Q2 2026 review window.

Primary contact: conformance@mindburn.org

Thanks,
[Signatory]
Mindburn Labs
```

## Automation (future)

A small Go/Python script that:
1. Parses YAML front-matter of all `docs/standards/submissions/*.md`.
2. Updates the table in this file.
3. Runs in CI on every PR touching `docs/standards/submissions/`.

Pending; not a v0.4.0 blocker.
