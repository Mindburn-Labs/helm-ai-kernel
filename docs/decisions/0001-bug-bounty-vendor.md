---
title: "ADR-0001 — Bug Bounty Vendor Selection"
status: Accepted
date: 2026-04-15
deciders: security-lead, ops-lead
supersedes: none
---

# ADR-0001 — Bug Bounty Vendor Selection

## Context

HELM OSS ships fail-closed AI execution governance. The attack surface includes the Go kernel, 5 language SDKs, MCP gateway, policy engine, and `try.mindburn.org` dashboard. A bug bounty program signals seriousness about vulnerability intake, provides a safe-harbor channel for researchers, and multiplies our pre-GA scrutiny budget without hiring.

## Options considered

### 1. HackerOne

Pros:
- Industry standard. Named programs carry weight with enterprise buyers (CISOs recognize the badge).
- Researcher pool is the largest in the industry (~2M+ registered).
- Triage services (paid tier) reduce Mindburn's operational load.
- VDP (vulnerability disclosure program) tier is free; paid programs start at ~$4K/month retainer + bounties.
- Strong legal safe-harbor template.

Cons:
- Pricing opaque until sales call. Paid programs historically cost $30–60K/year for similar-sized OSS projects.
- Long onboarding (2–4 weeks to go live).

### 2. Bugcrowd

Pros:
- Competitive researcher pool, slightly smaller than HackerOne but higher signal-to-noise in some domains.
- Flexible pricing — includes a free "Open Scope" tier for pre-revenue companies.
- Strong in Web3/crypto space (relevant for HELM's ZK work).
- Integrations: GitHub, Jira, Slack.

Cons:
- Fewer Fortune 500 logos than HackerOne (brand signal weaker).
- Platform UX dated vs HackerOne.

### 3. Self-hosted (GitHub Security Advisories + SECURITY.md)

Pros:
- Zero vendor cost. Uses GitHub's built-in private-vulnerability-reporting + advisories.
- Already enabled on Mindburn-Labs/helm-oss (2026-04-15).
- Researcher communication stays on-platform.
- CVE issuance straightforward via GitHub's CVE Numbering Authority.

Cons:
- No financial bounty without separate payment infrastructure.
- No dedicated triage — Mindburn security-lead handles everything.
- Smaller researcher reach; passive intake only.
- No marketing amplification.

### 4. Huntr.com (Protect AI)

Pros:
- AI-security focused. Matches HELM's domain.
- Operated by Protect AI, growing reputation.
- Listed bounties are AI/ML specific.

Cons:
- Small researcher pool vs HackerOne / Bugcrowd.
- Less established; fewer enterprise recognition signals.

## Decision

**Phase 1 (now through v0.5.0)**: **self-hosted via GitHub Security Advisories + Huntr.com listing**.

Rationale:
1. GitHub Security Advisories + `security@mindburn.org` + SECURITY.md cover the basic intake obligation. All enabled as of 2026-04-15.
2. Huntr.com is cheap (free to list a program) and AI-security-adjacent audiences find HELM there.
3. Before v0.5.0 we don't have the commercial revenue to justify $30–60K/year paid HackerOne. A formal program at that stage is premature.
4. GitHub's CNA capability allows us to issue CVEs directly, which satisfies the audit-trail requirement.

**Phase 2 (v1.0.0 and beyond, or earlier if paid customers ≥ 3)**: **upgrade to HackerOne**.

Rationale:
1. HackerOne's researcher pool + enterprise-buyer recognition becomes the dominant factor once there are paying customers whose procurement asks about bug bounty.
2. At v1.0.0 the codebase is stable enough to warrant professional triage; pre-1.0 churn would burn researcher time.
3. $30–60K/year is defensible when HELM is generating revenue.

**Explicit reject**: Bugcrowd. Close runner-up, but HackerOne's brand signal tips it in enterprise procurement contexts where HELM will compete.

## Consequences

- **Short term**: publish SECURITY.md + enable GHA advisories (✓ done 2026-04-15). List on Huntr.com within 4 weeks.
- **Medium term**: define Phase 2 upgrade trigger (v1.0.0 tag OR 3 paying customers, whichever first).
- **Payment path**: Phase 1 uses no-cost Halls of Fame credit. Phase 2 will use HackerOne's Stripe-integrated bounty payout.
- **Triage SLA**: 48h ack, 7-day response, 30-day patch, per SECURITY.md.

## References

- `SECURITY.md` — Responsible Disclosure Policy section
- `docs/ops/incident-response.md` — to be written when Phase 5 commercial incident response ships
- GitHub Security Advisories docs: https://docs.github.com/en/code-security/security-advisories
- Huntr.com AI/ML bug bounty: https://huntr.com
