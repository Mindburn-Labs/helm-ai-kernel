---
title: "ADR-0002 — CI Runner Strategy (macOS + Windows Cross-OS Matrix)"
status: Accepted
date: 2026-04-15
deciders: ops-lead, release-eng
supersedes: none
---

# ADR-0002 — CI Runner Strategy for Cross-OS Builds

## Context

HELM OSS ships a Go binary cross-compiled to 5 platforms (linux/amd64, linux/arm64, darwin/amd64, darwin/arm64, windows/amd64). Release gate #4 per the production deployment plan requires benchmarks to run on representative hardware for each platform to catch platform-specific regressions (e.g., darwin/arm64 crypto performance, windows SQLite locking).

The fuzz, chaos, and Apalache workflows run on ubuntu-latest (free, unlimited). The gap is darwin + windows.

## GitHub-hosted runner pricing (2026-04)

| Runner | Per-minute cost | Notes |
|--------|-----------------|-------|
| ubuntu-latest (public repo) | **Free** | unlimited for public repos |
| ubuntu-latest (private repo) | $0.008/min | included in free tier up to 2000 min/mo |
| macos-latest (14 core) | **$0.08/min** | 10× Linux premium |
| windows-latest | $0.016/min | 2× Linux premium |
| macos-latest-xlarge (M1 Pro 6 core) | $0.16/min | 20× Linux premium |

## Estimated monthly usage (v0.4.0 cadence)

Benchmarks: 5 platforms × nightly (30 days) × ~10 min each = 1,500 min/platform.

| Platform | Monthly minutes | Monthly cost (GitHub-hosted) |
|----------|-----------------|-------------------------------|
| ubuntu-latest ×2 arches | ~3,000 | $0 (public repo) |
| macos-latest ×2 arches | ~3,000 | ~$240 |
| windows-latest | ~1,500 | ~$24 |
| **Total GitHub-hosted** | ~7,500 | **~$264/month** |

At this volume, GitHub-hosted is **cheaper than self-hosting** for the first 12 months (any dedicated Mac mini or Windows box would cost $1K+ upfront for < $25 monthly marginal value).

## Scale thresholds — when self-hosted becomes cheaper

- Self-hosted macOS: a Mac mini M2 (~$1K) covers 5,000+ min/month at zero marginal cost. Breakeven vs GitHub-hosted at ~12.5K min/month (≈83 hrs/month of CI).
- Self-hosted Windows: a mid-tier PC (~$1K) at 5K min/month marginal is the same breakeven profile.

Neither threshold is reached at v0.4.0's scope.

## Decision

**Phase 1 (through v0.6.0 or ~Q4 2026)**: **all runners are GitHub-hosted**. No self-hosted infrastructure.

Rationale:
1. At forecast volume (~7,500 min/month), GitHub-hosted costs ~$264/month — under the $1K hardware + ~$50/month colocation cost of self-hosting.
2. Operational burden of self-hosted runners (patching, token rotation, physical presence for darwin/arm64) exceeds cash savings.
3. GitHub-hosted runners are trusted by SLSA provenance attestation out of the box; self-hosted runners require explicit SLSA builder trust (extra audit burden).

**Phase 2 trigger — promote to self-hosted when ANY of:**
- Monthly CI spend > $1,000
- CI queue time > 15 min p99 for critical path
- Need for ARM64 Linux (not yet GitHub-hosted natively for arm64 beyond the GA tier)
- Regulatory requirement for hardware provenance (unlikely pre-v1.0)

**Explicit reject**: self-hosting now. Premature cost.

## Budget allocation

Build `$300/month` into the ops budget for CI runner time starting 2026-04. This covers the full cross-OS benchmark + release matrix with ~10% headroom.

## Monitoring

- Track `billing/usage` via `gh api` monthly.
- Alert if monthly spend > $500 (approaching self-hosting crossover).
- Review every quarter.

## Windows-specific caveat

Windows runners have the highest flakiness rate per GitHub's own reports (pathname limits, locked-file issues during SQLite benchmarks). Budget extra retry tolerance on windows-latest jobs. Any chronic flake gets an escape hatch via `continue-on-error: true` with a separate blocker issue tracking the root cause.

## References

- GitHub Actions billing docs: https://docs.github.com/en/billing/managing-billing-for-github-actions
- SLSA builder trust model: https://slsa.dev/spec/v1.0/requirements#isolated
- `docs/BENCHMARKS.md` — the workload this ADR supports
