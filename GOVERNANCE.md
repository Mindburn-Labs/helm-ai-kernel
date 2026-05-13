# Governance

This document describes how the helm-ai-kernel project is governed. It is the
canonical reference for maintainer responsibilities, decision-making, and
project change control. The governance model is designed to satisfy CNCF
Sandbox eligibility and to scale to a multi-organization maintainer set.

## Project Scope

helm-ai-kernel is the open-source kernel for governed AI tool calling. Its public
surface is documented in `README.md` and bounded by `docs/OSS_SCOPE.md`.
Anything outside that scope (hosted control-plane features, commercial
Studio surfaces, private operational tooling) is governed elsewhere and is
not in scope for this project's governance.

## Maintainer Model

The project is led by a small set of maintainers who hold commit access and
the ability to approve releases. The initial roster is listed in
`MAINTAINERS.md`. Maintainers represent themselves first and their
affiliation second; a single organization holds no more than half of the
seats once the maintainer set reaches three or more members.

There are three roles:

- **Maintainer** — full commit access, may merge after a single review,
  approves releases, votes on governance changes.
- **Reviewer** — may approve PRs in a defined area; cannot merge; named
  in `MAINTAINERS.md` under the relevant area.
- **Contributor** — anyone who opens a PR or issue. No formal status; the
  project welcomes contributions per `CONTRIBUTING.md`.

### Becoming a Maintainer

Reviewers who consistently demonstrate technical judgement and project
stewardship are invited to become maintainers by lazy consensus of the
existing maintainers. The path is:

1. Make sustained, high-quality contributions over at least three months.
2. Be nominated by an existing maintainer.
3. Receive lazy-consensus approval (no objections within seven days) from
   the existing maintainers.
4. Be added to `MAINTAINERS.md` in the same PR that grants commit access.

### Stepping Down

Maintainers may step down at any time by removing themselves from
`MAINTAINERS.md`. Inactive maintainers (no review or merge activity for
six months) are moved to "Emeritus" status by lazy consensus.

## Decision-Making

The default decision rule is **lazy consensus**: any maintainer may propose
a change, and absence of objection for the configured review window is
treated as approval.

| Decision Type | Rule | Window |
| --- | --- | --- |
| Routine code change | One maintainer review | Same day |
| Architectural change | Lazy consensus | 72 hours |
| Breaking API change | Super-majority (2/3) | 7 days |
| Governance change | Super-majority (2/3) | 14 days |
| Maintainer addition | Lazy consensus | 7 days |
| Maintainer removal | Super-majority (2/3) | 14 days |

A breaking API change is any change to `protocols/`, `api/openapi/`, the
public CLI flag set, or the `core/pkg/contracts/` types. Such changes
require an entry in `CHANGELOG.md` and an SDK version bump.

Votes are conducted on the relevant pull request or in the project's
public discussion forum. Each maintainer has one vote. Affiliated
maintainers do not abstain on technical decisions; they recuse only on
direct conflicts of interest.

## Code of Conduct

The project adopts the Contributor Covenant 2.1
(<https://www.contributor-covenant.org/version/2/1/code-of-conduct/>).
Reports go to `conduct@mindburn.org`. Code-of-conduct decisions are made
by the maintainer set acting as a committee; a maintainer involved in
the report recuses.

## Release Policy

Release process, cadence, and artifact set are documented in `RELEASE.md`.
The release pipeline is automated via `.github/workflows/release.yml`.
Releases ship checksum material, SBOM material, and release attestation.
Cosign bundle and OpenVEX verification apply when those files are attached to
the GitHub release; the current public `v0.4.0` release does not attach
`*.cosign.bundle` or `*.openvex.json` assets. Per-release benchmark snapshots
are pinned by `scripts/release/pin_benchmarks.sh`.

A release is approved when:

1. CI passes on the tagged commit.
2. The reproducibility job in `release.yml` confirms byte-identical builds.
3. At least one maintainer has signed off on the release notes.

## Security Policy

Security reports follow the process in `SECURITY.md`. The maintainer set
is collectively responsible for triage, embargo, and coordinated
disclosure. The default embargo window is 30 days; severity and
exploitability may shorten or lengthen it.

## Conflict Resolution

Technical disagreements that cannot be resolved by discussion escalate
to a maintainer vote under the rules above. Persistent
non-technical disputes escalate to the CNCF TOC liaison once the project
is admitted to the Sandbox; until then, they escalate to the Mindburn-Labs
project lead acting as a neutral arbiter, who is bound to follow the
super-majority rule on governance questions.

## Amendments

Changes to this document require the governance-change rule above
(super-majority, 14-day window). Pull requests must update both this
file and any cross-referenced files in the same PR.

## References

- `MAINTAINERS.md` — current roster
- `CONTRIBUTING.md` — contribution rules
- `SECURITY.md` — vulnerability disclosure
- `RELEASE.md` — release process
- `BEST_PRACTICES.md` — OpenSSF gold-tier mapping
- `docs/governance/cncf-application.md` — CNCF Sandbox application narrative
