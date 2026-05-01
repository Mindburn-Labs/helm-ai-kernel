# Architecture Decision Records (ADRs)

This directory contains the durable architectural decisions that shape
the HELM design-system. Each ADR is a short, self-contained markdown
file with the structure: **Status / Context / Decision / Consequences /
References**.

We keep them lightweight (≤ 200 lines each) so they stay readable a
year from now. The intended audience is the next maintainer onboarding
to the codebase, or the next contributor proposing a change that
contradicts a prior decision.

## Index

| #    | Title                                                        | Status     |
| ---- | ------------------------------------------------------------ | ---------- |
| 0001 | [Monorepo layout](./0001-monorepo-layout.md)                  | Accepted   |
| 0002 | [Two-source-of-truth tokens](./0002-token-sourcing.md)        | Accepted   |
| 0003 | [`asChild` composition pattern](./0003-asChild-pattern.md)    | Accepted   |
| 0004 | [No CSS-in-JS runtime](./0004-no-css-in-js-runtime.md)        | Accepted   |
| 0005 | [Locale defaults + RTL detection](./0005-locale-defaults.md)  | Accepted   |

## When to write an ADR

Open a new ADR (`NNNN-short-slug.md`) when you:

- Choose between two non-trivially-different technologies (a CSS-in-JS
  library, a state-management approach, a build tool).
- Lock in a public-API pattern that consumers will rely on
  (`asChild`, `<Form>` orchestration, controlled-vs-uncontrolled).
- Decide *not* to do something significant (e.g. ICU MessageFormat,
  Storybook, runtime CSS-in-JS) — recording the path-not-taken keeps
  the next contributor from re-litigating it.

## When to update an ADR

If a decision changes, mark the old ADR as **Superseded by
NNNN-…** and write a new one. Do not delete or rewrite history —
the rationale of the *old* decision remains useful context.
