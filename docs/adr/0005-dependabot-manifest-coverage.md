# ADR-0005: Validate Dependabot coverage from parsed configuration

Status: Accepted
Date: 2026-10-13
Tracking: HELM-972

## Context

The dependency hygiene checker matched literal `directory:` text for seven
paths. Dependabot already used plural `directories: ['**/*']` for most
ecosystems, so that check reported gaps without evaluating the configuration.
It also omitted Go modules outside its fixed directory list.

## Decision

Parse `.github/dependabot.yml` with safe YAML loading. Resolve singular paths
and plural directory globs relative to the repository. Require every tracked
Go module and recognized SDK manifest to match an entry for its own ecosystem
on the default branch. Retain the existing required manifest and lockfile checks.
Pin the parser and its Python 3.12 Linux wheel hashes in the existing CI
requirements file; use the existing gate self-test discovery for regression tests.

## Consequences

New Go modules automatically enter the coverage check. Comments and entries for
other ecosystems cannot satisfy coverage. Malformed configuration fails the
check. Weekly scheduling and existing groups stay as configured when coverage
has no gap. This check does not execute Dependabot or prove bot update success.

Source: [Dependabot directories reference](https://docs.github.com/en/code-security/reference/supply-chain-security/dependabot-options-reference#directories-or-directory).
