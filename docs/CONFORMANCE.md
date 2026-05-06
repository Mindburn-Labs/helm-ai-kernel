---
title: Conformance
last_reviewed: 2026-05-05
---

# Conformance

## Audience

## Outcome

After this page you should know what this surface is for, which source files own the behavior, which public route or adjacent page to use next, and which validation command to run before changing the claim.

## Source Truth

- Public route: `helm-oss/conformance`
- Source document: `helm-oss/docs/CONFORMANCE.md`
- Public manifest: `helm-oss/docs/public-docs.manifest.json`
- Source inventory: `helm-oss/docs/source-inventory.manifest.json`
- Validation: `make docs-coverage`, `make docs-truth`, and `npm run coverage:inventory` from `docs-platform`

Do not expand this page with unsupported product, SDK, deployment, compliance, or integration claims unless the inventory manifest points to code, schemas, tests, examples, or an owner doc that proves the claim.

## Troubleshooting

| Symptom | First check |
| --- | --- |
| The public page and source behavior disagree | Treat the source path in `Source Truth` as canonical, then update the docs and source-inventory row in the same change. |
| A link or route is missing from the docs website | Check `docs/public-docs.manifest.json`, `llms.txt`, search, and the per-page Markdown export before changing navigation. |
| A claim is not backed by code or tests | Remove the claim or add the missing code, example, schema, or validation command before publishing. |

## Diagram

This scheme maps the main sections of Conformance in reading order.

```mermaid
flowchart LR
  Page["Conformance"]
  A["Run the Kernel Conformance Command"]
  B["Run the Conformance Test Suite"]
  C["Profile Material"]
  D["What L1 and L2 Mean in This Repo"]
  Page --> A
  A --> B
  B --> C
  C --> D
```

HELM keeps a retained conformance profile under `tests/conformance/profile-v1/`. The profile describes the minimum checks an implementation must pass to match the public OSS kernel behavior documented in this repository.

## Run the Kernel Conformance Command

```bash
./bin/helm conform --level L1 --json
./bin/helm conform --level L2 --json
./bin/helm conform negative --json
./bin/helm conform vectors --json
```

The public API exposes the same negative gates at
`GET /api/v1/conformance/negative` and `GET /api/v1/conformance/vectors`.
Reports can be created and read through `POST /api/v1/conformance/run`,
`GET /api/v1/conformance/reports`, and
`GET /api/v1/conformance/reports/{report_id}`.

## Run the Conformance Test Suite

```bash
cd tests/conformance
go test ./...
```

## Profile Material

The profile directory contains:

- `checklist.yaml` for the machine-readable checklist
- `profile_test.go` for profile assertions
- `README.md` for the human-readable profile summary

## What L1 and L2 Mean in This Repo

- `L1` covers core structural correctness such as canonicalization, schema handling, receipt shape, offline verification, and checkpoint roots.
- `L2` adds MCP execution-firewall behavior: quarantine, tool-list/call consistency, OAuth resource and scope checks, schema pinning, direct-bypass denial, and deny-path receipt emission.
- `L3` covers sandbox grants, ReBAC snapshots, approval ceremonies, budget ceilings, stale tuple/model mismatch denial, and backend outage denial.
- `L4` covers non-authoritative telemetry/coexistence exports, evidence envelope wrappers, framework middleware, and checkpoint inclusion verification.

The exact checks are defined by the code and checklist in `tests/conformance/`, not by this page.

<!-- docs-depth-final-pass -->

## Conformance Completion Path

A conformance page is complete only when it tells a maintainer how to run the profile, how to interpret a failure, and which fixture owns the expected behavior. Keep profiles explicit: runtime decision, receipt canonicalization, verifier replay, policy denial, MCP boundary, and OpenAI-compatible proxy behavior are different surfaces. When adding a profile, add a fixture, a golden expected output, a negative case, and a short compatibility note. Public users should be able to run the command from a clean checkout, compare output to the documented profile, and decide whether a failure is a local environment issue, a schema drift, or an implementation regression.
