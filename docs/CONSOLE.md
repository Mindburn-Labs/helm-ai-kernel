---
title: HELM OSS Console
last_reviewed: 2026-05-05
---

# HELM OSS Console

## Audience

Use this page when you need the public `helm-oss/console` guidance without opening repo internals first. It is written for developers, operators, security reviewers, and evaluators who need to connect the docs website back to the owning HELM source files.

## Outcome

After this page you should know what this surface is for, which source files own the behavior, which public route or adjacent page to use next, and which validation command to run before changing the claim.

## Source Truth

- Public route: `helm-oss/console`
- Source document: `helm-oss/docs/CONSOLE.md`
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

This scheme maps the main sections of HELM OSS Console in reading order.

```mermaid
flowchart LR
  Page["HELM OSS Console"]
  A["What It Covers"]
  B["Running Locally"]
  C["Production Boundary"]
  D["Verification"]
  Page --> A
  A --> B
  B --> C
  C --> D
```

HELM OSS ships one browser frontend: `apps/console`.

The Console is a self-hostable operator surface for the OSS kernel. It is built
with React, Vite, TypeScript, and `@helm/design-system-core`; it does not carry a
second component system, Tailwind layer, private package, or generated marketing
surface.

## What It Covers

- Command-first governance over the local kernel.
- Live receipts from `/api/v1/receipts` and `/api/v1/receipts/tail`.
- Intent evaluation through `/api/v1/evaluate`.
- ProofGraph, replay, evidence, conformance, MCP, trust, approval, incident,
  audit, developer, and settings navigation surfaces.
- A read-only bootstrap contract at `/api/v1/console/bootstrap` for kernel
  version, workspace, health, counts, recent receipts, conformance, and MCP
  scope state.

## Running Locally

Build the design-system package and Console:

```bash
make build-console
```

Start the kernel with the Console enabled:

```bash
./bin/helm serve --policy ./release.high_risk.v3.toml --console
```

The default `helm serve` bind is `127.0.0.1:7714`. Console assets are loaded from
`apps/console/dist` by default, or from `HELM_CONSOLE_DIR` / `--console-dir` when
set.

## Production Boundary

The Console is OSS and self-hostable. It is not the managed Mindburn hosted
service. The OSS repository still excludes billing, hosted retention, proprietary
operator workflows, entitlement systems, private connector programs, and managed
multi-region operations.

`helm serve --console` serves static assets with the same security middleware as
the API. API-like paths never fall through to `index.html`, so broken contracts
remain visible during development and deployment.

## Verification

Run the Console gate:

```bash
make test-console
```

Run the broader platform gate:

```bash
make test-platform
```
