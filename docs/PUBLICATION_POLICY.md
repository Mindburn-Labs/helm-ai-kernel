---
title: Publication Policy
last_reviewed: 2026-07-01
---

# Publication Policy

The kernel repository can contain more public-safe source documents than the
live docs site publishes. The live site should stay small and proof-oriented.

## Route Authority

- `docs/public-docs.manifest.json` marks source documents that are eligible for
  public use.
- The docs app publication policy chooses the smaller live route set.
- The deployed `route-manifest.json` is the route truth for the live host.
- Unknown routes, private namespaces, and non-Kernel product surfaces must
  return non-200 responses at the edge.

## Live Public Shape

The public site should lead with:

- local quickstart proof;
- what HELM is and is not claiming;
- integrations for MCP and OpenAI-compatible traffic;
- offline receipt and EvidencePack verification;
- a compact API/reference surface for local proof operations;
- support and troubleshooting.

Generated API pages are fail-closed. They should be published only for local
proof and core boundary operations. Console diagnostics, identity, billing,
trust-key mutation, private control-plane, secret, and deployment runbook
surfaces stay out of the live public route set.

## Denied Namespaces

The public host must not publish reserved account, private operations,
control-plane, backend, product-console, or platform namespaces. The edge should
return a non-200 response with a noindex robots header for those namespaces and
for unknown routes.

## Validation

```bash
python3 scripts/check_documentation_truth.py
HELM_KERNEL_REPO_PATH=/path/to/helm-ai-kernel npm run ci
HELM_DOCS_URL=https://helm.docs.mindburn.org
curl -i "$HELM_DOCS_URL/reserved-test"
curl -i "$HELM_DOCS_URL/no-such-route"
```
