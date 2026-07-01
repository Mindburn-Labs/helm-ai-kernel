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
- Unknown routes, private prefixes, and customer or Enterprise-only paths must
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
trust-key mutation, Enterprise, customer, internal, secret, and deployment
runbook surfaces stay out of the live public route set.

## Denied Prefixes

The public host must not publish these prefixes:

```text
/customer
/internal
/helm-ai-enterprise
/enterprise
/trust
/product
/operations
/backend
/platform
```

## Validation

```bash
python3 scripts/check_documentation_truth.py
HELM_KERNEL_REPO_PATH=/path/to/helm-ai-kernel npm run ci
HELM_DOCS_URL=https://helm.docs.mindburn.org
curl -i "$HELM_DOCS_URL/customer/test"
curl -i "$HELM_DOCS_URL/no-such-route"
```
