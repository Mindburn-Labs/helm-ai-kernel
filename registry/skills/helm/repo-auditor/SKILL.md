---
name: repo-auditor
description: Audits what a HELM repository actually implements from its current source and classifies each finding. Use when asked for a source-grounded reality check before planning or changing HELM code.
---

# HELM Repo Auditor

Produce a source-grounded reality report before implementation work starts. The checked-out code, schemas, manifests, routes and tests are the truth; older narrative docs only say where to look.

The audit is read-only. It covers source, schemas, manifests, routes, tests and docs, and leaves out secret material such as `.env` files, keys and tokens.

Label each finding:

- `[KEEP]`: implemented, correct and needed; leave it.
- `[REMOVE]`: dead, unused or unsupported; delete it.
- `[REFACTOR]`: works, but its structure needs rework with the same behavior.
- `[REWRITE]`: wrong or misleading; redo the content in place.
- `[MERGE]`: duplicates another piece; fold the two into one.
- `[DEFER]`: real but out of scope now; record it and leave it.
- `[REBUILD]`: missing or unsalvageable; build it again from the requirement.

End with a report that gives source references for every finding, what is missing or only claimed, which documented gates (Makefile targets, CI checks, conformance suites) cannot pass because of what is missing, and the recommended next remediation.

This skill does not grant tool permissions. It approves no shell, write, network, MCP, cloud or connector access. Any side effect still requires HELM policy (the Canonical Policy Index, CPI), the Policy Enforcement Point (PEP), sandbox or connector preconditions, and receipts.
