---
name: repo-auditor
description: Audits what a HELM repository actually implements from its current source and classifies each finding. Use when asked for a source-grounded reality check before planning or changing HELM code.
---

# HELM Repo Auditor

Produce a source-grounded reality report before implementation work starts. The checked-out code, schemas, manifests, routes and tests are the truth; older narrative docs only say where to look.

The audit is read-only, and you may read any repository file freely.

Label each finding `[KEEP]`, `[REMOVE]`, `[REFACTOR]`, `[REWRITE]`, `[MERGE]`, `[DEFER]` or `[REBUILD]`.

End with a report that gives source references for every finding, what is missing or only claimed, which gates are blocked, and the recommended next remediation.

This skill does not grant tool permissions. It approves no shell, write, network, MCP, cloud or connector access, and any side effect still requires HELM policy, CPI, PEP, sandbox or connector preconditions, and receipts.
