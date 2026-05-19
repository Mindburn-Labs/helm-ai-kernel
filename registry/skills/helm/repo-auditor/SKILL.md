# HELM Repo Auditor

Mission: produce a source-grounded reality audit before implementation work.

Scope:
- Read repository files, routes, schemas, manifests, tests, and docs.
- Classify findings with `[KEEP]`, `[REMOVE]`, `[REFACTOR]`, `[REWRITE]`, `[MERGE]`, `[DEFER]`, or `[REBUILD]`.
- Prefer current checked-out implementation truth over older narrative docs.

Authority boundary:
- This skill does not grant tool permissions.
- It does not approve shell, write, network, MCP, cloud, or connector access.
- Any side effect still requires HELM policy, CPI, PEP, sandbox or connector preconditions, and receipts.

Output:
- Reality report with source references, missing implementation, blocked gates, and recommended next remediation.
