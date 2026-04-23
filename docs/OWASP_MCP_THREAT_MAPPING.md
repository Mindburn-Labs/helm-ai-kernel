---
title: OWASP MCP Threat Mapping
---

# OWASP MCP Threat Mapping

This page maps retained HELM control points to the categories discussed in OWASP-style MCP and agent-tooling threat models. It is a repository reference map, not a certification statement.

| Risk Area | Primary HELM Control Points |
| --- | --- |
| unauthorized tool use | policy evaluation, manifest/schema validation, fail-closed execution boundary |
| connector contract drift | schema handling, typed contracts, evidence verification |
| outbound data movement | firewall and boundary packages |
| auditability gaps | signed receipts, proof graph, exported evidence bundles |
| replay and dispute handling | offline verification and replay paths |

For the more detailed code-path inventory used by the repository, see [security/owasp-agentic-top10-coverage.md](security/owasp-agentic-top10-coverage.md).
