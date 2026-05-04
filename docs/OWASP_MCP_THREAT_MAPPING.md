---
title: OWASP MCP Threat Mapping
---

# OWASP MCP Threat Mapping

This page maps retained HELM OSS control points to OWASP-style MCP and agent-tooling threat areas. It is a public engineering map, not a certification statement.

| Risk Area | Primary HELM Control Points | Evidence To Review |
| --- | --- | --- |
| unauthorized tool use | policy evaluation, manifest/schema validation, fail-closed execution boundary | policy bundle, denial reason code, receipt |
| connector contract drift | schema handling, typed contracts, conformance checks | generated schema, connector conformance output |
| outbound data movement | egress rules, boundary packages, approval gates | policy bundle and proof graph |
| prompt-injection tool misuse | untrusted context handling, tool allowlists, effect levels | denied examples and threat-model tests |
| auditability gaps | signed receipts, proof graph, exported evidence bundles | receipt timeline and verifier output |
| replay and dispute handling | offline verification, causal hashes, evidence pack export | verifier command and evidence archive |

For a deeper agentic threat inventory, use [security/owasp-agentic-top10-coverage.md](security/owasp-agentic-top10-coverage.md). For product-level trust language, use the HELM trust docs on `helm.docs.mindburn.org`.
