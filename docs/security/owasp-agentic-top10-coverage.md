# OWASP Agentic Top 10 Mapping

This file is a code-oriented inventory of retained control points in the OSS kernel.

| OWASP Category | Repository Control Points |
| --- | --- |
| ASI-01 Prompt Injection | `core/pkg/threatscan/`, guarded execution boundary |
| ASI-02 Tool Poisoning | contract validation, firewall, connector validation |
| ASI-03 Excessive Permission | policy and effect-boundary packages |
| ASI-04 Insufficient Validation | guardian, manifest, schema, and policy packages |
| ASI-05 Improper Output Handling | evidence, receipts, and verification flow |
| ASI-06 Resource Overuse | budget and execution-control packages |
| ASI-07 Cascading Effects | proof graph and effect tracking |
| ASI-08 Sensitive Data Exposure | firewall, policy, and receipt material |
| ASI-09 Insecure Tool Integration | MCP, connector, and schema surfaces |
| ASI-10 Insufficient Monitoring | evidence export, proof graph, and verification commands |

Use this page as an implementation map. Validation still depends on the code, tests, and verification commands in the repository.
