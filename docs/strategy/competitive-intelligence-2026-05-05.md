---
title: Competitive Intelligence and Clean-Room Workstream - May 2026
---

# Competitive Intelligence and Clean-Room Workstream - May 2026

Research date: 2026-05-05 EEST.
Local verification: `date` returned `2026-05-05 03:18:17 EEST +0300`.
Access date for external sources: 2026-05-05 unless a row says otherwise.

This report is an internal strategy and implementation input for HELM OSS. Do
not copy competitor code, tests, schemas, UI expression, examples, branding, or
distinctive prose into HELM. Do not publish competitor comparisons from this
file without explicit approval. Public docs should use mechanism-based
differentiation unless a named comparison is separately approved.

The April 2026 strategy docs remain prior hypotheses. Current public evidence
in this report takes precedence where there is a conflict.

## Research Scope

Sources searched:

- official repositories, GitHub API metadata, package registries, and project docs;
- official product docs, launch pages, release pages, and standards pages;
- public regulatory, standards, and protocol documents;
- vendor pages and press/news pages where primary technical docs were not public;
- limited community/search snippets only where clearly labeled as sentiment or weak evidence.

Categories covered:

- direct agent execution firewalls and MCP interceptors;
- agent control planes and enterprise governance suites;
- MCP gateways, proxies, scanners, and local desktop proxy tools;
- OpenAI-compatible and LLM gateways;
- agent identity, non-human identity, delegated authorization, and workload identity;
- observability/evals and agent QA platforms;
- cryptographic receipts, evidence formats, signed logs, provenance, and notarization;
- policy engines, ReBAC systems, sandbox runtimes, and secure execution backends;
- agent frameworks and orchestration systems;
- standards and regulatory surfaces, including MCP, NIST, ISO, EU AI Act, WebAuthn, VC/DID, JOSE/JWS, JCS, OTel, SLSA, SBOM/VEX, SCITT, and C2PA;
- physical AI / robotics governance signals where public, especially ROS 2 security and Open-RMF.

Categories not deeply tested in this pass:

- live SaaS control planes requiring accounts, private tenants, contracts, or credentials;
- proprietary binaries or hosted sandboxes whose terms require account-specific review;
- paid enterprise consoles behind authentication;
- patented or patent-likely implementation details;
- exploit testing against live services.

Confidence level: Medium-High for public positioning and open-source artifact
posture; Medium for default runtime behavior unless locally reproduced; Low for
vendor-claimed enterprise feature depth not backed by public API or repo
evidence.

Known blind spots:

- Full hands-on bakeoff is not complete. A scratch directory was created at
  `/tmp/helm-competitive-re-2026-05-05`; metadata was fetched there. The
  install/run program below is part of the implementation backlog and must run
  before code changes derived from competitor behavior.
- PolicyLayer public pages claim Apache-2.0/open-source posture, but pkg.go.dev
  reported unknown license for `github.com/policylayer/intercept` v1.4.0. Treat
  this as a legal/posture inconsistency until the repository license is directly
  reviewed.
- Standards with draft status, especially SCITT/COSE receipts and OTel GenAI,
  should not be described as stable HELM conformance targets.

## Executive Competitive Summary

Biggest current threats:

- Microsoft Agent Governance Toolkit is the strongest OSS narrative threat:
  it claims broad runtime governance, identity, policy, sandboxing, and OWASP
  coverage with permissive MIT licensing and recent public activity.
- agentgateway is the strongest infrastructure threat: it combines MCP gateway,
  authz, CEL policy, OpenAI-compatible LLM gateway posture, Kubernetes-friendly
  distribution, and an active Apache-2.0 repository.
- PolicyLayer Intercept is the strongest focused MCP firewall threat: its public
  docs claim fail-closed MCP tool-call enforcement, YAML policies, tool hiding,
  counters, JSONL audit, and sub-ms in-process evaluation.
- Permit MCP Gateway and VerdictLayer/HumanLatch validate identity, consent,
  HITL, and approval-control-plane expectations.
- AWS Bedrock AgentCore is the strongest managed-cloud enterprise alternative
  for customers already on AWS.

Biggest table-stakes gaps for HELM:

- Crisp "wrap an existing MCP server in minutes" experience and docs.
- Machine-readable conformance vectors for deny-path semantics, MCP auth,
  stale policy, direct-connection bypass, and schema/tool drift.
- Visible quarantine/approval workflow for newly discovered MCP servers and
  risky tool bundles.
- Receipt/evidence fields that explicitly prove sandbox grants, network mode,
  mounted paths, env exposure, image/template digest, and relationship snapshot.
- Optional standards envelopes for export/interchange: DSSE/JWS first,
  in-toto/SLSA/Sigstore next, SCITT/COSE only after maturity improves.

Biggest HELM advantages:

- The current HELM repo already positions around fail-closed execution boundary,
  signed allow/deny receipts, ProofGraph, EvidencePack export, offline
  verification, replay, MCP, OpenAI-compatible proxy, SDKs, and conformance.
- No direct competitor source accessed in this pass verified the full
  combination of fail-closed pre-action enforcement plus signed allow/deny
  receipts plus offline-verifiable evidence packs plus replayable causal proof.
- HELM can stay provider-neutral and self-hostable instead of becoming a generic
  agent framework, SaaS governance registry, or passive observability product.

Biggest implementation opportunities:

- P0 conformance gates for negative execution-boundary behavior.
- P0 receipt/evidence contract design for sandbox grants and relationship
  snapshots.
- P1 MCP auth profile and protected-resource conformance.
- P1 coexistence docs for outer gateways and scanners, with HELM as the
  proof-bearing inner boundary.
- P1 optional export envelopes without replacing HELM-native JCS receipts.

Biggest narrative risks:

- "AI governance platform" invites comparison with ServiceNow, IBM, Credo AI,
  Salesforce, Databricks, Palantir, and compliance workflow suites where HELM
  OSS should not compete.
- "Trust layer" is too vague and easy to commoditize.
- "OpenAI-compatible governed proxy" is too narrow because agentgateway,
  LiteLLM, Portkey, Helicone, and cloud gateways already own gateway narratives.
- If HELM cannot demonstrate drop-in MCP wrapping and deny-path evidence, focused
  MCP firewalls will look more practical even with weaker proof.

What should be built first:

1. Negative conformance vectors for fail-closed MCP/tool-call behavior.
2. Receipt/evidence schema design for sandbox grants and authz snapshots.
3. MCP auth profile docs and tests.
4. Gateway/scanner coexistence docs.
5. A local bakeoff harness for AGT, PolicyLayer, agentgateway, MCPProxy,
   Invariant, Snyk Agent Scan, Ramparts, OPA, Cedar, CEL, and OpenFGA.

## Competitor Matrix

Legend:

- Source IDs refer to the Public Artifact Evidence Ledger.
- Scores use 1-10 where 10 is strongest in that column.
- Legal classification uses `[PUBLICLY IMPLEMENTABLE]`, `[PUBLIC BUT LICENSE-RESTRICTED]`, `[OBSERVABLE BUT DO NOT COPY]`, `[REQUIRES LEGAL REVIEW]`, or `[DO NOT USE]`.

### High-Priority Scorecard

| Competitor | Source | Category | Threat class | Execution boundary | Fail-closed | Policy depth | Receipt strength | Evidence/replay | MCP | OpenAI proxy | Sandbox | Identity | Audit | DX | OSS/license | Threat to HELM | Legal classification |
| --- | --- | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- | ---: | --- |
| Microsoft AGT | E01-E03 | runtime governance | DIRECT THREAT, NARRATIVE THREAT | 8 | 6 | 8 | 5 | 5 | 6 | 3 | 7 | 8 | 7 | 8 | MIT | 9 | [PUBLICLY IMPLEMENTABLE] for concepts; no code copying |
| PolicyLayer Intercept | E04-E06 | MCP firewall | DIRECT THREAT, OPEN-SOURCE WEDGE THREAT | 9 | 8 | 8 | 2 | 3 | 10 | 1 | 3 | 3 | 6 | 9 | claimed Apache-2.0, license mismatch | 9 | [REQUIRES LEGAL REVIEW] until repo license verified |
| agentgateway | E07 | agentic gateway | DISTRIBUTION THREAT, FEATURE THREAT | 7 | 6 | 7 | 1 | 3 | 9 | 8 | 3 | 7 | 6 | 8 | Apache-2.0 | 8 | [PUBLICLY IMPLEMENTABLE] |
| Permit MCP Gateway | E08 | MCP authz/consent | ENTERPRISE PROCUREMENT THREAT | 8 | 6 | 8 | 1 | 4 | 9 | 1 | 2 | 9 | 7 | 7 | proprietary/managed | 8 | [OBSERVABLE BUT DO NOT COPY] |
| Invariant Guardrails | E09-E10 | LLM/MCP guardrails | FEATURE THREAT | 6 | 5 | 7 | 1 | 3 | 8 | 8 | 2 | 2 | 5 | 8 | Apache-2.0 | 6 | [PUBLICLY IMPLEMENTABLE] for concepts |
| MCPProxy | E11 | local MCP proxy | DISTRIBUTION THREAT | 6 | 5 | 5 | 1 | 3 | 9 | 1 | 6 | 7 | 6 | 8 | MIT | 7 | [PUBLICLY IMPLEMENTABLE] |
| Snyk Agent Scan | E12 | scanner | FEATURE THREAT, POTENTIAL INTEGRATION | 3 | 2 | 4 | 1 | 2 | 7 | 1 | 2 | 2 | 5 | 8 | Apache-2.0 | 5 | [PUBLICLY IMPLEMENTABLE] |
| Ramparts | E13 | MCP scanner | FEATURE THREAT, POTENTIAL INTEGRATION | 2 | 1 | 3 | 1 | 2 | 7 | 1 | 1 | 1 | 4 | 7 | Apache-2.0 | 4 | [PUBLICLY IMPLEMENTABLE] |
| VerdictLayer HumanLatch | E14 | HITL approval control plane | NARRATIVE THREAT | 7 | 7 | 6 | 1 | 4 | 3 | 2 | 1 | 5 | 7 | 6 | MIT CE claimed | 6 | [PUBLICLY IMPLEMENTABLE] after CE review |
| Agent Policy Specification | E15 | policy standard/narrative | STANDARD TO SUPPORT, NARRATIVE THREAT | 7 | 5 | 7 | 1 | 2 | 5 | 5 | 1 | 2 | 4 | 7 | Apache-2.0 | 5 | [PUBLICLY IMPLEMENTABLE] after spec review |
| AWS Bedrock AgentCore | E16 | managed agent runtime | ENTERPRISE PROCUREMENT THREAT | 8 | 7 | 8 | 1 | 5 | 6 | 5 | 6 | 9 | 8 | 7 | proprietary cloud | 8 | [OBSERVABLE BUT DO NOT COPY] |
| Google Vertex AI Agent Builder | E17 | managed agent platform | ENTERPRISE PROCUREMENT THREAT | 7 | 5 | 7 | 1 | 5 | 5 | 5 | 4 | 8 | 8 | 7 | proprietary cloud | 7 | [OBSERVABLE BUT DO NOT COPY] |
| IBM watsonx.governance | E18 | AI GRC | ENTERPRISE PROCUREMENT THREAT | 3 | 2 | 5 | 1 | 5 | 1 | 1 | 1 | 5 | 8 | 6 | proprietary | 5 | [OBSERVABLE BUT DO NOT COPY] |
| ServiceNow AI Control Tower | E19 | AI control plane/GRC | ENTERPRISE PROCUREMENT THREAT | 4 | 3 | 6 | 1 | 6 | 3 | 2 | 1 | 6 | 8 | 7 | proprietary | 6 | [OBSERVABLE BUT DO NOT COPY] |
| Salesforce Agentforce Trust | E20 | CRM agent governance | ENTERPRISE PROCUREMENT THREAT | 5 | 4 | 6 | 1 | 5 | 4 | 4 | 2 | 7 | 8 | 7 | proprietary | 6 | [OBSERVABLE BUT DO NOT COPY] |
| CyberArk Secure AI Agents | E21 | non-human identity | ADJACENT THREAT | 5 | 5 | 7 | 1 | 5 | 2 | 1 | 2 | 9 | 8 | 6 | proprietary | 6 | [OBSERVABLE BUT DO NOT COPY] |
| Teleport | E22 | infrastructure identity | POTENTIAL INTEGRATION | 4 | 5 | 6 | 2 | 6 | 1 | 1 | 4 | 9 | 8 | 7 | mixed OSS/proprietary | 5 | [PUBLIC BUT LICENSE-RESTRICTED] |
| LangGraph | E23 | agent framework | FEATURE THREAT, POTENTIAL INTEGRATION | 4 | 3 | 4 | 1 | 7 | 3 | 5 | 1 | 2 | 6 | 8 | MIT | 5 | [PUBLICLY IMPLEMENTABLE] |
| OpenAI Agents SDK | E24 | agent SDK | DISTRIBUTION THREAT | 5 | 5 | 6 | 1 | 5 | 8 | 8 | 2 | 4 | 7 | 9 | SDK terms/license to verify | 7 | [REQUIRES LEGAL REVIEW] before dependency |
| LiteLLM | E25 | LLM gateway | DISTRIBUTION THREAT | 4 | 3 | 5 | 1 | 4 | 4 | 9 | 1 | 3 | 7 | 8 | OSS/commercial | 6 | [PUBLIC BUT LICENSE-RESTRICTED] |
| Langfuse | E26 | observability/evals | POTENTIAL INTEGRATION | 2 | 1 | 3 | 1 | 6 | 3 | 5 | 1 | 2 | 8 | 8 | OSS/self-host | 4 | [PUBLIC BUT LICENSE-RESTRICTED] |
| OPA/Rego | E27 | policy engine | STANDARD TO SUPPORT | 6 | 5 | 9 | 1 | 3 | 1 | 1 | 1 | 3 | 7 | 7 | Apache-2.0 | 4 | [PUBLICLY IMPLEMENTABLE] |
| Cedar | E28 | authz policy | STANDARD TO SUPPORT | 7 | 7 | 8 | 1 | 3 | 1 | 1 | 1 | 5 | 6 | 7 | Apache-2.0 | 4 | [PUBLICLY IMPLEMENTABLE] |
| CEL | E29 | expression language | STANDARD TO SUPPORT | 5 | 4 | 6 | 1 | 2 | 1 | 1 | 1 | 2 | 4 | 8 | Apache-2.0 | 3 | [PUBLICLY IMPLEMENTABLE] |
| OpenFGA | E30 | ReBAC | POTENTIAL INTEGRATION | 6 | 6 | 8 | 1 | 3 | 1 | 1 | 1 | 8 | 6 | 7 | Apache-2.0 | 5 | [PUBLICLY IMPLEMENTABLE] |
| WASI/wazero/Wasmtime | E31-E33 | sandbox/runtime | STANDARD TO SUPPORT | 7 | 8 | 3 | 1 | 3 | 1 | 1 | 8 | 2 | 4 | 7 | Apache-2.0 | 5 | [PUBLICLY IMPLEMENTABLE] |
| Firecracker/gVisor/nsjail | E34-E36 | isolation runtime | POTENTIAL INTEGRATION | 8 | 7 | 2 | 1 | 3 | 1 | 1 | 9 | 2 | 5 | 5 | Apache-2.0 | 5 | [PUBLICLY IMPLEMENTABLE] |
| E2B/Daytona/Modal | E37-E39 | hosted sandboxes | FEATURE THREAT | 5 | 5 | 3 | 1 | 3 | 2 | 2 | 7 | 3 | 6 | 8 | mixed | 5 | [PUBLIC BUT LICENSE-RESTRICTED] |

### Differentiation Matrix

| Competitor | Primary narrative | Target user | Deployment | Public status | MCP support | Proxy support | Policy/enforcement model | Fail-closed evidence | Receipt/evidence/replay | Strongest advantage | Weakest gap | HELM advantage | HELM gap | Recommended action |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Microsoft AGT | OSS runtime governance for agents | platform/security engineers | Python package/library | MIT OSS, public preview | partial/adapter evidence | no primary OpenAI proxy evidence | deterministic policy, identity, sandboxing claims | inferred, not fully verified | offline receipt docs exist; full proof model unclear | broad Microsoft-backed narrative | no HELM-grade EvidencePack verified | signed receipts, ProofGraph, offline verification | needs direct bakeoff and coexistence doc | benchmark, do not copy |
| PolicyLayer Intercept | MCP firewall before tool execution | developers using MCP servers | npx/go binary | public docs claim Apache-2.0; pkg.go license unknown | yes | no primary evidence | YAML policies, counters, tool hiding, approval/deny | claimed fail-closed | JSONL audit, no signed receipts verified | crisp drop-in MCP story | license/posture inconsistency; audit not proof | stronger cryptographic evidence | needs equally crisp MCP wrapper quickstart | legal review, benchmark |
| agentgateway | agentic proxy/gateway | platform/SRE/K8s teams | binary/container/Helm | Apache-2.0 OSS | yes | yes | CEL authz, routing, filters, rate/budget controls | inferred from gateway policy | logs/telemetry, no signed proof | distribution and infra fit | gateway is not evidence authority | proof-bearing inner boundary | docs must explain composition | publish coexistence guide |
| Permit MCP Gateway | MCP authorization and consent | enterprise app teams | managed gateway | proprietary/managed | yes | no primary evidence | real-time checks, consent, audit | inferred | audit, no signed proof verified | identity/consent UX | SaaS/control-plane dependency | local-first signed receipts | needs external-authz integration story | monitor/integrate |
| Invariant | contextual guardrails for agents | AI app developers | Python library/gateway | Apache-2.0 | yes | yes | rule engine over messages/tool traces | inferred | analysis results, no signed proof | flow/prompt-injection detection | content guardrail not execution proof | deterministic execution boundary | coexistence docs | integrate conceptually |
| MCPProxy | local smart MCP proxy | developers/desktops | local app/CLI | MIT OSS | yes | no | quarantine, OAuth, local proxy controls | inferred | local logs, no signed proof | desktop UX and onboarding | not hard semantic authorization | evidence and policy depth | MCP server quarantine UI | borrow concept clean-room |
| Snyk Agent Scan | scanner for agents/MCP | security/dev teams | CLI/package | Apache-2.0 | scanner/proxy support | no | assessment/consent, not inline boundary | no | reports, no proof | security scanner distribution | not runtime PEP | runtime receipts | machine-readable scanner exports | potential integration |
| Ramparts | MCP security scanner | security engineers | Rust CLI | Apache-2.0 | scanner | no | assessment only | no | reports, no proof | lightweight MCP scanning | not enforcement | runtime boundary | scanner artifact export | potential integration |
| VerdictLayer HumanLatch | human approval between intent and action | infra/ops/security | CE/self-host + cloud claimed | MIT CE claimed, tiny repo | not primary | no | proposal API, approve/escalate/block | claimed/roadmap | audit trail, no proof verified | HITL wedge | early maturity | stronger proof/evidence | approval UX | monitor |
| Agent Policy Specification | vendor-neutral policy contract | SDK/platform authors | spec/SDKs | Apache-2.0 claim | general | general | input/tool/output policy contract | not verified | no receipt model | narrative standardization | immature adoption | receipt-bearing conformance | must avoid DSL sprawl | monitor/support selectively |
| AWS AgentCore | managed agent runtime and identity | AWS enterprises | AWS cloud | proprietary | partial | AWS-native | IAM/Cedar/gateway policies | cloud-managed | CloudWatch/S3/Firehose evidence, not portable proof | enterprise cloud integration | lock-in | self-hostable proof | cloud identity adapter story | monitor/integrate |
| Google Vertex/Gemini agent governance | managed tool governance | Google Cloud users | Google Cloud | proprietary | partial | Google-native | tool catalog, IAM, lifecycle, logs | platform-defined | cloud logs/traces | platform reach | less portable | portable evidence | GCP deployment docs | monitor |
| IBM watsonx.governance | AI governance lifecycle | risk/compliance teams | SaaS/Software Hub | proprietary | no primary | no | factsheets, risk, compliance workflows | no | lifecycle evidence, not runtime proof | procurement/compliance | not execution boundary | runtime receipts | compliance mapping | avoid category confusion |
| ServiceNow AI Control Tower | centralized AI command center | enterprise platform owners | ServiceNow platform | proprietary | indirect | no | inventory, lifecycle, workflows | no | evidence exports claimed | enterprise workflow | platform lock-in | open kernel | enterprise connector docs | monitor |
| Salesforce Agentforce Trust | CRM agent trust layer | Salesforce admins/devs | Salesforce cloud | proprietary | partial | Salesforce-native | masking, trust layer, command center | platform-defined | Data 360/audit trail | CRM distribution | ecosystem-specific | provider-neutral boundary | Salesforce adapter docs | monitor |
| CyberArk Secure AI Agents | agent identity security | identity/security teams | enterprise platform | proprietary | no primary | no | least privilege, lifecycle, audits | policy-dependent | identity audit | NHI credibility | not full runtime PEP | tool-call evidence | identity integration docs | monitor |
| Teleport | infrastructure identity platform | infra/security teams | self-host/cloud | mixed | no primary | no | short-lived certs, JIT, sessions | yes for infra access | session recording/audit | mature identity | not agent-specific PEP | agent action receipts | workload identity bridge | potential integration |
| LangGraph/OpenAI Agents SDK/CrewAI/AutoGen/Mastra | agent orchestration | app developers | library/framework | mixed OSS | varying | varying | framework-local controls | framework-defined | traces/checkpoints, no signed proof | adoption/DX | not evidence authority | framework-neutral boundary | adapters/examples | support via SDK docs |
| LiteLLM/Portkey/Helicone | LLM gateway/observability | platform teams | gateway/SaaS/self-host | mixed | varying | yes | routing, logging, spend controls | gateway-defined | logs/traces, no proof | provider portability | proxy-only | execution proof | docs must avoid proxy-only story | coexist |
| Langfuse/AgentOps/Galileo/Fiddler | observability/evals/control | ML/AI ops | SaaS/self-host mixed | mixed | varying | varying | observe/evaluate/guardrail | mostly no | traces/evals/evidence, not signed receipts | UX/reporting | passive unless integrated inline | enforce and prove | OTLP/trace export | integrate, do not become |
| OPA/Cedar/CEL/OpenFGA | policy/authz primitives | platform engineers | embedded/server | Apache-2.0 | no | no | PDP/ReBAC/expression engines | integration-owned | no native receipts | mature policy primitives | not agent evidence | HELM PEP/receipts | conformance matrices | support as policy inputs |
| WASI/wazero/Wasmtime/Firecracker/gVisor/nsjail | isolation runtimes | platform/security engineers | embedded/runtime | Apache-2.0 | no | no | capability or VM/container isolation | config-dependent | no native receipts | real containment | not policy authority | receipted grants | explicit sandbox fields | integrate by profile |
| ROS 2/Open-RMF/NVIDIA Isaac/AWS robotics | physical AI stack | robotics/OT teams | middleware/vendor | mixed | no | no | middleware security/fleet governance | ROS security can enforce | no HELM-like receipts | concrete physical signal | fragmented standards | actuation-proof boundary | physical adapter strategy | monitor unless near-term customer |

## Public Artifact Evidence Ledger

| ID | Competitor/source | URL | Source type | Date/access date | What it proves | What it does not prove | Confidence | Claim posture | License posture | HELM relevance |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| E01 | Microsoft AGT repo | https://github.com/microsoft/agent-governance-toolkit | official repository/GitHub API | created 2026-03-02; updated 2026-05-04; accessed 2026-05-05 | public MIT repo, 1398 stars, 268 forks, Python, active issues, runtime-governance description | default runtime behavior, evidence quality | High | current implementation + vendor description | MIT | direct runtime-governance benchmark |
| E02 | Microsoft AGT PyPI | https://pypi.org/project/agent-governance-toolkit/ | package registry | public preview; latest metadata accessed 2026-05-05 | package install path `pip install agent-governance-toolkit[full]`, Python 3.9-3.12 classifiers | legal completeness of all transitive deps | High | current package | MIT claim | installability and DX |
| E03 | AGT offline receipts docs | https://microsoft.github.io/agent-governance-toolkit/tutorials/33-offline-verifiable-receipts/ | official tutorial | date not visible; accessed 2026-05-05 | public docs describe offline-verifiable receipt concept | exact code maturity without install/run | Medium | implementation docs | MIT project context | closest runtime-receipt overlap |
| E04 | PolicyLayer docs | https://policylayer.com/docs/reference/policy-controls | official docs/landing | crawled last month; accessed 2026-05-05 | open-source MCP proxy claim, fail-closed, YAML rules, JSONL audit, SQLite counters, npx/go install | repository license consistency | Medium | vendor-claimed/current docs | claims Apache-2.0 | direct MCP firewall threat |
| E05 | PolicyLayer pkg.go.dev | https://pkg.go.dev/github.com/policylayer/intercept | package registry | v1.4.0 published 2026-04-09; accessed 2026-05-05 | Go module exists, tagged stable module, import tree visible | redistributable license; docs hidden due license policy | High | current package metadata | UNKNOWN on pkg.go.dev | legal review gate |
| E06 | PolicyLayer npm CDN | https://www.jsdelivr.com/package/npm/%40policylayer/intercept | package registry/CDN metadata | crawled last week; accessed 2026-05-05 | npm package version 1.4.0 and Apache-2.0 license metadata | source-code license text | Medium | registry metadata | Apache-2.0 metadata | installability |
| E07 | agentgateway repo | https://github.com/agentgateway/agentgateway | official repository/GitHub API | created 2025-03-18; updated 2026-05-05; accessed 2026-05-05 | Apache-2.0 repo, 2591 stars, 438 forks, Rust, MCP/gateway topics | fail-closed default semantics | High | current implementation | Apache-2.0 | infra/gateway threat |
| E08 | Permit MCP Gateway docs | https://docs.permit.io/permit-mcp-gateway/overview/ | official docs | accessed 2026-05-05 | MCP authorization/consent gateway positioning | self-hosting or receipt semantics | Medium | vendor docs | proprietary/managed unless OSS found | identity/consent pressure |
| E09 | Invariant repo | https://github.com/invariantlabs-ai/invariant | official repository/GitHub API | updated 2026-04-29; accessed 2026-05-05 | Apache-2.0 repo, 414 stars, 45 forks, guardrail project | gateway runtime behavior | High | current implementation | Apache-2.0 | guardrail coexistence |
| E10 | invariant-ai PyPI | https://pypi.org/project/invariant-ai/ | package registry | latest metadata accessed 2026-05-05 | package describes MCP/LLM proxy and local policy evaluation | signed receipts or offline proof | High | current package docs | dynamic license metadata; repo Apache-2.0 | flow guardrail benchmark |
| E11 | MCPProxy repo | https://github.com/smart-mcp-proxy/mcpproxy-go | official repository/GitHub API | created 2025-06-18; updated 2026-05-04; accessed 2026-05-05 | MIT repo, 209 stars, 24 forks, Go, local-first MCP proxy topics | hard policy semantics | High | current implementation | MIT | developer-desktop proxy threat |
| E12 | Snyk Agent Scan repo | https://github.com/snyk/agent-scan | official repository/GitHub API | created 2025-04-07; updated 2026-05-04; accessed 2026-05-05 | Apache-2.0 repo, 2334 stars, 211 forks, scanner for AI agents/MCP/skills | inline enforcement or receipts | High | current implementation | Apache-2.0 | scanner integration signal |
| E13 | Ramparts crate | https://crates.io/crates/ramparts | package registry | v0.7.3 published 2025-09-11; accessed 2026-05-05 | Rust CLI scanner for MCP servers, Apache-2.0, crate downloads | live repo activity beyond crate | High | current package | Apache-2.0 | pre-deployment scanner signal |
| E14 | VerdictLayer/HumanLatch | https://www.verdictlayer.com/ and https://github.com/VerdictLayer/humanlatch | official site/repo | 2026 site copyright; accessed 2026-05-05 | proposal API, approve/escalate/block, audit trail, MIT CE claim, pricing; tiny public repo | maturity, implementation depth, receipt strength | Medium | vendor-claimed + repo | MIT repo; CE to review | HITL narrative threat |
| E15 | Agent Policy Specification | https://agentpolicyspecification.github.io/ | public spec site | accessed 2026-05-05 | vendor-neutral policy contract over input/tool/output policy, Apache-2.0 claim | adoption, receipt model, conformance maturity | Medium | roadmap/spec/narrative | Apache-2.0 claim | standard-to-monitor |
| E16 | AWS Bedrock AgentCore | https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/identity.html | official docs | accessed 2026-05-05 | managed agent identity/runtime authorization docs | portable offline evidence | High | current implementation docs | proprietary cloud | enterprise procurement threat |
| E17 | Google Vertex AI Agent Builder | https://cloud.google.com/blog/products/ai-machine-learning/new-enhanced-tool-governance-in-vertex-ai-agent-builder | official blog/docs | blog dated 2025-12-19; accessed 2026-05-05 | tool governance/lifecycle narrative in Google Cloud | open implementation | Medium | vendor docs/marketing | proprietary cloud | cloud-platform pressure |
| E18 | IBM watsonx.governance | https://cloud.ibm.com/catalog/services/watsonxgovernance | official catalog/docs | date visible 2026-02-19; accessed 2026-05-05 | IBM governance service posture | inline agent execution control | Medium | current product docs | proprietary | GRC procurement pressure |
| E19 | ServiceNow AI Control Tower | https://newsroom.servicenow.com/press-releases/details/2025/ServiceNow-Launches-AI-Control-Tower-a-Centralized-Command-Center-to-Govern-Manage-Secure-and-Realize-Value-From-Any-AI-Agent-Model-and-Workflow/ | official newsroom/docs | 2025 launch; accessed 2026-05-05 | centralized governance/agent lifecycle positioning | cryptographic receipts | Medium | vendor launch | proprietary | enterprise control-plane pressure |
| E20 | Salesforce Agentforce Trust | https://developer.salesforce.com/docs/ai/agentforce/guide/trust.html | official docs | accessed 2026-05-05 | trust layer, masking, audit/control surfaces in Salesforce estate | portable runtime boundary | Medium | current docs | proprietary | CRM ecosystem pressure |
| E21 | CyberArk Secure AI Agents | https://www.cyberark.com/solutions/secure-agentic-ai/ | official solution page | accessed 2026-05-05 | agent identity/security posture | execution receipts | Medium | vendor marketing/docs | proprietary | NHI integration pressure |
| E22 | Teleport identity platform | https://goteleport.com/api/files/Teleport-Datasheet-Infrastructure-Identity-Platform/ | vendor datasheet | accessed 2026-05-05 | short-lived identity, JIT approvals, session/audit posture | agent-specific PEP | Medium | vendor datasheet | mixed | workload identity bridge |
| E23 | LangGraph | https://docs.langchain.com/oss/python/langgraph | official docs | accessed 2026-05-05 | durable agent orchestration/checkpointing | cryptographic action receipts | High | current docs | MIT repo context | framework adapter expectation |
| E24 | OpenAI Agents SDK | https://platform.openai.com/docs/guides/agents-sdk/ | official docs | accessed 2026-05-05 | agent SDK and MCP/tool integration posture | self-hosted proof boundary | High | current docs | license/terms to verify | SDK integration pressure |
| E25 | LiteLLM proxy | https://docs.litellm.ai/docs/proxy/ | official docs | accessed 2026-05-05 | OpenAI-compatible proxy/routing | signed evidence | High | current docs | mixed OSS/commercial | gateway coexistence |
| E26 | Langfuse | https://langfuse.com/docs/ | official docs | accessed 2026-05-05 | open-source/self-host observability/evals posture | fail-closed PEP | Medium | current docs | license to verify before embedding | telemetry integration |
| E27 | OPA | https://github.com/open-policy-agent/opa | official repository/GitHub API | updated 2026-05-04; accessed 2026-05-05 | Apache-2.0 policy engine, 11679 stars, 1557 forks, active repo | application-level fail-closed by default | High | current implementation | Apache-2.0 | policy input |
| E28 | Cedar | https://github.com/cedar-policy/cedar | official repository/docs | accessed 2026-05-05 | typed authorization policy engine | HELM receipt model | High | current implementation | Apache-2.0 | policy input |
| E29 | CEL | https://github.com/google/cel-go | official repository/docs | accessed 2026-05-05 | embedded expression language | full PDP or receipts | High | current implementation | Apache-2.0 | policy predicates |
| E30 | OpenFGA | https://github.com/openfga/openfga | official repository/docs | accessed 2026-05-05 | Zanzibar-style ReBAC server | receipt/evidence | High | current implementation | Apache-2.0 | optional relationship resolver |
| E31 | WASI | https://github.com/WebAssembly/WASI | standard/repo | accessed 2026-05-05 | capability-based WebAssembly system interface | runtime security by itself | High | standard/current | Apache-2.0 | sandbox contract |
| E32 | wazero | https://github.com/tetratelabs/wazero | official repo/docs | accessed 2026-05-05 | pure-Go WebAssembly runtime | OS-level isolation | High | current implementation | Apache-2.0 | embedded sandbox |
| E33 | Wasmtime | https://docs.wasmtime.dev/security.html | official docs | accessed 2026-05-05 | Wasm/WASI runtime security model | HELM policy semantics | High | current docs | Apache-2.0 | heavier sandbox |
| E34 | Firecracker | https://github.com/firecracker-microvm/firecracker | official repo/docs | accessed 2026-05-05 | microVM runtime and isolation docs | simple developer setup | High | current implementation | Apache-2.0 | high-risk exec tier |
| E35 | gVisor | https://gvisor.dev/docs/architecture_guide/security/ | official docs | accessed 2026-05-05 | user-space kernel/container isolation model | full VM isolation | High | current docs | Apache-2.0 | intermediate sandbox |
| E36 | nsjail | https://github.com/google/nsjail | official repo | accessed 2026-05-05 | Linux namespaces/cgroups/seccomp sandbox | strong multi-tenant isolation | Medium | current implementation | Apache-2.0 | local test/fuzz runner |
| E37 | E2B | https://github.com/e2b-dev/e2b | official repo/docs | accessed 2026-05-05 | agent-focused cloud/self-host sandbox posture | HELM-grade policy/evidence | Medium | current implementation/docs | Apache-2.0 repo; service terms to review | sandbox backend |
| E38 | Daytona | https://github.com/daytonaio/daytona | official repo/docs | accessed 2026-05-05 | full-computer sandbox/enterprise security posture | license fit for embedding | Medium | current implementation/docs | AGPL-3.0 | license-restricted sandbox backend |
| E39 | Modal Sandboxes | https://modal.com/docs/guide/sandbox | official docs | accessed 2026-05-05 | managed sandbox and network controls | OSS/self-host or deterministic proof | Medium | current docs | proprietary | hosted sandbox benchmark |
| E40 | MCP spec and auth | https://modelcontextprotocol.io/specification/2025-11-25 | protocol spec | version 2025-11-25; accessed 2026-05-05 | MCP protocol and authorization profile direction | HELM conformance by itself | High | current spec | open spec | MCP auth profile |
| E41 | MCP roadmap | https://modelcontextprotocol.io/development/roadmap | roadmap | updated 2026-03-05; accessed 2026-05-05 | enterprise auth/SEP direction | commitments | Medium | roadmap | open docs | monitor only |
| E42 | NIST NCCoE software/AI agent identity | https://www.nccoe.nist.gov/projects/software-and-ai-agent-identity-and-authorization | NIST project/concept | concept paper published 2026-02-05; accessed 2026-05-05 | U.S. guidance direction for software and AI agent identity/authorization | final standard | Medium | draft concept | public guidance | terminology alignment |
| E43 | WebAuthn Level 3 | https://www.w3.org/TR/webauthn-3/ | W3C CR snapshot | 2026-01-13; accessed 2026-05-05 | passkey/WebAuthn approval standard direction | agent policy by itself | High | standards track | W3C | HITL approvals |
| E44 | VC Data Model 2.0 | https://www.w3.org/TR/vc-data-model/ | W3C Recommendation | 2025-05-15; accessed 2026-05-05 | verifiable credentials for portable identity/delegation | dense runtime receipt format | High | standard | W3C | optional delegation credentials |
| E45 | RFC 7515 JWS | https://www.rfc-editor.org/rfc/rfc7515 | IETF RFC | 2015-05; accessed 2026-05-05 | interoperable signed payload envelope | canonicalization strategy | High | standard | IETF | optional receipt envelope |
| E46 | RFC 8785 JCS | https://www.rfc-editor.org/rfc/rfc8785.html | IETF RFC | 2020-06; accessed 2026-05-05 | deterministic JSON canonicalization | policy semantics | High | standard | IETF informational | native HELM receipt canonicalization |
| E47 | Sigstore bundle | https://docs.sigstore.dev/about/bundle/ | official docs | last updated 2025-01-14; accessed 2026-05-05 | offline-verifiable signature bundle concept | per-action receipt model | High | current spec/docs | open | export/notarization |
| E48 | SCITT architecture | https://datatracker.ietf.org/doc/draft-ietf-scitt-architecture/ | IETF draft | last updated 2026-03-06; accessed 2026-05-05 | signed-statement transparency direction | stable RFC | Medium | draft | IETF draft | roadmap export |
| E49 | COSE Merkle Tree Proofs | https://datatracker.ietf.org/doc/html/draft-ietf-cose-merkle-tree-proofs | IETF draft | rev18/Auth48 state 2026-03-06; accessed 2026-05-05 | signed inclusion/consistency proof direction | mature tooling | Medium | draft | IETF draft | roadmap receipts |
| E50 | OpenTelemetry GenAI | https://opentelemetry.io/docs/specs/semconv/gen-ai/ | official spec docs | semconv 1.41.0, Development; accessed 2026-05-05 | telemetry schema for GenAI spans/events | audit truth | Medium | development spec | CNCF/open | non-authoritative telemetry |
| E51 | NIST AI RMF | https://www.nist.gov/itl/ai-risk-management-framework | NIST framework | released 2023-01-26; accessed 2026-05-05 | risk management vocabulary | product certification | High | framework | public | compliance crosswalk |
| E52 | ISO/IEC 42001 | https://www.iso.org/standard/42001 | ISO standard page | 2023; accessed 2026-05-05 | AI management-system standard | HELM product compliance | High | standard page | ISO terms | enterprise mapping |
| E53 | EU AI Act | https://eur-lex.europa.eu/eli/reg/2024/1689/ | law | adopted 2024-06-13; OJ 2024-07-12; accessed 2026-05-05 | legal requirements for AI systems/use cases | applicability to every HELM user | High | law | public law | evidence hooks |
| E54 | ROS 2 Security | https://docs.ros.org/en/iron/Concepts/Intermediate/About-Security.html | official docs | accessed 2026-05-05 | enclaves, signed permissions, enforce strategy | robotics safety certification | Medium | current docs | open docs | physical AI monitor |
| E55 | Open-RMF | https://www.open-rmf.org/ | project page | OSRA governance since 2024; accessed 2026-05-05 | robot fleet interoperability/governance context | action receipt standard | Medium | project docs | open ecosystem | monitor |

## Reverse-Engineering Notes

Legal boundary for this pass:

- Allowed: public docs, public source under license, public package metadata,
  package install commands that do not require private credentials, and local
  black-box tests against OSS tools installed into `/tmp/helm-competitive-re-2026-05-05`.
- Forbidden: private repos, proprietary decompilation, bypassing auth/paywalls,
  live exploitation, scraping in violation of terms, copying code/tests/schemas,
  and implementing distinctive proprietary behavior.

Scratch setup:

- Created `/tmp/helm-competitive-re-2026-05-05`.
- Fetched GitHub API metadata for AGT, agentgateway, Invariant, MCPProxy,
  Snyk Agent Scan, and OPA.
- Fetched PyPI/crates metadata for AGT, Invariant, and Ramparts.
- No third-party source code was copied into this repository.

Hands-on bakeoff protocol for installable OSS candidates:

| Candidate | Install step | Minimum run step | Allow path | Deny/malformed path | Failure path | Evidence inspection |
| --- | --- | --- | --- | --- | --- | --- |
| AGT | `python -m venv /tmp/helm-competitive-re-2026-05-05/agt && pip install agent-governance-toolkit[full]` | run quickstart or local governed action | read-only action | destructive write action | missing policy or identity | receipt/audit/log files |
| PolicyLayer | `npx -y @policylayer/intercept` or `go install github.com/policylayer/intercept@latest` after license review | wrap a toy MCP stdio server | benign tool call | blocked destructive tool | invalid policy / evaluator error | JSONL audit, deny shape |
| agentgateway | use release binary/container from official repo | run local MCP proxy fixture | listed allowed tool | disallowed tool and filtered list | policy/config missing | logs/metrics/decision payload |
| MCPProxy | install signed package or binary from repo release | register toy MCP server | allowed server connection | quarantined unknown server | missing OAuth/config | local logs/quarantine state |
| Invariant | `pip install invariant-ai` | run local `LocalPolicy` trace example | non-violating trace | malicious flow trace | missing detector/API key | analysis result shape |
| Snyk Agent Scan | package install from repo docs once package name verified | scan toy MCP server | clean fixture | malicious/destructive fixture | missing config | JSON/SARIF/report output |
| Ramparts | `cargo install ramparts` | scan toy MCP endpoint | clean fixture | vulnerable fixture | invalid endpoint | scanner report |
| OPA | official binary or `go install` | `opa eval` with Rego policy | allow decision | undefined/deny decision | bundle not ready | decision-log fields |
| Cedar | official CLI/library | evaluate typed entity policy | permit | forbid/error | schema/entity drift | decision and diagnostics |
| CEL | `go test`/cel-go example | evaluate expression | true | false/error | host function absent | expression diagnostics |
| OpenFGA | Docker/binary | run local store/model | relation allowed | stale/missing tuple | service unavailable | decision and tuple snapshot |

Observed behavior from public artifacts:

- AGT is installable from PyPI and the public repo is active; runtime receipt
  claims need direct local validation before HELM imports any conceptual tests.
- PolicyLayer appears highly relevant for drop-in MCP wrapping, but license
  metadata must be reconciled before source-level review.
- agentgateway has strong distribution and gateway posture; use it as an
  outer-gateway benchmark, not a receipt-system source.
- Invariant is a guardrail/flow-policy layer; useful for coexistence and
  test-scenario inspiration, not for HELM's core receipt design.
- MCPProxy and scanner tools validate developer expectations around discovery,
  quarantine, and security reports.

Clean-room spec candidates:

- Hostile MCP fixture: server advertises a benign `list_files` tool and a
  destructive `delete_repository` tool; HELM and competitors must prove
  list/call consistency and deny destructive call before upstream dispatch.
- Tool drift fixture: server changes schema hash between discovery and call;
  expected HELM behavior is fail-closed with signed deny receipt.
- Policy outage fixture: PDP/policy bundle unavailable; expected HELM behavior
  is deny with deterministic reason and receipt.
- Sandbox overgrant fixture: tool requests filesystem preopen, env secret, and
  unrestricted egress; expected HELM behavior is deny unless all grants are
  explicit and receipted.
- Direct-connection bypass fixture: client attempts to call upstream MCP server
  outside HELM; expected documentation and deployment test verify that the
  guarded topology prevents or detects bypass.

## HELM Gap Analysis

| Gap | Severity | Competitor evidence | Affected HELM area | Recommended action | Target files | Required tests | Verification method |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Drop-in MCP wrapping story is less crisp than PolicyLayer/agentgateway | P0 | E04-E07 | docs, CLI, MCP gateway | publish quickstart and conformance for wrapping existing MCP stdio/http server | `docs/INTEGRATIONS/mcp.md`, `docs/DEVELOPER_JOURNEY.md`, `core/pkg/mcp`, `tests/conformance` | toy upstream allow/deny/drift | `go test ./core/pkg/mcp/...`; conformance |
| Negative fail-closed vectors are not visible enough | P0 | E04, E07, E27-E30 | conformance, PDP, MCP | add vectors for policy-not-ready, stale bundle, PDP outage, malformed args, missing creds | `core/pkg/conformance`, `tests/conformance`, `protocols/conformance/v1` | fail-closed reason-code tests | `cd tests/conformance && go test ./...` |
| Receipts do not explicitly prove sandbox grants in public docs/contracts | P0 | E31-E39 | receipts/evidence/sandbox | design receipt/evidence fields for fs/env/net/image/policy/tuple grants | `schemas/receipts`, `protocols/spec/evidence-pack-v1.md`, `core/pkg/receipts`, `core/pkg/runtime/sandbox` | canonicalization and tamper tests | `make test`; evidence verify |
| MCP auth profile is not packaged as a conformance target | P1 | E40-E42 | MCP, auth, conformance | define profile around protected-resource metadata, scopes, challenges, and per-tool consistency | `docs/INTEGRATIONS/mcp.md`, `api/openapi/helm.openapi.yaml`, `tests/conformance` | OAuth metadata and insufficient-scope tests | conformance + API tests |
| HELM lacks explicit coexistence docs for outer gateways/scanners | P1 | E07-E13, E25-E26 | docs/examples | document HELM as inner proof boundary under gateways/scanners | `docs/COMPATIBILITY.md`, `docs/INTEGRATIONS/mcp.md`, examples | docs-truth links to current surfaces | doccheck |
| Optional export envelopes are not prioritized | P1 | E45-E50 | evidence/export | add design note: DSSE/JWS first; in-toto/Sigstore next; SCITT/COSE monitor | `protocols/spec/evidence-pack-v1.md`, `docs/VERIFICATION.md` | golden export fixture once implemented | verify fixture bytes |
| New MCP server quarantine/approval is not first-class in Console | P2 | E11, E14 | Console, MCP registry | design UI surface for unknown/risky servers and tool bundles | `apps/console`, `core/pkg/mcp`, `schemas/approvals` | UI state and API contract tests | `make test-console` |
| Broad governance/GRC platforms can blur HELM positioning | P2 | E18-E20, E51-E53 | docs/positioning | keep OSS positioning on execution firewall, receipts, offline verification | README and public docs | docs claim audit | doccheck |
| Physical AI language lacks near-term implementation boundary | P3 | E54-E55 | roadmap/docs | monitor only unless customer asks; map ROS 2 enforce mode in future adapter | future docs | none now | no current implementation |

## Implementation Backlog

| Status | Priority | Capability | Competitor/source | Public evidence | License posture | HELM relevance | HELM-native design | Target files | Required tests | Required docs | Effort | Strategic impact | Severity if missing |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| [NEW] | P0 | Negative execution-boundary conformance vectors | PolicyLayer, agentgateway, OPA/Cedar/OpenFGA | E04-E07, E27-E30 | public/OSS; PolicyLayer legal review | protects fail-closed claim | deterministic fixtures that assert deny + receipt before dispatch | `core/pkg/conformance`, `tests/conformance`, `protocols/conformance/v1` | policy outage, stale bundle, malformed args, missing creds, deny receipt | conformance guide | M | core proof | HELM claims weaken |
| [NEW] | P0 | Sandbox grant receipt design | WASI, wazero, Wasmtime, Firecracker, gVisor, hosted sandboxes | E31-E39 | mostly OSS, mixed hosted | proves what authority was actually granted | add canonical sandbox grant object to receipt/evidence design | `schemas/receipts`, `core/pkg/receipts`, `core/pkg/runtime/sandbox`, `protocols/spec/evidence-pack-v1.md` | canonical hash, tamper, offline verify, overgrant deny | security model + evidence spec | L | core proof | evidence incomplete |
| [MODIFY] | P1 | MCP auth conformance profile | MCP spec/auth, NCCoE | E40-E42 | open specs | enterprise auth baseline | protected-resource metadata + OAuth scope challenge profile | `docs/INTEGRATIONS/mcp.md`, `api/openapi/helm.openapi.yaml`, `tests/conformance` | missing scope, wrong resource, list/call mismatch | MCP docs | M | enterprise bridge | auth story weak |
| [NEW] | P1 | Gateway/scanner coexistence docs | agentgateway, MCPProxy, Snyk, Ramparts, LiteLLM | E07, E11-E13, E25 | OSS/mixed | avoids proxy-only confusion | topology docs: outer routing/scanning, HELM inner PEP/evidence | `docs/COMPATIBILITY.md`, `docs/INTEGRATIONS/mcp.md`, examples | docs truth | compatibility docs | S | narrative clarity | distribution pressure |
| [NEW] | P1 | Optional DSSE/JWS export envelope design | DSSE/JWS/Sigstore/SCITT | E45-E50 | standards/open | interoperability without format swap | wrap HELM receipt roots, not replace native receipts | `protocols/spec/evidence-pack-v1.md`, `docs/VERIFICATION.md` | future golden fixtures | verification docs | M | procurement bridge | evidence less portable |
| [NEW] | P1 | Optional OpenFGA relationship resolver | OpenFGA/Zanzibar | E30 | Apache-2.0 | resource graph auth | relationship snapshot token recorded in decision receipt | `core/pkg/authz`, `core/pkg/pdp`, `schemas/receipts` | stale tuple, service unavailable, race tests | policy-language docs | M | enterprise auth | weak delegated auth |
| [NEW] | P2 | MCP server quarantine/approval surface | MCPProxy, VerdictLayer | E11, E14 | MIT/public | developer trust/DX | unknown server enters quarantined state until approved | `core/pkg/mcp`, `schemas/approvals`, `apps/console` | UI state/API tests | Console docs | L | adoption | weaker desktop UX |
| [DEFER] | P3 | PQC/ML-DSA/SCITT default receipts | asqav, SCITT, COSE | E48-E50 plus prior April radar | draft/mixed | future proofing | monitor; no default key-management change | none now | none now | roadmap note only | S | future narrative | low now |
| [DEFER] | P3 | Physical AI adapter | ROS 2/Open-RMF | E54-E55 | mixed/open | future vertical | monitor; no OSS core expansion | none now | none now | no tactical docs now | S | optional vertical | low unless customer asks |

## Clean-Room Implementation Specs

### Spec A: Negative Execution-Boundary Conformance

Neutral functional spec:

- Given a tool call request, the implementation must produce a deterministic
  deny result and receipt when policy is unavailable, policy is stale, required
  credentials are absent, arguments do not match pinned schema, the advertised
  tool differs from the callable tool, or PDP/ReBAC/backend evaluation fails.
- The upstream tool must not be invoked on deny.
- The deny record must contain a stable reason code, policy reference when
  available, receipt hash/signature, and causal parent linkage.

HELM-native architecture:

- Add conformance fixtures and tests around HELM's Guardian/PEP and MCP
  gateway, using toy MCP/tool fixtures under `tests/conformance`.
- Use existing reason-code and receipt primitives rather than adopting any
  competitor policy language or audit format.

Public contract impact:

- May add or clarify reason codes in OpenAPI/schema docs.
- No new external dependency required.

Security impact:

- Hardens public fail-closed claims and prevents silent fail-open regressions.

Test plan:

- Unit tests for each fail mode.
- Conformance tests for MCP list/call mismatch and deny receipt emission.
- Offline verification of generated deny receipt fixtures.

Docs plan:

- Update conformance guide and MCP integration docs after implementation.

### Spec B: Sandbox Grant Evidence

Neutral functional spec:

- Every governed execution that enters a sandbox must record the authority
  granted to that sandbox: filesystem preopens, env variables passed by name and
  redaction/hash policy, network mode/CIDR/destinations, runtime/image/template
  digest, CPU/memory/time/gas limits, policy model id, and relationship snapshot
  token when applicable.
- Verification must fail if evidence claims a grant that was not present in the
  receipt chain or if canonical grant hashes are tampered.

HELM-native architecture:

- Define a HELM sandbox grant object in receipt/evidence contracts.
- Bind grant hash into the decision receipt and EvidencePack manifest.
- Keep backend-specific adapters under the sandbox actuator boundary.

Public contract impact:

- Receipt/evidence schema version bump or additive optional field with strict
  canonicalization.

Security impact:

- Makes sandbox authority auditable and reduces ambiguity around egress, mounts,
  secrets, and images.

Test plan:

- Canonicalization golden tests.
- Tamper tests for grant changes.
- Overgrant deny tests.
- Offline verification tests.

Docs plan:

- Update Execution Security Model and EvidencePack spec after implementation.

### Spec C: MCP Auth Profile

Neutral functional spec:

- HELM publishes a profile for MCP protected-resource metadata, OAuth/OIDC
  discovery assumptions, accepted scopes, insufficient-scope challenges, and
  consistency between `tools/list` visibility and `tools/call` authorization.
- Unknown or insufficient scopes produce a deterministic deny and receipt.

HELM-native architecture:

- Extend current MCP auth docs and conformance tests.
- Keep auth profile independent of any one SaaS IdP.

Public contract impact:

- OpenAPI and MCP docs clarify metadata and error shapes.

Security impact:

- Reduces delegated-token ambiguity and makes MCP auth behavior testable.

Test plan:

- Protected-resource metadata test.
- Missing/wrong resource tests.
- Insufficient scope tests.
- List/call consistency test.

Docs plan:

- Add profile section to MCP docs and conformance guide.

### Spec D: Coexistence With Outer Gateways and Scanners

Neutral functional spec:

- Document that HELM can run below or beside gateways/scanners that handle
  routing, compression, inventory, DLP, or developer UX.
- HELM remains the authority for execution admissibility and signed evidence.

HELM-native architecture:

- Add topology diagrams and examples using generic "outer gateway" and
  "scanner" language in public docs.
- Do not publish competitor-named comparisons without approval.

Public contract impact:

- None.

Security impact:

- Prevents users from treating passive logs or route-level filters as proof.

Test plan:

- Docs truth check only unless examples are added.

Docs plan:

- Update compatibility and MCP integration docs after approval.

### Spec E: Optional Standards Export Envelopes

Neutral functional spec:

- HELM keeps native JCS JSON receipts as source of truth.
- Exporters may wrap receipt roots or EvidencePack summaries in DSSE/JWS,
  in-toto/SLSA, Sigstore bundle/Rekor, and later SCITT/COSE when stable.
- Export envelopes must be lossy only if clearly marked; they must not replace
  offline native verification.

HELM-native architecture:

- Implement envelope exporters as optional adapters over verified pack roots.
- Add golden fixtures per envelope only after contract design.

Public contract impact:

- New export options and docs, no default receipt replacement.

Security impact:

- Improves external interoperability while preserving HELM's canonical truth.

Test plan:

- Golden fixture byte determinism.
- Verification of wrapped root.
- Failure when native pack is tampered.

Docs plan:

- Verification docs explain native vs external envelope authority.

## Final Recommendation

Build now:

- P0 negative execution-boundary conformance gates.
- P0 sandbox grant receipt/evidence contract design.
- P1 MCP auth profile.
- P1 gateway/scanner coexistence docs.

Do not build now:

- Generic AI governance platform features.
- Passive observability as a substitute for execution receipts.
- Default PQC/ML-DSA, SCITT, or COSE receipt changes.
- A broad agent framework or orchestration layer.
- Competitor-named public comparison pages.

Watch:

- AGT release cadence and offline receipt docs.
- PolicyLayer license/posture and MCP firewall adoption.
- agentgateway gateway distribution and policy model.
- VerdictLayer/HumanLatch approval-control-plane traction.
- Agent Policy Specification adoption.
- MCP authorization updates and SEPs.
- OTel GenAI stabilization.
- SCITT/COSE implementation maturity.
- NCCoE agent identity/authorization guidance.

Remove or simplify:

- Any OSS tactical docs that over-emphasize "AI governance platform",
  "trust layer", "proxy", or long-horizon physical-world/org-autonomy language
  without code-backed proof.

Claim publicly only when repo reality supports it:

- HELM is an OSS execution kernel and self-hostable Console for governed AI
  tool calling.
- HELM sits at the execution boundary, evaluates before dispatch, records
  signed allow/deny receipts, exports EvidencePacks, supports offline
  verification, and can integrate with MCP and OpenAI-compatible flows where
  implemented.

Must not claim:

- Certified compliance with NIST/ISO/EU AI Act.
- Compatibility with a competitor unless tested and lawful.
- Superiority over named vendors without reproducible public evidence.
- Stable conformance to draft standards.
- That logs, traces, dashboards, or OTel spans are equivalent to signed
  receipts or offline-verifiable evidence.
