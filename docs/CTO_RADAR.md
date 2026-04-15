---
title: CTO_RADAR
---

# CTO / Core Contributor Radar

This document tracks high-signal individuals identified through live conversations in the agent security, MCP, and execution-boundary ecosystem. Updated continuously as part of the HELM OSS operator mission.

---

## Scoring Dimensions

| Dimension | Weight |
|-----------|--------|
| Systems / security depth | 0-25 |
| Execution-safety focus | 0-20 |
| OSS track record | 0-15 |
| Builder energy (ships things) | 0-15 |
| Product judgment | 0-10 |
| Clarity of communication | 0-10 |
| Network centrality | 0-5 |

---

## Tier 1 — Highest Priority

### Nash Borges (@nashborges / @RogueEngineer)

- **Role:** SVP Engineering & AI at Sophos. Former NSA. Hopkins PhD.
- **Why:** Published a full CaMeL prototype POC for OpenClaw. Opened 6 focused enforcement-hook issues (openclaw/openclaw#48503–48519) that describe the same architecture HELM implements. Uses identical framing: "enforcement primitives in the kernel, policy engine as plugin." The SELinux analogy he uses is exact.
- **Evidence:**
  - Article: [Building a CaMeL Prototype for OpenClaw](https://x.com/RogueEngineer/status/2033660042893803777)
  - Issues: `openclaw/openclaw` #48503, #48506, #48509, #48510, #48515, #48517, #48519
- **HELM interactions:**
  - X reply to his article (Mar 2026) referencing `before_tool_call` hook + SELinux analogy + HELM
  - GitHub comment on #48503 with HELM's implementation decisions (actionCategory + capabilities bitmask, externalContentDetected, receiptId)
- **Next step:** Monitor for response to GitHub comment. If positive engagement, initiate DM with concrete technical question about hook schema alignment.
- **Score estimate:** 92/100

---

### Thomas Roccia (@fr0gger_)

- **Role:** Senior Threat Researcher at Microsoft. 137K+ followers. SANS instructor.
- **Why:** Published SHIELD.md (security standard for OpenClaw/AI agents). Explicitly named SHIELD's ceiling: "not a security boundary." This is the exact gap HELM fills.
- **Evidence:** [SHIELD.md article](https://x.com/fr0gger_/status/2020025525784514671) with 137K views
- **HELM interactions:**
  - X reply (Mar 2026): named prompt injection override of SHIELD as root cause, positioned HELM as runtime layer below the model
- **Next step:** Monitor reply engagement. Consider quoting his SHIELD article with HELM architecture framing once thread cools.
- **Score estimate:** 85/100

---

## Tier 2 — High Priority

### @affaanmustafa

- **Role:** Anthropic Hackathon winner. Agentic security researcher.
- **Why:** Published "Shorthand Guide to Everything Agentic Security" with exfiltration-via-tool-call as core threat model. Active in MCP/agent security community.
- **HELM interactions:** X reply (Mar 2026) on exfiltration-via-tool-call pattern → missing execution boundary → HELM
- **Next step:** Follow for new posts. Engage next relevant article.
- **Score estimate:** 78/100

### Mario Poneder (@MarioPoneder)

- **Role:** Smart contract security researcher, AI red teaming. Affiliated with Spearbit, Zenith256.
- **Why:** Posted: "prompts are like comments — non-binding. Security boundaries must be enforced, not requested. The real boundary is between the LLM layer and the execution layer." Verbatim HELM architecture framing.
- **HELM interactions:** X reply (Mar 2026): execution layer intercepts + validates + enforces + signs, below where LLM can touch
- **Next step:** Engage next relevant post. Strong crossover between smart contract security and HELM's signed receipt / proof-graph model.
- **Score estimate:** 74/100

### @razashariff (autogen MCP tool poisoning)

- **Role:** Microsoft AutoGen team contributor.
- **Why:** Opened `microsoft/autogen#7427` (MCP tool poisoning CVE-class), referencing OWASP MCP Top 10 and fail-closed defaults.
- **HELM interactions:** GitHub comment on #7427 with schema pinning + execution boundary + signed receipts + `McpWorkbench` hook suggestion
- **Next step:** Monitor for response. Offer to contribute a concrete validation hook to `autogen-ext/tools/mcp/`.
- **Score estimate:** 71/100

---

## Tier 3 — Watch List

| Handle | Context | Signal |
|--------|---------|--------|
| @dreddi | GitHub CLI org (openclaw/openclaw maintainer) | Opened `cli/cli#12912` (schema for agents); responded to HELM comment |
| @williammartin | GitHub CLI org | Active on agent security issues |
| @arscontexta | "determinism boundary separates guaranteed agent behavior from probabilistic compliance" | Exact HELM framing; small account but sharp |
| @asmah2107 | "Each tool call is an unsigned contract" post | Named the root of all MCP attack classes correctly |
| @erans | X | "Rule files are not enforcement" — exact execution-boundary framing; replied with HELM |
| @provnai | X/GitHub | Built McpVanguard MCP proxy; semantic scoring gap identified; execution boundary reply sent |
| @s-a-m-a-i | GitHub | Built PolicyLayer Intercept (transport proxy); commented on complementary two-layer stack |
| @ilblackdragon | GitHub | nearai/ironclaw maintainer; persistent sandbox issue#1458; per-call policy hook comment sent |
| @MindTheGapMTG | X | "immutable audit trail" framing on MCP runtime security; signed receipt reply sent |
| @Mako_L | GitHub | BakeLens/crust security researcher; DLP bypass report#116; dispatch boundary comment sent |

---

## Interaction Log

| Date | Surface | Target | Action | Response |
|------|---------|--------|--------|----------|
| Mar 2026 | X | @fr0gger_ | Reply to SHIELD.md article | Pending |
| Mar 2026 | X | @affaanmustafa | Reply to agentic security guide | Pending |
| Mar 2026 | GitHub | openclaw/openclaw#48503 | Comment: actionCategory + capabilities + receiptId | Pending |
| Mar 2026 | GitHub | microsoft/autogen#7427 | Comment: schema pinning + execution boundary + McpWorkbench | Pending |
| Mar 2026 | GitHub | cli/cli#12912 | Comment: two-layer schema + execution boundary architecture | Pending |
| Mar 2026 | X | @RogueEngineer | Reply to CaMeL prototype article | Pending |
| Mar 2026 | X | @asmah2107 | Reply to MCP security post | Pending |
| Mar 2026 | X | @MarioPoneder | Reply to enforcement layer post | Pending |
| Mar 2026 | X | @mindburnlabs | Posted 3-tweet thread: prompt-layer vs execution kernel | Live |
| Mar 2026 | X | @mindburnlabs | Posted AISecHub category-gap post (execution firewall) | Live |
| Mar 2026 | GitHub | ironcurtain#67 | Comment: HELM as atomic policy+receipt kernel, interop with ironcurtain | Live |
| Mar 2026 | GitHub | agentshield-benchmark#36 | Feature request: Execution Boundary category + HELM as reference | Live |
| Mar 2026 | GitHub | nearai/ironclaw#1458 | Comment: per-call policy hook before exec_in_container, signed receipts | Live |
| Mar 2026 | GitHub | BakeLens/crust#116 | Comment: pattern-scanning root cause analysis, dispatch boundary alternative | Live |
| Mar 2026 | GitHub | github-mcp-server discussion#2125 | Comment: transport proxy vs execution kernel, two-layer stack framing | Live |
| Mar 2026 | X | @erans | Reply to "Rule files are not enforcement" post | Live |
| Mar 2026 | X | @MindTheGapMTG | Reply to immutable audit trail / runtime security layer | Live |
| Mar 2026 | X | @provnai | Reply to McpVanguard launch: schema-pinned dispatch gap | Live |

---

## Capability Radar — New Differentiators for CTO Conversations

These capabilities are unique to HELM and map directly to CTO-level concerns. Use in outreach and positioning.

### Cost & Financial Governance
| Capability | CTO Pitch | Status |
|---|---|---|
| **Cost attribution** | Per-decision cost attribution — know exactly which agent, tool, and session spent what. | Shipped |
| **Cost estimation** | Pre-execution cost estimation — budget enforcement knows what an action will cost before it runs. | Shipped |
| **SLO-driven governance** | SLO violations automatically trigger governance actions (throttle, escalate, freeze) — not just alerts. | Shipped |

### Compliance & Certification
| Capability | CTO Pitch | Status |
|---|---|---|
| **ZK compliance proofs** | Prove your agents are compliant to auditors without revealing proprietary policies or decision details. | Shipped |
| **Hybrid PQ signing** | Dual Ed25519 + ML-DSA-65 — future-proof signing that satisfies both current and post-quantum requirements. No migration cliff. | Shipped |
| **W3C DID identity** | Decentralized agent identity — no vendor lock-in to a central identity provider. | Shipped |
| **Evidence summaries** | Constant-size cryptographic summaries — auditors verify a 256-byte summary instead of GB-scale archives. | Shipped |

### Agent Workforce Management
| Capability | CTO Pitch | Status |
|---|---|---|
| **Memory governance** | Prevents memory poisoning across agent sessions. Trust-scored, integrity-verified agent memory. | Shipped |
| **Continuous delegation (AIP)** | Agents delegate to sub-agents with narrowing constraints, continuously monitored. No confused deputy. | Shipped |
| **SkillFortify** | Runtime tool integrity verification — detects tampering, version drift, unauthorized modifications. | Shipped |
| **Federated trust** | Cross-org trust roots — partner organizations can trust each other's agents without shared infrastructure. | Shipped |

### Supply Chain & Threat Defense
| Capability | CTO Pitch | Status |
|---|---|---|
| **MCPTox** | Detects rug-pull (tool behavior change post-approval), typosquatting, and supply chain attacks in MCP tool registries. | Shipped |
| **Ensemble scanner** | Multiple independent threat scanners with quorum-based verdicts — no single scanner bypass. | Shipped |
| **Supply chain provenance** | End-to-end signed attestations for tools, policies, and model artifacts. | Shipped |
| **DDIPE doc scanning** | Automated extraction of governance-relevant data from organizational documents. | Shipped |

### Observability & Operations
| Capability | CTO Pitch | Status |
|---|---|---|
| **CloudEvents SIEM export** | Governance decisions exported as CloudEvents — plugs directly into Splunk, Sentinel, Elastic. | Shipped |
| **OTel-native** | Full OpenTelemetry integration — traces, metrics, spans across the entire governance path. | Shipped |
| **Replay comparison** | Side-by-side replay diffs — see exactly how policy changes affect agent behavior before deployment. | Shipped |
| **Reversibility engine** | Declares which effects are reversible, tracks compensation actions, verifies rollback completion. | Shipped |

---

*This file is internal. Update after each operator loop cycle.*
