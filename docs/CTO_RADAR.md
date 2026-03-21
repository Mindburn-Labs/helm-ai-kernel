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

---

*This file is internal. Update after each operator loop cycle.*
