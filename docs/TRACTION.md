---
title: HELM AI Kernel OSS Traction Plan
last_reviewed: 2026-06-02
---

# HELM AI Kernel OSS Traction Plan

This page keeps public launch and community work tied to source-backed HELM AI Kernel behavior. The goal is not maximum attention; it is maximum verified Kernel adoption.

Primary objective: drive verified adoption of HELM AI Kernel as the local-first fail-closed execution boundary for AI agents.

Primary conversion: visitor -> install -> run boundary -> trigger DENY or ESCALATE -> inspect signed receipt -> verify EvidencePack offline -> star, follow, discuss, or contribute.

## Canonical Positioning

- Public OSS name: HELM AI Kernel.
- Repository: `Mindburn-Labs/helm-ai-kernel`.
- Binary: `helm-ai-kernel`.
- Disambiguation: Mindburn Labs' HELM execution kernel for AI agents, not the Kubernetes package manager.
- Short description: Fail-closed execution firewall for AI agents: quarantine MCP tools, proxy OpenAI-compatible requests, emit signed receipts, and verify EvidencePacks offline.
- Proof vocabulary: signed receipts, EvidencePack, ProofGraph, offline verification, ALLOW, DENY, ESCALATE.

Avoid `HELM OSS`, `helm-oss`, `HELM Teams`, generic AI governance platform language, hosted-control-plane claims for Kernel, certification claims, or Enterprise features framed as Kernel features.

## GitHub Metadata

Repository topics should spend the 20 slots on the execution-boundary wedge:

```text
ai-agents
agent-security
mcp
model-context-protocol
tool-calling
execution-firewall
ai-security
llm-security
developer-tools
self-hosted
open-source
policy-engine
zero-trust
sandbox
signed-receipts
cryptographic-receipts
evidencepack
openai-compatible
llmops
security
```

Do not use `saas`, `compliance`, `ai-governance`, `generative-ai`, `agentic-ai`, `helm`, `openai`, or `proof-receipts` as OSS repo topics.

## README First Viewport

The README must lead with mechanism and proof:

```md
# HELM AI Kernel

HELM AI Kernel is the fail-closed execution firewall for AI agents.

Mindburn Labs' HELM execution kernel for AI agents, not the Kubernetes package manager.

Models propose. HELM governs execution. Every ALLOW / DENY / ESCALATE decision leaves proof.
```

The star CTA belongs after the local proof path:

```text
Star HELM AI Kernel if you want to follow fail-closed AI agent execution, MCP quarantine, signed receipts, and offline-verifiable EvidencePacks.
```

## Proof Assets

Public proof assets are executable artifacts, not just polished images. Each asset must name:

- asset name
- command to generate
- expected verdict: ALLOW, DENY, or ESCALATE
- receipt path
- EvidencePack path
- offline verification command
- expected verification output
- screenshot or GIF source
- last verified commit SHA

Canonical demo ladder:

1. Unknown MCP tool enters quarantine.
2. Sensitive action returns DENY or ESCALATE.
3. Signed receipt is produced.
4. EvidencePack verifies offline.
5. Tampered receipt fails verification.

Current assets:

- Social preview: [helm-social-preview.png](assets/helm-social-preview.png)
- Social preview source: [helm-social-preview.svg](assets/helm-social-preview.svg)
- MCP quarantine proof board: [helm-mcp-quarantine-demo.png](assets/helm-mcp-quarantine-demo.png)
- MCP quarantine proof board source: [helm-mcp-quarantine-demo.svg](assets/helm-mcp-quarantine-demo.svg)
- Sanitized transcripts: [examples/launch/assets](../examples/launch/assets)

Render updated PNG files from SVG sources before publishing visual changes:

```bash
rsvg-convert docs/assets/helm-mcp-quarantine-demo.svg -w 1600 -h 900 -o docs/assets/helm-mcp-quarantine-demo.png
rsvg-convert docs/assets/helm-social-preview.svg -w 1280 -h 640 -o docs/assets/helm-social-preview.png
```

## Launch Sequence

Gate 1: GitHub readiness.
README, repo description, topics, social preview, release assets, proof demos, docs, issue templates, security policy, and Discussions are source-backed and coherent.

Gate 2: Technical launch.
Use Show HN and targeted security/devtools Reddit only after the local proof path is clean.

Gate 3: Ecosystem integration.
Submit upstream fixtures and listings only after the repo has concrete MCP, proxy, receipt, and EvidencePack examples.

Gate 4: Broader social.
Use LinkedIn, X, Product Hunt, DEV, and Hashnode only after technical audiences have a proof artifact to reference.

Show HN title: `Show HN: HELM AI Kernel, a fail-closed execution firewall for AI agents`

Short description: HELM AI Kernel quarantines unknown MCP tools before dispatch, governs OpenAI-compatible requests through ALLOW, DENY, and ESCALATE decisions, emits signed receipts, and verifies EvidencePacks offline.

## UTM Links

| Channel | Docs link |
| --- | --- |
| GitHub README | `https://helm.docs.mindburn.org/helm-ai-kernel?utm_source=github&utm_medium=readme&utm_campaign=oss-traction` |
| GitHub Discussions | `https://helm.docs.mindburn.org/helm-ai-kernel?utm_source=github&utm_medium=discussions&utm_campaign=oss-traction` |
| Hacker News | `https://helm.docs.mindburn.org/helm-ai-kernel?utm_source=hackernews&utm_medium=showhn&utm_campaign=oss-traction` |
| Reddit | `https://helm.docs.mindburn.org/helm-ai-kernel?utm_source=reddit&utm_medium=community&utm_campaign=oss-traction` |
| Product Hunt | `https://helm.docs.mindburn.org/helm-ai-kernel?utm_source=producthunt&utm_medium=launch&utm_campaign=oss-traction` |
| LinkedIn | `https://helm.docs.mindburn.org/helm-ai-kernel?utm_source=linkedin&utm_medium=social&utm_campaign=oss-traction` |
| X | `https://helm.docs.mindburn.org/helm-ai-kernel?utm_source=x&utm_medium=social&utm_campaign=oss-traction` |

## Discussions

Use Discussions for high-signal participation:

- Announcements
- Proof demo help
- MCP server quarantine proposals
- Receipt and EvidencePack schema questions
- Integration ideas
- First contribution help
- Show-and-tell

Triage flow: Discussion -> maintainer triage -> reproduction, fixture, or spec -> issue.

## Contributor Funnel

OSS-safe contribution streams:

- docs: quickstart clarity, troubleshooting, examples
- mcp: quarantine fixtures, server metadata, authorization examples
- proxy: OpenAI-compatible client examples
- receipts: offline verification examples, tamper tests
- evidence: EvidencePack examples
- sdk: small SDK polish and samples
- security: negative tests and threat-model examples
- ecosystem: factual integrations and listings

Every contributor issue should include context, exact file paths, expected output, validation command, acceptance criteria, and out-of-scope boundaries. Do not expose Enterprise implementation details in OSS issues.

## Measurement

Awareness:

- GitHub visitors, referrers, and popular content
- social, Hacker News, Reddit, and docs traffic

Evaluation:

- README and quickstart visits
- Homebrew install interest or available formula analytics
- clone count
- release asset downloads

Proof:

- boundary started
- proof demo run
- DENY or ESCALATE receipt generated
- EvidencePack exported
- EvidencePack verified offline

Engagement:

- stars
- watchers
- discussions
- issues
- PRs
- ecosystem mentions

Commercial bridge:

- HELM AI Enterprise Basic interest CTA clicks
- docs path from Kernel to Basic
- inbound team-use requests

GitHub traffic windows are short, so export private analytics daily, publish a weekly channel cohort report, keep a launch-post UTM map, and log README hook changes.

## Truth Gate

Run this checklist before publishing README edits, launch posts, diagrams, videos, social previews, and website copy:

- Uses HELM AI Kernel, not HELM OSS as the current public name.
- Mentions not Kubernetes Helm when context is introductory.
- Uses signed receipts, EvidencePack, and ProofGraph exactly.
- Uses ALLOW, DENY, and ESCALATE.
- Does not claim seccomp or eBPF unless current code proves it.
- Does not claim a hosted control plane for OSS Kernel.
- Does not claim certification unless certification exists.
- Does not describe Enterprise features as Kernel features.
- Does not imply Basic or Enterprise weakens or forks Kernel semantics.
- Does not mention robot fleets, AGI OS, OrgDNA compiler, Titan, or physical-world control in OSS copy.

## Diagram Doctrine

OSS hero diagrams should use this shape:

```text
Agent / Model / Orchestrator
  -> Action Proposal
  -> HELM AI Kernel Boundary
  -> ALLOW / DENY / ESCALATE
  -> Signed Receipt
  -> ProofGraph
  -> EvidencePack
  -> Offline Verification
```

Keep CompanyArtifactGraph, GeneratedSpec, and Enterprise loop diagrams on Enterprise bridge pages, not the OSS hero.

## Ecosystem Rule

No listing PR without a working integration, fixture, or reproducible example. Prioritize:

- MCP quarantine fixture
- OpenAI-compatible proxy example
- receipt verification fixture
- EvidencePack tamper-negative test
- policy DENY or ESCALATE example

Submit listings after the proof exists.

## Commercial Bridge

Use this bridge after local Kernel proof:

```text
Try HELM AI Kernel locally.
Use HELM AI Enterprise Basic for shared approvals, receipts, policies, and short-retention evidence.
Talk to Mindburn Labs about production execution authority.
```

HELM AI Enterprise Basic gives teams a shared control plane for governed AI actions: workspaces, approvals, receipts, API access, custom policies, and short-retention evidence, all built on HELM AI Kernel.
