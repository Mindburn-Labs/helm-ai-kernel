---
title: OSS Traction Playbook
last_reviewed: 2026-06-02
---

# OSS Traction Playbook

This page keeps public launch and community work tied to source-backed HELM AI Kernel behavior.

## Attention Goals

- More GitHub stars, watchers, forks, discussions, first issues, and external contributors.
- More docs and website visitors who run a local demo before evaluating hosted Mindburn Labs surfaces.
- More ecosystem visibility in MCP, AI gateway, agent-framework, and LLM security communities.

## UTM Links

| Channel | Docs link |
| --- | --- |
| GitHub README | `https://helm.docs.mindburn.org/helm-ai-kernel?utm_source=github&utm_medium=readme&utm_campaign=oss-traction` |
| GitHub Discussions | `https://helm.docs.mindburn.org/helm-ai-kernel?utm_source=github&utm_medium=discussions&utm_campaign=oss-traction` |
| Hacker News | `https://helm.docs.mindburn.org/helm-ai-kernel?utm_source=hackernews&utm_medium=showhn&utm_campaign=oss-traction` |
| Product Hunt | `https://helm.docs.mindburn.org/helm-ai-kernel?utm_source=producthunt&utm_medium=launch&utm_campaign=oss-traction` |
| Reddit | `https://helm.docs.mindburn.org/helm-ai-kernel?utm_source=reddit&utm_medium=community&utm_campaign=oss-traction` |
| LinkedIn | `https://helm.docs.mindburn.org/helm-ai-kernel?utm_source=linkedin&utm_medium=social&utm_campaign=oss-traction` |
| X | `https://helm.docs.mindburn.org/helm-ai-kernel?utm_source=x&utm_medium=social&utm_campaign=oss-traction` |

## Launch Drafts

Show HN title: `Show HN: HELM, an execution firewall for AI agent tool calls`

Short description: HELM AI Kernel is an open-source execution firewall for MCP and AI agents. It quarantines unknown tools before dispatch, evaluates ALLOW, DENY, and ESCALATE decisions, emits signed receipts, and verifies evidence offline.

## Proof Assets

- Social preview: [helm-social-preview.png](assets/helm-social-preview.png)
- Social preview source: [helm-social-preview.svg](assets/helm-social-preview.svg)
- MCP quarantine proof board: [helm-mcp-quarantine-demo.png](assets/helm-mcp-quarantine-demo.png)
- MCP quarantine proof board source: [helm-mcp-quarantine-demo.svg](assets/helm-mcp-quarantine-demo.svg)
- Sanitized transcripts: [examples/launch/assets](../examples/launch/assets)

Use the PNG files for README, launch posts, and link previews. Keep the SVG
files as the editable sources when copy, layout, or proof framing changes.

Render updated PNG files from the SVG sources before publishing visual changes:

```bash
rsvg-convert docs/assets/helm-mcp-quarantine-demo.svg -w 1600 -h 900 -o docs/assets/helm-mcp-quarantine-demo.png
rsvg-convert docs/assets/helm-social-preview.svg -w 1280 -h 640 -o docs/assets/helm-social-preview.png
```
