---
title: Cognitive Firewall Pattern
last_reviewed: 2026-05-05
---

# Cognitive Firewall Split-Compute Pattern

## Audience

Architecture reviewers evaluating the fail-closed execution firewall pattern and its HELM AI Kernel implementation boundaries.

## Outcome

After this page you should know what this surface is for, which source files own the behavior, which public route or adjacent page to use next, and which validation command to run before changing the claim.

## Source Truth

- Public route: `helm-ai-kernel/architecture/cognitive-firewall`
- Source document: `helm-ai-kernel/docs/architecture/cognitive-firewall.md`
- Public manifest: `helm-ai-kernel/docs/public-docs.manifest.json`
- Source inventory: `helm-ai-kernel/docs/source-inventory.manifest.json`
- Validation: `make docs-coverage`, `make docs-truth`, and `npm run coverage:inventory` from `docs-platform`

Do not expand this page with unsupported product, SDK, deployment, compliance, or integration claims unless the inventory manifest points to code, schemas, tests, examples, or an owner doc that proves the claim.

Source: Qianlong Lan and Anuj Kaul, "The Cognitive Firewall: Securing Browser Based AI Agents Against Indirect Prompt Injection Via Hybrid Edge Cloud Defense", arXiv:2603.23791.

The HELM AI Kernel mapping keeps the paper's three-stage split:

| Paper stage | HELM AI Kernel mapping |
| --- | --- |
| Local visual Sentinel | `BrowserSplitObservation`: URL, DOM hash, visual-text hash, Sentinel risk, findings |
| Cloud Deep Planner | `BrowserSplitPlan`: tool intent, side-effect flag, planner reference hash |
| Deterministic Guard | `BrowserSplitAdapter`: domain policy, Sentinel risk gate, planner-reference gate, ProofGraph intent node |

The adapter lives at `core/pkg/runtimeadapters/browser_split.go`. It does not ship a browser UI or cloud planner. Instead, it defines the boundary contract a browser extension, OpenClaw-style gateway, or MCP browser tool can use when forwarding an already-scanned action into HELM governance.

## Egress Gate Composition

The split-compute guard should run before browser side effects are dispatched:

1. The browser-side Sentinel hashes the DOM and visual text, scores presentation-layer prompt-injection risk, and forwards only risk metadata and hashes.
2. The planner returns a tool intent with `planner_ref` instead of raw chain-of-thought.
3. `BrowserSplitAdapter` denies side-effecting actions when the Sentinel risk exceeds policy, when the destination is outside domain scope, or when the planner reference is missing.
4. Deployments that also use Guardian should pass the same destination as `destination`, the page text hash as evidence, and tainted browser content as `user_input`/`source_channel=TOOL_OUTPUT` so Guardian's threat scanner and egress checker can produce the final signed decision.

This keeps semantic reasoning and execution authority split: the planner may propose, but the deterministic guard owns the last pre-dispatch decision.

## Troubleshooting

| Symptom | First check |
| --- | --- |
| Published output is stale or incomplete | Run `npm run helm-public:accuracy` in `docs-platform`, then check the source path and public manifest row for this page. |
| A claim needs implementation backing | Check the Source Truth files above and update the implementation, manifest, source inventory, or page in the same change. |

## Diagram

```mermaid
flowchart TD
    subgraph Ingestion["1. Ingestion & Context Plane"]
        intent["Agent intent"]
    end

    subgraph Evaluation["2. Evaluation & Policy Plane"]
        normalize["Normalize context"]
        policy["Policy decision"]
    end

    subgraph Execution["3. Execution & Verdict Plane"]
        permit{"Permit?"}
        execute["Execute tool"]
        block["Block effect"]
    end

    subgraph Ledger["4. Tamper-Evident Ledger Plane"]
        receipt["Receipt"]
        verify["Verification"]
    end

    %% Operational Flow Edges
    intent --> normalize
    normalize --> policy
    policy --> permit
    permit -->|allow| execute
    permit -->|deny| block
    execute --> receipt
    block --> receipt
    receipt --> verify

    %% Premium Styling Rules
    style normalize fill:#2d3748,stroke:#4a5568,stroke-width:2px,color:#fff
    style policy fill:#2d3748,stroke:#4a5568,stroke-width:2px,color:#fff
    style permit fill:#3182ce,stroke:#2b6cb0,stroke-width:2px,color:#fff
    style execute fill:#3182ce,stroke:#2b6cb0,stroke-width:2px,color:#fff
    style block fill:#e53e3e,stroke:#9b2c2c,stroke-width:2px,color:#fff
    style receipt fill:#2f855a,stroke:#276749,stroke-width:2px,color:#fff
    style verify fill:#2f855a,stroke:#276749,stroke-width:2px,color:#fff
```



<!-- docs-depth-final-pass -->

## Implementation Checklist

A change to this pattern is complete only when the adapter test covers allow, deny, and missing-planner-reference paths, the receipt records the Sentinel risk and planner reference, and the public page still describes the browser UI and cloud planner as integration points rather than bundled HELM AI Kernel features. Keep examples focused on the boundary contract: input hashes, domain scope, side-effect flag, destination, policy threshold, and resulting receipt. If a downstream browser extension or MCP browser tool adds richer context later, update this page by linking to that source-owner document instead of widening the core adapter claim.
