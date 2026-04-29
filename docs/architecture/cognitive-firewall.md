# Cognitive Firewall Split-Compute Pattern

Source: Qianlong Lan and Anuj Kaul, "The Cognitive Firewall: Securing Browser Based AI Agents Against Indirect Prompt Injection Via Hybrid Edge Cloud Defense", arXiv:2603.23791.

The HELM OSS mapping keeps the paper's three-stage split:

| Paper stage | HELM OSS mapping |
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
