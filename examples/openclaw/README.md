# OpenClaw Browser Split-Compute Pattern

This example documents the runtime-adapter contract for an OpenClaw-style browser gateway.

The browser gateway should run local Sentinel checks before sending an action to HELM:

```json
{
  "runtime_type": "browser_split",
  "tool_name": "browser.submit",
  "principal_id": "openclaw-browser-agent",
  "arguments": {
    "url": "https://app.example.com/checkout"
  },
  "metadata": {
    "browser.dom_hash": "sha256:...",
    "browser.visual_text_hash": "sha256:...",
    "browser.sentinel_risk": "12",
    "browser.sentinel_findings_csv": "",
    "browser.planner_ref": "sha256:planner-output",
    "browser.side_effect": "true",
    "browser.destination": "https://app.example.com/checkout"
  }
}
```

`BrowserSplitAdapter` records a ProofGraph intent node and denies side effects when local Sentinel risk is too high, the destination is outside policy scope, or the planner reference is missing.

For deployments that also use Guardian, forward tainted page text through Guardian's threat scanner and set the egress `destination` to the same URL before dispatching the browser tool.
