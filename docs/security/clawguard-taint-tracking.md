# ClawGuard Taint Tracking Prototype

Source: Wei Zhao, Zhe Li, Peixin Zhang, and Jun Sun, "ClawGuard: A Runtime Security Framework for Tool-Augmented LLM Agents Against Indirect Prompt Injection", arXiv:2604.11790.

ClawGuard's core operational move is deterministic enforcement at every tool-call boundary. HELM OSS maps that into the existing Guardian and PRG surfaces:

| ClawGuard concept | HELM OSS implementation |
| --- | --- |
| Task/tool boundary rule set | PRG/CEL requirements evaluated by Guardian |
| Taint on tool-returned or external content | `Effect.Taint` and `AuthorizedExecutionIntent.Taint` |
| Deterministic tool-call interception | Feature-flagged Guardian tainted-egress gate |
| Auditable enforcement | signed `DecisionRecord`, intent taint binding, TLA invariant |

## Runtime Contract

Callers may attach taint labels through `DecisionRequest.Context`:

```json
{
  "destination": "https://external.example/upload",
  "taint": ["pii", "tool_output"]
}
```

When `HELM_TAINT_TRACKING=1`, Guardian denies outbound egress carrying sensitive taint (`pii`, `credential`, or `secret`) unless the context explicitly contains:

```json
{
  "allow_tainted_egress": true
}
```

The decision remains fail-closed: denial uses `TAINTED_DATA_EGRESS_DENY`, and issued execution intents copy normalized taint labels from the effect they authorize.

## CEL Helper

PRG requirements can use either explicit or shorthand forms:

```cel
taint_contains(input.taint, "pii")
taint_contains("pii")
```

The shorthand is rewritten to the explicit form inside the PRG evaluator. Policy-pack validation supports the same shorthand against the top-level `taint` variable.
