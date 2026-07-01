---
title: Write Policies
last_reviewed: 2026-07-01
---

# Write Policies

Policies decide whether a proposed action becomes `ALLOW`, `DENY`, or
`ESCALATE`. Public HELM supports CEL, Rego, and Cedar inputs through one
normalized decision boundary.

## Choose A Language

| Use case | Start with |
| --- | --- |
| Small attribute rules | CEL |
| Existing OPA/Rego practice | Rego |
| Entity and role relationships | Cedar |

All three paths must produce the same kind of verdict envelope.

## CEL

```cel
request.action == "view"
  ? {"verdict": "ALLOW"}
  : {"verdict": "DENY"}
```

CEL is the smallest path for attribute checks. Keep rules direct; avoid nested
policy logic that is hard to review.

## Rego

```rego
package helm.policy
import rego.v1

default decision := {"verdict": "DENY"}
decision := {"verdict": "ALLOW"} if {
  input.action == "view"
}
```

Rego is useful when your team already uses OPA or set-based rules. HELM uses a
restricted capability set for deterministic evaluation.

## Cedar

```cedar
permit(principal, action == Action::"view", resource);
```

Cedar is useful for entity-shaped authorization where principals, actions, and
resources have explicit types.

## Determinism Rules

Policy evaluation does not read the network, filesystem, environment, random
numbers, or system clock directly. The kernel injects request data and time so
the same input can be verified later.

## Build And Test

```bash
helm-ai-kernel bundle build --policy ./policy.cel --out ./policy.bundle
helm-ai-kernel evaluate --bundle ./policy.bundle --input ./request.json
helm-ai-kernel conform --level L1 --json
```

Use `DENY` for unsafe or mismatched actions. Use `ESCALATE` only when a
developer can resolve the block with a local scoped approval.
