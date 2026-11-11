---
title: Write Policies
last_reviewed: 2026-08-21
---

# Write Policies

Policies decide whether a proposed action becomes `ALLOW`, `DENY`, or
`ESCALATE`. The shipped binaries decide with CEL: an action in a serve policy
pack can carry a boolean CEL `expression` over the request `input`, which
`core/pkg/kernel/authority` compiles and evaluates. Rego and Cedar sources
compile with `helm-ai-kernel bundle build`; their evaluators are library code
that no shipped command calls, so a Rego or Cedar policy does not decide an
action.

## Choose A Language

| Use case | Start with |
| --- | --- |
| Small attribute rules | CEL |
| Existing OPA/Rego practice | Rego |
| Entity and role relationships | Cedar |

The examples below are the files under `examples/policies/`; they express one
rule as a verdict object. No shipped command evaluates that verdict-object
form, including the CEL one: runtime CEL is the boolean `expression` of a pack
action.

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
helm-ai-kernel bundle build --language=rego ./policy.rego
helm-ai-kernel policy test --dir policies
helm-ai-kernel conform vectors --json
```

Use `DENY` for unsafe or mismatched actions. Use `ESCALATE` when the call
must stay blocked until a credential-verified durable dispatch admission
exists; local `mcp approve` does not mint that authority.
