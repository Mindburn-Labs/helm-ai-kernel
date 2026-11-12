# BGT Labs Sentinel Proposal Types

<!-- quantum_posture: this page describes type declarations only; nothing here signs, verifies or implements a cryptographic control. -->

> Status: type declarations only. There is no Sentinel handler, endpoint or adapter in this repository, and this page is not release or runtime evidence.

The Sentinel connector was removed (`controls.yaml` CTL-043). `core/pkg/mcp/sentinel.go` still declares two types:

- `SentinelIntent`: the fields the kernel expected in a BGT Labs Sentinel authorization proposal (`principal`, `action`, `resource`, `context`).
- `SentinelConnector`: a struct that holds a Guardian reference. It has no constructor and no methods.

Nothing parses a proposal, maps a `SentinelIntent` to a `DecisionRequest`, evaluates it, or signs a result. No shipped binary references either type, and no test covers them or checks the field set against a Sentinel payload.
