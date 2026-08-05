---
title: Deny Reason Codes
last_reviewed: 2026-07-24
---

# Deny Reason Codes

Every `DENY` and `ESCALATE` verdict carries a machine-readable reason code plus
a human-readable reason string. This page explains the codes you can hit while
authoring policies and running the local MCP approval loop, what usually causes
them, and the next step that reaches `ALLOW`.

The normative, versioned registry of all codes is
[Reason Code Registry v1](../../protocols/specs/rfc/reason-codes-v1.md); the Go
constants live in `core/pkg/contracts/verdict.go`. This page is the
operator-facing companion: it covers the codes reachable from the Guardian and
the local `mcp` commands, and what to change when you see one.

## Policy Evaluation Codes

These come from Guardian policy evaluation (PRG requirement sets, including the
compiled serve policy used by `mcp serve --policy`).

| Code | Verdict | Usual cause | Next step |
| --- | --- | --- | --- |
| `MISSING_REQUIREMENT` | DENY | A requirement in the matched rule was not satisfied — most often a CEL expression did not match the call. | Read the reason string: it names the blocking requirement id and the available `input.*` fields with their types. Review that requirement in the policy source (see the worked example below). |
| `NO_POLICY_DEFINED` | DENY | No rule in the policy graph covers this action. | Add the action to the policy (serve policy: add the action to the reference pack), or call an action the policy authorizes. |
| `PRG_EVALUATION_ERROR` | DENY | The CEL expression failed to compile or evaluate (syntax error, missing key, wrong type). | Review the expression in the policy source. Policy source and literals are not copied into the public deny reason. |
| `ENVELOPE_INVALID` | DENY | The effect envelope failed structural validation. | Inspect the effect construction; this indicates a malformed call, not a policy mismatch. |
| `BUDGET_EXCEEDED` | DENY | The effect's `budget_id` is over its ceiling. | Raise the budget or stop the run. |
| `BUDGET_ERROR` | DENY | Budget backend unavailable (fail-closed). | Restore the budget backend; calls are denied until it answers. |

## MCP Approval Loop Codes

These come from the execution firewall behind `mcp authorize-call` (and the
same checks enforced at serve time).

| Code | Verdict | Usual cause | Next step |
| --- | --- | --- | --- |
| `APPROVAL_REQUIRED` | ESCALATE | The MCP server is unknown or remains quarantined because local credential verification is unavailable. | Inspect with `mcp quarantine` or `mcp pending`. Local `mcp approve` rejects opaque values; the governing approval integration must issue a credential-verified durable dispatch admission before re-evaluation. |
| `APPROVAL_REQUIRED` | DENY | A verifier-backed server exists, but this tool or effect is outside the exact admitted scope. | Do not widen scope locally. The governing approval integration must issue a new credential-verified durable dispatch admission for the exact request. |
| `APPROVAL_TIMEOUT` | DENY | A verifier-backed dispatch admission expired or was revoked. | Obtain a new credential-verified durable dispatch admission from the governing approval integration, then re-evaluate. |
| `SCHEMA_VIOLATION` | ESCALATE | The tool schema is not pinned yet. | Rerun `mcp authorize-call` with `--pinned-schema-hash <hash>`; the CLI prints the exact command with the hash filled in. |
| `SCHEMA_VIOLATION` | DENY | The pinned hash no longer matches the tool's current schema (schema drift). | Review the schema change, then pin the new hash printed in the receipt. |
| `INSUFFICIENT_PRIVILEGE` | DENY | Granted OAuth scopes do not cover the tool's required scopes. | Re-authorize with the required scopes (`--scopes` on `mcp authorize-call`, or the OAuth flow for a live server). |

## `MISSING_REQUIREMENT` In Detail

When a serve policy loads but a call is still denied, the verdict reason now
tells you which requirement failed and what the expression could see:

```text
MISSING_REQUIREMENT: policy requirement not met; blocking requirement(s): acme:file_read:expression; available input.* fields: action (string), artifacts (array), effect (object), timestamp (number), taint (array)
```

Two things to read off this:

- **The blocking requirement is named.** `acme:file_read:expression` is the
  requirement id (`<policy>:<action>:expression` for inline reference-pack
  expressions). Review the expression in the policy source.
- **`input.effect` is an object, not a string.** The intuitive
  `input.effect == 'read'` can never match; the fields a policy expression can
  actually reference are:

| Field | Type | Contents |
| --- | --- | --- |
| `input.action` | string | The matched action id (the MCP tool name, e.g. `file_read`). |
| `input.effect` | object | The effect envelope: `type` (e.g. `EXECUTE_TOOL`), `params` (tool arguments plus `tool_name`), taint, hashes. |
| `input.artifacts` | array | Evidence artifact envelopes attached to the decision. |
| `input.timestamp` | number | Unix timestamp of the evaluation. |
| `input.taint` | array | Normalized taint labels on the effect. |

## Worked Example: A Serve Policy That Reaches ALLOW

Goal: allow the built-in MCP `file_read` tool through `mcp serve --policy`.

`acme.toml`:

```toml
name = "acme"
profile = "dev-local"
reference_pack = "./acme-pack.json"

[server]
bind = "127.0.0.1"
port = 7715

[receipts]
store = "sqlite"
path = "./data/receipts.db"
```

`acme-pack.json`:

```json
{
  "pack_id": "acme-pack-v1",
  "label": "Acme local tools",
  "version": 1,
  "actions": [
    {
      "action": "file_read",
      "enabled": true,
      "expression": "input.action == 'file_read' && input.effect.params.path.endsWith('.md')"
    }
  ]
}
```

The expression checks the action id and constrains the tool argument `path`
(MCP tool arguments arrive under `input.effect.params`). With this pack,
`file_read` on a Markdown file returns `ALLOW`; `file_read` on any other file
is denied with a `MISSING_REQUIREMENT` reason that names the requirement and
lists the fields above — enough to locate and adjust the policy.

Common authoring mistakes this prevents:

- `input.effect == 'read'` — `input.effect` is an object; compare
  `input.effect.type` or fields under `input.effect.params` instead.
- Referencing a tool argument at the top level (`input.path`) — arguments live
  at `input.effect.params.path`.
- An expression that errors instead of returning false — that surfaces as
  `PRG_EVALUATION_ERROR`, not `MISSING_REQUIREMENT`; inspect the policy source
  for the detailed expression.

## Source Truth

- `core/pkg/contracts/verdict.go` (reason-code constants)
- `core/pkg/guardian/guardian.go` (policy evaluation and deny reasons)
- `core/pkg/prg/engine.go` (requirement-set evaluation)
- `core/pkg/mcp/firewall.go` (MCP approval loop verdicts)
- `protocols/specs/rfc/reason-codes-v1.md` (normative registry)
