# Protect Local Coding Agents

HELM can sit around Codex, Claude Code, and similar local agent workflows. The
goal is narrow: selected effects cross a HELM boundary before dispatch, and
each decision leaves a local receipt.

HELM is not a competing coding agent. It evaluates the actions your agent wants
to take.

## Install A Local Hook

Inspect the writes first:

```bash
helm-ai-kernel setup codex --dry-run --json
helm-ai-kernel setup claude-code --dry-run --json
```

Install the local integration:

```bash
helm-ai-kernel setup codex --yes
helm-ai-kernel setup claude-code --yes
```

Setup writes draft policy and quarantine artifacts. It does not approve tools
or grant broad operating permissions.

## Prove A Denial

Ask the local agent to attempt an action the starter policy denies, such as a
risky shell cleanup. HELM should block before dispatch and write a receipt.

Verify the receipt:

```bash
helm-ai-kernel workstation verify-decision \
  --receipt ~/.helm-ai-kernel/receipts/hooks/wpd_<decision>.json
```

Expected fields:

```text
verdict: DENY
reason: OPERATE_PERMISSIONS_EMPTY
effect: WORKSTATION_SHELL_COMMAND
signature: true
```

## Prove An Escalation

For MCP-backed local tools, unknown servers and missing scoped approvals should
pause as `ESCALATE`:

```bash
helm-ai-kernel mcp authorize-call \
  --server-id shell-mcp-server \
  --tool-name pwd
```

Expected output:

```text
HELM ESCALATE
decision: dec_...
reason: unknown MCP server requires approval
receipt: ~/.helm-ai-kernel/receipts/...
approve:
  helm-ai-kernel mcp approve --server-id shell-mcp-server \
    --tools "pwd" \
    --ttl 15m \
    --reason "read-only repo inspection for local dev"
```

Approve the exact scope only when it is safe:

```bash
helm-ai-kernel mcp approve \
  --server-id shell-mcp-server \
  --tools "pwd,ls,cat" \
  --ttl 15m \
  --reason "read-only repo inspection for local dev"
```

Then rerun the original action. Approval never resumes it automatically.

## Revoke Access

```bash
helm-ai-kernel mcp revoke \
  --server-id shell-mcp-server \
  --reason "repo inspection finished"
```

The next evaluation must fail closed when the approval is revoked, expired, or
outside its server, tool, or effect scope.

## Inspect Receipts

```bash
helm-ai-kernel mcp pending --json
helm-ai-kernel mcp receipts --json
helm-ai-kernel boundary records --json
```

The report is receipt-scoped. It does not claim full desktop, browser, OS, or
hosted-agent control.
