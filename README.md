# HELM AI Kernel

**A local firewall for AI-agent actions.**

HELM evaluates actions that reach its configured MCP, proxy, wrapper, or hook
boundary. It decides `ALLOW`, `DENY`, or `ESCALATE`, then writes a signed
receipt you can verify later.

![HELM AI Kernel: one boundary, one decision, one receipt](docs/assets/readme-boundary-preview.png)

## Try It

```bash
brew tap mindburn-labs/tap
brew trust mindburn-labs/tap   # recent Homebrew requires trusting third-party taps
brew install helm-ai-kernel
helm-ai-kernel setup claude-code --yes
# Codex: helm-ai-kernel setup codex --yes
```

Ask your agent to do something risky. HELM blocks or escalates the action before
it runs, then records the decision.

```bash
helm-ai-kernel workstation verify-decision \
  --receipt ~/.helm-ai-kernel/receipts/hooks/<decision>.json
```

No cloud account. No model key. No Docker. No production credentials.

## What It Does

| Agent tries to... | HELM does this | Proof |
| --- | --- | --- |
| Run a destructive shell command | `DENY` | signed receipt |
| Use an unknown MCP tool | `ESCALATE` | quarantine record |
| Read protected secrets | `DENY` | fail-closed receipt |
| Run approved work | `ALLOW` | receipt + evidence |
| Export a review bundle | verify offline | EvidencePack |

HELM only governs effects that reach its boundary. For example, evals showed
network egress blocks firing when an agent actually dispatched a LAN or
non-allowlisted HTTPS request. Prompt-only manipulation, model refusal, or an
agent that never attempts the tool call needs model, app, and sandbox controls
alongside HELM.

## One Example

```text
Agent asks: delete the production database
HELM sees: protected data + irreversible action
HELM says: DENY
You get:  a signed receipt you can verify offline
```

## Where To Go Next

| Need | Link |
| --- | --- |
| 5-minute local proof | [Quickstart](docs/QUICKSTART.md) |
| End-to-end proof loop | [HELM Proof Loop](docs/PROOF_LOOP.md) |
| Local AI-agent risk audit | [Agent Risk Scan](docs/reference/agent-risk-scan.md) |
| CLI commands | [CLI reference](docs/reference/cli.md) |
| Security model | [Execution security model](docs/EXECUTION_SECURITY_MODEL.md) |
| MCP tool quarantine | [MCP integration](docs/INTEGRATIONS/mcp.md) |
| Native client lifecycle and review limits | [Maintainer protocol](docs/INTEGRATIONS/native-client-lifecycle.md) |
| Evidence verification | [Verification](docs/VERIFICATION.md) |
| AI security category map | [AI Security Categories](docs/AI_SECURITY_CATEGORIES.md) |

## What It Is Not

- Not Kubernetes Helm.
- Not the hosted HELM Enterprise product.
- Not a vague AI-safety claim.

It is the open-source execution boundary: policy in, action checked, receipt out.

Codex project setup proves generated local configuration and a Kernel-only
synthetic denial. It does not by itself prove that a live Codex session loaded
the configuration; see the native-client lifecycle protocol before making that
claim.

## Free Forever

The open-source kernel is the complete boundary, not a trial:

- The local execution boundary — verdicts, signed receipts, offline
  verification — is free forever.
- Bring your own keys: BYOK and self-hosting are never paywalled.
- The commercial products are the organizational layer around the boundary
  (hosted retention, team control plane, certification) — never the boundary
  itself.

Contributions are Apache-2.0 with a DCO ([CONTRIBUTING.md](CONTRIBUTING.md));
name and logo use is covered by [TRADEMARK.md](TRADEMARK.md).

## Source Build

```bash
git clone https://github.com/Mindburn-Labs/helm-ai-kernel.git
cd helm-ai-kernel
make build
bin/helm-ai-kernel setup claude-code --yes
```

## Project

| Release target | SDK pointers after publication |
| --- | --- |
| `v0.7.2` | `github.com/Mindburn-Labs/helm-ai-kernel/sdk/go@v0.7.2` |
| `v0.7.2` | `io.github.mindburnlabs:helm-sdk:0.7.2` |

Apache-2.0. See [LICENSE](LICENSE), [SECURITY.md](SECURITY.md), and
[CONTRIBUTING.md](CONTRIBUTING.md).

## Where HELM Fits

Examples are illustrative. HELM is the execution boundary, not the agent,
orchestrator, cloud control plane, or observability tool.

| Category | Examples | What They Do | Where They Stop | HELM AI Kernel |
| --- | --- | --- | --- | --- |
| **Agent permission modes** | Claude Code Auto Mode | Let agents work faster with fewer prompts. | Permission automation is not execution governance. | **HELM makes every governed action produce a verdict and proof.** |
| **Model-vendor agents** | OpenAI Agents, ChatGPT Agent, Claude agents | Provide agent runtimes, tools, guardrails, and HITL flows. | They are tied to their own agent stack and do not create neutral execution evidence. | **HELM is model-neutral: any agent can route actions through the same boundary.** |
| **Coding agents** | GitHub Copilot, Devin, Cursor, Replit Agent | Write, edit, test, and ship code faster. | They optimize developer productivity, not cross-runtime authority. | **HELM governs what the agent is allowed to execute.** |
| **Agent orchestration** | LangGraph, CrewAI, AutoGen, n8n | Decide what agents should do next. | Orchestration chooses attempts; it does not prove authorization. | **HELM decides whether the attempted action may happen.** |
| **MCP gateways and security** | Runlayer, Lasso, Obot, MintMCP, Operant | Route, scan, filter, and secure MCP/tool traffic. | Gateways protect traffic; they do not define the final authority record. | **HELM quarantines tools, issues verdicts, and records signed receipts.** |
| **Enterprise agent control planes** | Microsoft Agent 365, Entra Agent ID, ServiceNow AI Control Tower | Register, manage, and monitor agents inside enterprise platforms. | Identity and control-plane visibility are not portable execution proof. | **HELM proves whether a side effect was authorized under policy.** |
| **Cloud-native agent governance** | AWS Bedrock AgentCore, Google Agent Gateway / Model Armor | Govern agents inside cloud-provider ecosystems. | Strong inside one cloud estate; weaker as neutral cross-platform evidence. | **HELM provides a portable boundary and verifier.** |
| **Observability and evals** | LangSmith, Braintrust, Arize, Helicone, Weave | Show traces, metrics, evals, and debugging timelines. | Logs explain what happened after the fact. | **HELM decides before execution and leaves verifiable proof after.** |
| **AI security platforms** | Zenity, Noma, WitnessAI, HiddenLayer, Lakera | Detect, scan, monitor, and protect AI systems broadly. | Broad security coverage can blur runtime authority. | **HELM is narrow by design: fail-closed execution control.** |
| **Receipt and proof projects** | PipeLab / AAR, ACTA, Signet, ZeroClaw | Create receipts, signed records, or action proof. | Receipts alone do not equal governed execution. | **HELM binds receipt to policy verdict, effect, reason code, and EvidencePack.** |

**Bottom line:** most tools help agents act. HELM decides whether the action is
allowed, blocks it when it is not, and leaves proof an outside reviewer can
verify.
