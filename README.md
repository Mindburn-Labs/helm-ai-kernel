# HELM OSS — The Agent Hardening Kit

[![CI](https://github.com/Mindburn-Labs/helm-oss/actions/workflows/ci.yml/badge.svg)](https://github.com/Mindburn-Labs/helm-oss/actions/workflows/ci.yml)
[![Conformance](https://img.shields.io/badge/conformance-L1%20%2B%20L2%20%2B%20L3-brightgreen)](docs/CONFORMANCE.md)
[![Provenance](https://img.shields.io/badge/provenance-SLSA-blue)](https://github.com/Mindburn-Labs/helm-oss/releases)
[![Hardened](https://img.shields.io/badge/HELM-hardened-blueviolet)](https://mindburn.org/lab/status)

**Bring your agent runtime, get fail-closed execution and receipts.**

HELM OSS is the open Agent Hardening Kit for governed AI execution. Drop it in front of **DeerFlow**, **OpenClaw**, or any OpenAI-compatible agent runtime — every tool call gets fail-closed policy enforcement, cryptographic receipts (Ed25519), and deterministic **EvidencePacks** you can verify offline.

**What you get in 10 minutes:**

- 🔒 **Fail-closed governance** — every action is ALLOW/DENY with a signed receipt
- 📦 **Deterministic EvidencePacks** — offline-verifiable, air-gapped safe, bit-identical
- 📊 **Interactive Proof Report** — shareable HTML with causal chain visualization
- 🔌 **Works with your stack** — OpenAI SDK, LangChain, Claude, Mastra, any MCP client
- 🧱 **Kernel-grade trust** — Ed25519 signed, Lamport-ordered, replay-from-genesis

<details>
<summary>📊 <strong>What the Proof Report looks like</strong></summary>

> The canonical `helm demo organization` command generates an interactive HTML proof report with causal chain visualization, receipt details, authority-scope metadata, verification status, and one-click sharing. The legacy `helm demo company` alias remains supported for compatibility.
>
> <!-- TODO: Replace with actual screenshot: ![HELM Proof Report](docs/assets/proof-report-screenshot.png) -->

</details>

---

## 🚀 Agent Hardening Quickstarts

| Your Runtime | Hardening Quickstart | Time |
|-------------|---------------------|------|
| **DeerFlow** | [`examples/deerflow/`](examples/deerflow/) — governed research pipeline | 5 min |
| **OpenClaw** | [`examples/openclaw/`](examples/openclaw/) — hardened agent actions | 5 min |
| **Any OpenAI-compatible** | Just change `base_url` → [see below](#integrations) | 2 min |

> **See it live:** [Lab Status](https://mindburn.org/lab/status) · [Compatibility Matrix](https://mindburn.org/lab/compatibility) · [Proof Demos](https://mindburn.org/demos)

### Add HELM Checks to Your CI

```yaml
# .github/workflows/ci.yml — add this job
jobs:
  helm-check:
    uses: Mindburn-Labs/helm-oss/.github/workflows/boundary-checks.yml@main
    with:
      level: L2
```

---

## Install

```bash
# Script install (macOS / Linux)
curl -fsSL https://raw.githubusercontent.com/Mindburn-Labs/helm-oss/main/install.sh | bash

# Go
go install github.com/Mindburn-Labs/helm-oss/core/cmd/helm@latest

# Docker
docker run --rm ghcr.io/mindburn-labs/helm-oss:latest --help

# Homebrew formula is not published yet
# Use the install script, Go install, or Docker for now
```

## MCP One-Click Install

```bash
# Claude Desktop — one-click .mcpb
helm mcp pack --client claude-desktop --out helm.mcpb

# Claude Code
helm mcp install --client claude-code

# Windsurf / Codex / VS Code / Cursor
helm mcp print-config --client windsurf
```

## SDK Install

SDKs ship in-repo and can be used directly:

```bash
# TypeScript SDK (from repo)
cd sdk/ts && npm install && npm run build

# Python SDK (from repo)
cd sdk/python && pip install -e .

# Go SDK
go get github.com/Mindburn-Labs/helm-oss/sdk/go
```

npm packages are live: `npm install @mindburn/helm` (SDK), `npx @mindburn/helm-cli` (verifier).

---

## 📊 Performance

HELM is built for high-stakes, low-latency environments. To measure the overhead on your machine:

```bash
./scripts/bench/latency.sh
```

---

## 10-Minute Wow Path

```bash
# 1. Setup (SQLite + Ed25519 + config — instant)
helm onboard --yes

# 2. Run the canonical organization demo (legacy alias: `helm demo company`)
helm demo organization --template starter --provider mock

# 2b. Run the research-lab reference scenario in policy simulation mode
helm demo research-lab --template starter --provider mock --dry-run

# 3. Export deterministic EvidencePack + verify offline (air-gapped safe)
helm export --evidence ./data/evidence --out evidence.tar
helm verify --bundle evidence.tar

# 4. Explore skill lifecycle + maintenance loop
helm pack list && helm incident list && helm brief daily
```

→ Full commands: [docs/VERIFICATION.md](docs/VERIFICATION.md) · [docs/QUICKSTART.md](docs/QUICKSTART.md) · [docs/POLICY_SIMULATION.md](docs/POLICY_SIMULATION.md)

---

## 🔍 Verify Any Release

```bash
npx @mindburn/helm-cli
```

One command, progressive disclosure, cryptographic proof. Supports interactive and CI modes:

```bash
# CI mode — JSON on stdout, exit code 0/1
npx @mindburn/helm-cli --ci --bundle ./evidence 2>/dev/null | jq .verdict
```

→ Full guide: [docs/verify.md](docs/verify.md)

---

## Why Devs Should Care

| Pain (postmortem you're preventing) | HELM behavior                                                       | Receipt reason code      | Proof                                                                                                  |
| ----------------------------------- | ------------------------------------------------------------------- | ------------------------ | ------------------------------------------------------------------------------------------------------ |
| Tool-call overspend blows budget    | ACID budget locks, fail-closed on ceiling breach                    | `DENY_BUDGET_EXCEEDED`   | [UC-005](docs/use-cases/UC-005_wasi_gas_exhaustion.sh)                                                 |
| Schema drift breaks prod silently   | Fail-closed on input AND output schema mismatch                     | `DENY_SCHEMA_MISMATCH`   | [UC-002](docs/use-cases/UC-002_schema_mismatch.sh), [UC-009](docs/use-cases/UC-009_connector_drift.sh) |
| Untrusted WASM runs wild            | Sandbox: gas + time + memory budgets, deterministic traps           | `DENY_GAS_EXHAUSTION`    | [UC-004](docs/use-cases/UC-004_wasi_transform.sh)                                                      |
| "Who approved that?" disputes       | Timelock + challenge/response ceremony, Ed25519 signed              | `DENY_APPROVAL_REQUIRED` | [UC-003](docs/use-cases/UC-003_approval_ceremony.sh)                                                   |
| No audit trail for regulators       | Deterministic EvidencePack, offline verifiable, replay from genesis | —                        | [UC-008](docs/use-cases/UC-008_replay_verify.sh)                                                       |
| Can't prove compliance to auditors  | Conformance L1 + L2 gates, 12 runnable use cases                    | —                        | [UC-012](docs/use-cases/UC-012_openai_proxy.sh)                                                        |

---

## OSS Boundary

HELM OSS includes the full execution boundary:

- fail-closed policy enforcement
- ProofGraph and EvidencePacks
- replay and verification
- MCP, framework, and proxy integrations

HELM OSS does **not** include the full commercial control plane:

- managed federation
- pack distribution and entitlement management
- compliance intelligence workflows
- Mission Control / Studio operations surfaces
- full OrgDNA deployment lifecycle

That boundary exists to keep the kernel trustworthy, not to cripple OSS.

→ Details: [docs/OSS_SCOPE.md](docs/OSS_SCOPE.md)

---

## Integrations

### Python — OpenAI SDK

The only change:

```diff
- client = openai.OpenAI()
+ client = openai.OpenAI(base_url="http://localhost:8080/v1")
```

Full snippet:

```python
import openai

client = openai.OpenAI(base_url="http://localhost:8080/v1")

response = client.chat.completions.create(
    model="gpt-4",
    messages=[{"role": "user", "content": "List files in /tmp"}]
)
print(response.choices[0].message.content)
# Response headers include:
#   X-Helm-Decision-ID: dec_a1b2c3...
#   X-Helm-Verdict: ALLOW
#   X-Helm-Policy-Version: 1.0.0
```

→ Full example: [examples/python_openai_baseurl/main.py](examples/python_openai_baseurl/main.py)

### TypeScript — fetch

The only change:

```diff
- const BASE = "https://api.openai.com/v1";
+ const BASE = "http://localhost:8080/v1";
```

Full snippet:

```typescript
const response = await fetch("http://localhost:8080/v1/chat/completions", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({
    model: "gpt-4",
    messages: [{ role: "user", content: "What time is it?" }],
  }),
});
const data = await response.json();
console.log(data.choices[0].message.content);
// X-Helm-Decision-ID: dec_d4e5f6...
// X-Helm-Verdict: ALLOW
```

→ Full example: [examples/js_openai_baseurl/main.js](examples/js_openai_baseurl/main.js)

### MCP Gateway

````bash
# List governed capabilities
curl -s http://localhost:8080/mcp/v1/capabilities | jq '.tools[].name'

# Execute a governed tool call
curl -s -X POST http://localhost:8080/mcp/v1/execute \
  -H 'Content-Type: application/json' \
  -d '{"method":"file_read","params":{"path":"/tmp/test.txt"}}' | jq .
# → { "result": ..., "receipt_id": "rec_...", "reason_code": "ALLOW" }
→ Full example: [examples/mcp_client/main.sh](examples/mcp_client/main.sh)

### Organization-scoped metadata

When you need organizational context, thread it through receipt metadata:

```json
{
  "organization_id": "northstar-research",
  "scope_id": "lab.benchmarks.pipeline",
  "principal_id": "ml_engineer"
}
```

The kernel already supports metadata on intents and receipts. HELM OSS keeps this optional and backward-compatible so you can grow from local agent governance into organizational execution without changing the boundary contract.

---

## SDKs

Typed clients for 5 languages. All generated from [api/openapi/helm.openapi.yaml](api/openapi/helm.openapi.yaml).

| Language | Status | Path |
| :--- | :--- | :--- |
| **TypeScript** | In-repo | `sdk/ts/` |
| **Python** | In-repo | `sdk/python/` |
| **Go** | In-repo | `sdk/go/` |
| **Rust** | Preview | `sdk/rust/` |
| **Java** | Preview | `sdk/java/` |

Every SDK exposes the same primitives: `chatCompletions`, `approveIntent`, `listSessions`, `getReceipts`, `exportEvidence`, `verifyEvidence`, `conformanceRun`.

Every error includes a typed `reason_code` (e.g. `DENY_TOOL_NOT_FOUND`).

**Go — 10-line denial-handling example:**

```go
c := helm.New("http://localhost:8080")
res, err := c.ChatCompletions(helm.ChatCompletionRequest{
    Model:    "gpt-4",
    Messages: []helm.ChatMessage{{Role: "user", Content: "List /tmp"}},
})
if apiErr, ok := err.(*helm.HelmApiError); ok {
    fmt.Println("Denied:", apiErr.ReasonCode) // DENY_TOOL_NOT_FOUND
}
````

**Rust:**

```rust
let c = HelmClient::new("http://localhost:8080");
match c.chat_completions(&req) {
    Ok(res) => println!("{:?}", res.choices[0].message.content),
    Err(e) => println!("Denied: {:?}", e.reason_code),
}
```

**Java:**

```java
var helm = new HelmClient("http://localhost:8080");
try { helm.chatCompletions(req); }
catch (HelmApiException e) { System.out.println(e.reasonCode); }
```

Full examples: [examples/](examples/) · SDK docs: [docs/sdks/00_INDEX.md](docs/sdks/00_INDEX.md)

---

## OpenAPI Contract

[api/openapi/helm.openapi.yaml](api/openapi/helm.openapi.yaml) — OpenAPI 3.1 spec.

Single source of truth. SDKs are generated from it. CI prevents drift.

→ [Contract versioning](docs/sdks/contract_versioning.md)

---

## How It Works

```
Your App (OpenAI SDK)
       │
       │ base_url = localhost:8080
       ▼
   HELM Proxy ──→ Guardian (policy: allow/deny)
       │                │
       │           PEP Boundary (JCS canonicalize → SHA-256)
       │                │
       ▼                ▼
   Executor ──→ Tool ──→ Receipt (Ed25519 signed)
       │                        │
       ▼                        ▼
  ProofGraph DAG          EvidencePack (.tar)
  (append-only)           (offline verifiable)
       │
       ▼
  Replay Verify
  (air-gapped safe)
```

---

## What Ships

| Shipped in OSS v1.0                           |
| --------------------------------------------- |
| ✅ OpenAI-compatible governed proxy           |
| ✅ Schema PEP (input + output)                |
| ✅ ProofGraph DAG (Lamport + Ed25519)         |
| ✅ WASI sandbox (gas/time/memory)             |
| ✅ Approval ceremonies (timelock + challenge) |
| ✅ Trust registry (event-sourced)             |
| ✅ EvidencePack export + offline replay       |
| ✅ Proof Condensation (Merkle checkpoints)    |
| ✅ CPI (Canonical Policy Index)               |
| ✅ HSM signing (Ed25519)                      |
| ✅ Policy Bundles (load, verify, compose)     |
| ✅ Conformance L1 + L2 + L3                   |
| ✅ 11 CLI commands                            |

Full scope details in [docs/OSS_SCOPE.md](docs/OSS_SCOPE.md)

---

## Verification

```bash
make test       # 115 packages, 0 failures
make crucible   # 12 use cases + conformance L1/L2
make lint       # go vet, clean
```

---

## Deploy

```bash
# Local demo
docker compose up -d

# Production (DigitalOcean / any Docker host)
docker compose -f docker-compose.demo.yml up -d
```

→ [deploy/README.md](deploy/README.md) — deploy your own in 3 minutes

---

## Project Structure

```
helm/
├── api/openapi/         # OpenAPI 3.1 spec (single source of truth)
├── core/               # Go kernel (8-package TCB + executor + ProofGraph)
│   └── cmd/helm/       # CLI: proxy, export, verify, replay, conform, ...
├── packages/
│   └── mindburn-helm-cli/  # @mindburn/helm-cli (npm CLI verifier)
├── sdk/                # Multi-language SDKs (TS, Python, Go, Rust, Java)
├── examples/           # Runnable examples per language + MCP
├── scripts/            # Release, CI, SDK generation
├── deploy/             # Caddy config, demo compose, deploy guide
├── docs/               # Threat model, quickstart, verify, conformance
└── Makefile            # build, test, crucible, demo, release-binaries
```

---

## Scope and Guarantees

OSS ships L1 + L2 + L3 conformance. See [docs/OSS_SCOPE.md](docs/OSS_SCOPE.md) for the shipped-vs-spec boundary.

---

## Security Posture

- **TCB isolation gate** — 8-package kernel boundary, CI-enforced forbidden imports ([TCB Policy](docs/TCB_POLICY.md))
- **Bounded compute gate** — WASI sandbox with gas/time/memory caps, deterministic traps on breach ([UC-005](docs/use-cases/UC-005_wasi_gas_exhaustion.sh))
- **Schema drift fail-closed** — JCS canonicalization + SHA-256 on every tool call, both input and output ([UC-002](docs/use-cases/UC-002_schema_mismatch.sh))

See also: [SECURITY.md](SECURITY.md) (vulnerability reporting) · [Threat Model](docs/THREAT_MODEL.md) (9 adversary classes)

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Good first issues: conformance improvements, SDK enhancements, docs truth fixes.

## Roadmap

See the [GitHub Issues](https://github.com/Mindburn-Labs/helm-oss/issues) for planned items.

## License

[Apache License 2.0](LICENSE)

---

## Live Proof Surface

See HELM in action — no install required:

- 📊 **[Lab Status](https://mindburn.org/lab/status)** — live governed runs and receipts
- ✅ **[Compatibility Matrix](https://mindburn.org/lab/compatibility)** — weekly provider conformance results
- 🔬 **[Proof Demos](https://mindburn.org/demos)** — interactive gate, verify, policy, and conformance demos
- 🌐 **[Ecosystem Intel](https://mindburn.org/ecosystem)** — weekly briefs on DeerFlow, OpenClaw, Crucix, MiroFish

---

## 🎯 Try It — No Install

Use a HELM-governed AI assistant right now — free, no signup:

**→ [try.mindburn.run](https://try.mindburn.run)** — OpenClaw + HELM + free models. Every action gets a receipt.

See the full product ladder: [PRODUCT_LADDER.md](PRODUCT_LADDER.md)

---

Built by **[Mindburn Labs](https://mindburn.org)**.
