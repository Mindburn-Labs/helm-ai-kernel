# How to Prove It Works

Every claim is backed by a command you can run right now. Zero hidden steps.

---

## Install

```bash
# Script install (macOS / Linux)
curl -fsSL https://raw.githubusercontent.com/Mindburn-Labs/helm-oss/main/install.sh | bash

# Go install
go install github.com/Mindburn-Labs/helm-oss/core/cmd/helm@latest

# Docker
docker run --rm ghcr.io/mindburn-labs/helm-oss:latest --help

# Homebrew formula is not published yet
# Use the install script, Go install, or Docker for now
```

---

## Onboard + Demo (10 minutes)

```bash
# 1. One-command setup (SQLite + Ed25519 + config)
helm onboard --yes

# 2. Run starter organization demo (legacy alias: `helm demo company`)
helm demo organization --template starter --provider mock

# 2b. Optional: run the research-lab scenario in dry-run mode
helm demo research-lab --template starter --provider mock --dry-run

# 3. Export deterministic EvidencePack
helm export --evidence ./data/evidence --out evidence.tar

# 4. Offline verify (air-gapped safe)
helm verify --bundle evidence.tar
```

---

## Skill Lifecycle (governed self-extension)

```bash
# Propose a new skill
helm pack propose --name search --purpose "web search" --tools "http_get" --risk low

# Build pack from candidate
helm pack build <candidate-hash>

# Run conformance tests
helm pack test <pack-hash>

# Promote (requires explicit approval)
helm pack promote <pack-hash> --approve

# Install
helm pack install <pack-hash>

# View status
helm pack list
```

---

## Maintenance Loop (governed self-fixing)

```bash
# Create an incident
helm incident create --title "Schema drift" --severity medium --category schema

# List incidents
helm incident list

# Acknowledge
helm incident ack INC-<id>

# Run maintenance (deterministic replay → patch → conformance → apply)
helm run maintenance --once

# Daily brief
helm brief daily
```

---

## Proxy (HTTP)

```bash
# Start proxy
helm proxy --upstream https://api.openai.com/v1

# Python client
python -c "
import openai
c = openai.OpenAI(base_url='http://localhost:9090/v1')
print(c.chat.completions.create(model='gpt-4', messages=[{'role':'user','content':'hi'}]))
"
```

Responses WebSocket mode is not shipped in the OSS proxy runtime. Use the HTTP surface at `/v1/chat/completions`.

---

## MCP Distribution

```bash
# Start MCP server (stdio)
helm mcp serve

# Claude Desktop .mcpb bundle
helm mcp pack --client claude-desktop --out helm.mcpb

# Claude Code plugin install
helm mcp install --client claude-code

# Print config for other clients
helm mcp print-config --client windsurf
helm mcp print-config --client codex
helm mcp print-config --client vscode
helm mcp print-config --client cursor
```

---

## Sandbox Execution

```bash
# Mock (always works, zero deps)
helm sandbox exec --provider mock -- echo "hello"

# Real providers (requires API keys)
helm sandbox exec --provider opensandbox -- echo "hello"
helm sandbox exec --provider e2b -- echo "hello"
helm sandbox exec --provider daytona -- echo "hello"
```

---

## Conformance

```bash
# Run conformance suite
helm conform --level L2 --json
```

---

## SDK Tests

```bash
# Python adapters
cd sdk/python/openai_agents && python -m pytest test_helm_openai_agents.py -v
cd sdk/python/microsoft_agents && python -m pytest test_helm_ms_agent.py -v

# TypeScript adapters
cd sdk/ts/openai-agents && npm test -- --run
cd sdk/ts/mastra && npm test -- --run
```

---

## Weekly Compatibility Matrix

Published as CI artifacts every Monday:

- `compatibility-matrix.json` — machine-readable
- `compatibility-matrix.md` — human-readable
- Includes provider versions, pass/fail per tier, receipt samples for failures

Latest: [GitHub Actions → compatibility-matrix.yml](https://github.com/Mindburn-Labs/helm-oss/actions/workflows/compatibility_matrix.yml)
