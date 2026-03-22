# HELM Insertion Guide

Three copy-paste paths to put HELM in front of any AI agent.

---

## Path 1: Base URL Proxy (2 lines)

Point your OpenAI-compatible SDK at HELM instead of the upstream API. HELM proxies the request, governs it, and forwards to the real backend.

### Python (OpenAI SDK)

```python
from openai import OpenAI

client = OpenAI(
    base_url="http://localhost:8787/v1",  # HELM proxy
    api_key="your-openai-key",            # passed through to upstream
)

response = client.chat.completions.create(
    model="gpt-4o",
    messages=[{"role": "user", "content": "Hello"}],
)
```

### Node.js

```typescript
import OpenAI from "openai";

const client = new OpenAI({
  baseURL: "http://localhost:8787/v1",  // HELM proxy
  apiKey: process.env.OPENAI_API_KEY,
});
```

### Environment variable (any SDK)

```bash
export OPENAI_BASE_URL=http://localhost:8787/v1
# Every OpenAI-compatible SDK now routes through HELM.
```

### Start the proxy

```bash
helm proxy --upstream https://api.openai.com \
           --listen :8787 \
           --schema ./schemas/openai-tools.yaml
```

---

## Path 2: MCP Interceptor (1 command)

Install HELM as the MCP server boundary for Claude Code, Cursor, or any MCP client.

### Install

```bash
# Claude Code
helm mcp install claude-code

# Generic MCP client (stdio transport)
helm mcp serve --transport stdio

# HTTP transport (for remote MCP clients)
helm mcp serve --transport http --listen :8788
```

### What happens

1. HELM becomes the MCP server your client connects to
2. Every `tools/call` request passes through Guardian
3. Undeclared tools → fail-closed deny
4. Every allowed call → signed receipt in the local EvidencePack

### Verify

```bash
# After running some tool calls through MCP:
helm export --evidence ./data/evidence --out evidence.tar
helm verify --bundle evidence.tar
```

---

## Path 3: SDK Wrapper

Wrap your existing agent code with HELM's governance SDK.

### Go

```go
package main

import (
    "context"
    "log"

    helmclient "github.com/Mindburn-Labs/helm-oss/sdk/go/client"
)

func main() {
    client := helmclient.New("http://localhost:8787")

    // Submit a governed tool call
    result, err := client.ExecuteTool(context.Background(), helmclient.ToolRequest{
        Tool:      "web-search",
        Arguments: map[string]any{"query": "HELM governance"},
    })
    if err != nil {
        log.Fatal(err)
    }

    log.Printf("Decision: %s, Receipt: %s", result.Verdict, result.ReceiptID)
}
```

### TypeScript (npm)

```bash
npm install @mindburn/helm-cli
```

```typescript
import { verify } from "@mindburn/helm-cli";

// Verify an evidence pack (offline-safe)
const result = await verify({ bundle: "./evidence.tar" });
console.log(`Verified: ${result.valid}, Receipts: ${result.receiptCount}`);
```

---

## What Each Path Gives You

| Capability | Proxy | MCP | SDK |
|-----------|:-----:|:---:|:---:|
| Zero code changes | ✓ | ✓ | — |
| Fail-closed deny | ✓ | ✓ | ✓ |
| Signed receipts | ✓ | ✓ | ✓ |
| Schema enforcement | ✓ | ✓ | — |
| Offline verify | ✓ | ✓ | ✓ |
| Budget enforcement | ✓ | — | ✓ |
| Works with any LLM | ✓ | ✓ | ✓ |

---

## Quick Start

```bash
# 1. Install
git clone https://github.com/Mindburn-Labs/helm-oss.git
cd helm-oss && make build

# 2. Onboard (creates local env)
./bin/helm onboard --yes

# 3. Pick an insertion path above

# 4. Verify
./bin/helm conform --level L1 --json
```
