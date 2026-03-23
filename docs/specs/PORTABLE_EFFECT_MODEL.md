# Portable Effect Model

> How to embed HELM governance primitives in any framework or runtime.

## 1. The Core Primitive

Every HELM integration reduces to one function:

```
effect(type, params, principal) → (verdict, receipt, intent?)
```

This is the **only function a framework needs to call** to be HELM-governed.

## 2. Language Bindings

### Go (In-Process)

```go
import "helm.mindburn.run/core/pkg/guardian"

decision, err := g.SignDecision(effect, requirements)
// decision.Verdict is ALLOW/DENY/ESCALATE
// decision.Receipt is the governance receipt
```

### Python

```python
from helm_sdk import HelmClient

client = HelmClient("http://localhost:4001")
result = client.submit_effect("file_write", {"path": "/data/output.csv"})
if result.verdict == "ALLOW":
    # proceed with authorized intent
    do_file_write("/data/output.csv")
    client.complete(result.intent_id, success=True)
```

### TypeScript

```typescript
import { HelmClient } from "@mindburn/helm";

const helm = new HelmClient("http://localhost:4001");
const result = await helm.submitEffect("api_call", {
  url: "https://api.example.com",
});

if (result.verdict === "ALLOW") {
  const response = await fetch("https://api.example.com");
  await helm.complete(result.intentId, { success: true });
}
```

### Java

```java
HelmClient helm = HelmClient.create("http://localhost:4001");
EffectResult result = helm.submitEffect("database_query", Map.of("table", "users"));

if (result.getVerdict() == Verdict.ALLOW) {
    ResultSet rs = stmt.executeQuery("SELECT * FROM users");
    helm.complete(result.getIntentId(), true);
}
```

## 3. Framework Integration Patterns

### Pattern A: Tool Wrapper (Simplest)

Wrap each tool call with `effect()`:

```python
# Before
result = tool.execute(params)

# After
verdict = helm.submit_effect(tool.name, params)
if verdict.is_allow():
    result = tool.execute(params)
    helm.complete(verdict.intent_id, success=True)
else:
    raise GovernanceDenied(verdict.reason_code)
```

### Pattern B: Middleware/Interceptor

Register HELM as middleware in the framework's tool pipeline:

```typescript
// OpenAI Agents SDK
agent.use(
  helmMiddleware({
    endpoint: "http://localhost:4001",
    principal: "agent:my-agent",
  }),
);
```

### Pattern C: Substrate Embedding (Deepest)

Embed the EffectBoundary as a first-class runtime primitive:

```go
// Framework runtime
type Runtime struct {
    boundary *guardian.Guardian
}

func (r *Runtime) Execute(effect Effect) (Result, error) {
    decision, err := r.boundary.SignDecision(effect, r.requirements)
    if decision.Verdict != contracts.VerdictAllow {
        return nil, GovernanceDenied{Verdict: decision.Verdict}
    }
    result := r.doExecute(effect)
    r.boundary.RecordCompletion(decision, result)
    return result, nil
}
```

## 4. Transport Options

| Mode            | Latency | Use Case                            |
| --------------- | ------- | ----------------------------------- |
| In-process (Go) | <1ms    | Go applications, kernel extensions  |
| gRPC            | ~5ms    | Microservice architectures          |
| HTTP/JSON       | ~10ms   | Cross-language, simple integrations |
| Unix socket     | ~2ms    | Co-located processes                |

## 5. Governance Receipt

Every `effect()` call produces a governance receipt. This receipt:

- Is cryptographically signed
- Contains the verdict and reason code
- Links to the ProofGraph node
- Is independently verifiable offline

The receipt is the **proof artifact** — it proves that governance happened.

## 6. Non-Goals

The portable effect model does NOT:

- Define how frameworks discover tools (that's framework-specific)
- Mandate a specific PDP implementation (PDP is pluggable)
- Require the Go kernel (any language can implement the wire protocol)
- Lock frameworks into a specific version (IDL is versioned and stable)
