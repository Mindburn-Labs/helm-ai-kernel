# HELM Framework Integration Guide

> How frameworks embed HELM governance using the Portable Effect Model.

## Framework Index

| Framework                 | Language   | Integration Pattern | Adapter Status |
| ------------------------- | ---------- | ------------------- | -------------- |
| OpenAI Agents SDK         | Python     | Middleware          | Reference      |
| OpenAI Agents SDK         | JS/TS      | Middleware          | Reference      |
| Google ADK                | Python     | Tool wrapper        | Reference      |
| LangGraph                 | Python     | Node wrapper        | Reference      |
| LangChain                 | Python     | Callback handler    | Reference      |
| Mastra                    | TypeScript | Middleware          | Reference      |
| CrewAI                    | Python     | Tool wrapper        | Reference      |
| AI SDK (generic)          | TypeScript | Middleware          | Reference      |
| Microsoft Agent Framework | .NET       | Middleware          | Planned        |
| AutoGen                   | Python     | Tool wrapper        | Planned        |
| DSPy                      | Python     | Module wrapper      | Planned        |
| Semantic Kernel           | C#         | Filter              | Planned        |

---

## Integration Patterns

### Pattern 1: OpenAI Agents SDK (Python)

```python
from openai import agents
from helm_sdk import HelmGovernance

# Create governed agent
governance = HelmGovernance(
    endpoint="http://localhost:4001",
    preset="engineering",
    jurisdiction="eu-gdpr",
)

agent = agents.Agent(
    name="code-assistant",
    model="gpt-4o",
    tools=[...],
    middleware=[governance.middleware()],
)

# Every tool call automatically goes through HELM
result = agent.run("Deploy the new version")
# → HELM intercepts → PDP evaluates → ALLOW/DENY/ESCALATE
```

### Pattern 2: OpenAI Agents SDK (JS/TS)

```typescript
import { Agent } from 'openai/agents';
import { HelmGovernance } from '@mindburn/helm';

const governance = new HelmGovernance({
  endpoint: 'http://localhost:4001',
  preset: 'engineering',
});

const agent = new Agent({
  name: 'code-assistant',
  model: 'gpt-4o',
  tools: [...],
  middleware: [governance.middleware()],
});
```

### Pattern 3: Google ADK

```python
from google.adk import Agent
from helm_sdk import HelmGovernance

governance = HelmGovernance(
    endpoint="http://localhost:4001",
    auth_mode="google_oauth",
)

agent = Agent(
    model="gemini-2.0-flash",
    tools=[governance.wrap(tool) for tool in my_tools],
)
```

### Pattern 4: LangGraph

```python
from langgraph.graph import StateGraph
from helm_sdk import HelmGovernance

governance = HelmGovernance(endpoint="http://localhost:4001")

def governed_tool_node(state):
    tool_call = state["tool_calls"][-1]
    result = governance.submit_effect(
        tool_call["name"],
        tool_call["args"],
    )
    if result.verdict == "DENY":
        return {"denied": True, "reason": result.reason}
    # Execute tool and complete
    output = execute_tool(tool_call)
    governance.complete(result.intent_id, success=True)
    return {"output": output}

graph = StateGraph(...)
graph.add_node("tools", governed_tool_node)
```

### Pattern 5: Mastra (TypeScript)

```typescript
import { Agent } from "mastra";
import { HelmGovernance } from "@mindburn/helm";

const governance = new HelmGovernance({
  endpoint: "http://localhost:4001",
  preset: "engineering",
});

const agent = new Agent({
  name: "mastra-agent",
  model: openai("gpt-4o"),
  tools: governance.wrapAll(myTools),
});
```

### Pattern 6: CrewAI

```python
from crewai import Agent, Task, Crew
from helm_sdk import HelmGovernance

governance = HelmGovernance(endpoint="http://localhost:4001")

agent = Agent(
    role="analyst",
    goal="Analyze data",
    tools=[governance.wrap(tool) for tool in tools],
)
```

### Pattern 7: AI SDK (generic)

```typescript
import { generateText } from "ai";
import { HelmGovernance } from "@mindburn/helm";

const governance = new HelmGovernance({ endpoint: "http://localhost:4001" });

const result = await generateText({
  model: openai("gpt-4o"),
  tools: governance.wrapAll(myTools),
  prompt: "Analyze the sales data",
});
```

---

## Framework Adapter Structure

Each framework adapter follows this structure:

```
sdk/{language}/src/adapters/{framework}/
├── adapter.{ext}       # Core adapter implementation
├── middleware.{ext}     # Middleware/interceptor (if pattern A/B)
├── wrapper.{ext}       # Tool wrapper (if pattern C)
└── README.md           # Framework-specific guide
```

## Testing Framework Integrations

```bash
# Run framework integration tests
helm test frameworks --framework openai-agents
helm test frameworks --framework langgraph
helm test frameworks --all
```
