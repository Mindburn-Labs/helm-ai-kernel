import type { ChatCompletionWithReceipt } from "../client.js";
import type {
  ChatCompletionRequest,
  ChatCompletionRequestToolsInner,
} from "../types.gen.js";

export type AgentFramework =
  | "langgraph"
  | "crewai"
  | "openai-agents"
  | "pydantic-ai"
  | "llamaindex";

export interface AgentFrameworkAdapterMetadata {
  framework: AgentFramework;
  displayName: string;
  status: "compatible";
  source: string;
}

export const agentFrameworkAdapters: AgentFrameworkAdapterMetadata[] = [
  {
    framework: "langgraph",
    displayName: "LangGraph",
    status: "compatible",
    source: "TypeScript SDK",
  },
  {
    framework: "crewai",
    displayName: "CrewAI",
    status: "compatible",
    source: "TypeScript SDK",
  },
  {
    framework: "openai-agents",
    displayName: "OpenAI Agents SDK",
    status: "compatible",
    source: "TypeScript SDK",
  },
  {
    framework: "pydantic-ai",
    displayName: "PydanticAI",
    status: "compatible",
    source: "TypeScript SDK",
  },
  {
    framework: "llamaindex",
    displayName: "LlamaIndex",
    status: "compatible",
    source: "TypeScript SDK",
  },
];

export interface AgentFrameworkAction {
  framework: AgentFramework;
  toolName: string;
  arguments: Record<string, unknown>;
  toolCallId?: string;
  agentId?: string;
  runId?: string;
  taskId?: string;
  actor?: string;
  description?: string;
  metadata?: Record<string, unknown>;
}

export interface FrameworkAdapterOptions {
  model: string;
  policyPrompt?: string;
  temperature?: number;
  maxTokens?: number;
}

export interface FrameworkAdapterDefaults extends FrameworkAdapterOptions {
  metadata?: Record<string, unknown>;
}

export interface HelmGovernanceClient {
  chatCompletionsWithReceipt(
    req: ChatCompletionRequest,
  ): Promise<ChatCompletionWithReceipt>;
}

export interface GovernedFrameworkResult extends ChatCompletionWithReceipt {
  request: ChatCompletionRequest;
  action: AgentFrameworkAction;
}

export interface LangGraphToolCall {
  id?: string;
  name?: string;
  tool?: string;
  args?: unknown;
  arguments?: unknown;
  metadata?: Record<string, unknown>;
}

export interface CrewAITaskCall {
  id?: string;
  task?: string;
  taskId?: string;
  tool?: string | { name?: string; description?: string };
  input?: unknown;
  args?: unknown;
  agent?: string;
  crew?: string;
  metadata?: Record<string, unknown>;
}

export interface OpenAIAgentsToolCall {
  id?: string;
  name?: string;
  arguments?: unknown;
  function?: {
    name?: string;
    arguments?: unknown;
  };
  metadata?: Record<string, unknown>;
}

export interface PydanticAIToolCall {
  id?: string;
  tool_call_id?: string;
  tool_name?: string;
  name?: string;
  args?: unknown;
  arguments?: unknown;
  agent?: string;
  metadata?: Record<string, unknown>;
}

export interface LlamaIndexToolCall {
  id?: string;
  toolName?: string;
  tool_name?: string;
  name?: string;
  kwargs?: unknown;
  input?: unknown;
  agent?: string;
  metadata?: Record<string, unknown>;
}

const DEFAULT_POLICY_PROMPT =
  "Evaluate whether this agent framework tool call may execute through HELM policy. Return a normal chat completion and rely on HELM response headers for the governance receipt.";

export function fromLangGraphToolCall(
  call: LangGraphToolCall,
): AgentFrameworkAction {
  return frameworkAction(
    "langgraph",
    call.name ?? call.tool,
    call.args ?? call.arguments,
    {
      toolCallId: call.id,
      metadata: call.metadata,
    },
  );
}

export function fromCrewAITask(call: CrewAITaskCall): AgentFrameworkAction {
  const tool = typeof call.tool === "string" ? call.tool : call.tool?.name;
  return frameworkAction("crewai", tool, call.input ?? call.args, {
    toolCallId: call.id,
    taskId: call.taskId ?? call.task,
    agentId: call.agent ?? call.crew,
    description:
      typeof call.tool === "string" ? undefined : call.tool?.description,
    metadata: call.metadata,
  });
}

export function fromOpenAIAgentsToolCall(
  call: OpenAIAgentsToolCall,
): AgentFrameworkAction {
  return frameworkAction(
    "openai-agents",
    call.function?.name ?? call.name,
    call.function?.arguments ?? call.arguments,
    {
      toolCallId: call.id,
      metadata: call.metadata,
    },
  );
}

export function fromPydanticAIToolCall(
  call: PydanticAIToolCall,
): AgentFrameworkAction {
  return frameworkAction(
    "pydantic-ai",
    call.tool_name ?? call.name,
    call.args ?? call.arguments,
    {
      toolCallId: call.tool_call_id ?? call.id,
      agentId: call.agent,
      metadata: call.metadata,
    },
  );
}

export function fromLlamaIndexToolCall(
  call: LlamaIndexToolCall,
): AgentFrameworkAction {
  return frameworkAction(
    "llamaindex",
    call.toolName ?? call.tool_name ?? call.name,
    call.kwargs ?? call.input,
    {
      toolCallId: call.id,
      agentId: call.agent,
      metadata: call.metadata,
    },
  );
}

export function buildGovernedToolRequest(
  action: AgentFrameworkAction,
  options: FrameworkAdapterOptions,
): ChatCompletionRequest {
  const tool = toOpenAIFunctionTool(action);
  const payload = {
    framework: action.framework,
    tool_name: action.toolName,
    tool_call_id: action.toolCallId,
    agent_id: action.agentId,
    run_id: action.runId,
    task_id: action.taskId,
    actor: action.actor,
    arguments: action.arguments,
    metadata: action.metadata,
  };

  return {
    model: options.model,
    temperature: options.temperature ?? 0,
    max_tokens: options.maxTokens,
    messages: [
      {
        role: "system",
        content: options.policyPrompt ?? DEFAULT_POLICY_PROMPT,
      },
      {
        role: "user",
        content: `Authorize this ${displayName(action.framework)} tool call before execution.\n${JSON.stringify(payload, null, 2)}`,
      },
    ],
    tools: [tool],
  };
}

export function toOpenAIFunctionTool(
  action: AgentFrameworkAction,
): ChatCompletionRequestToolsInner {
  return {
    type: "function",
    _function: {
      name: normalizeToolName(action.toolName),
      description:
        action.description ??
        `${displayName(action.framework)} tool call: ${action.toolName}`,
      parameters: {
        type: "object",
        additionalProperties: true,
        properties: {},
      },
    },
  };
}

export async function submitGovernedToolIntent(
  client: HelmGovernanceClient,
  action: AgentFrameworkAction,
  options: FrameworkAdapterOptions,
): Promise<GovernedFrameworkResult> {
  const request = buildGovernedToolRequest(action, options);
  const result = await client.chatCompletionsWithReceipt(request);
  return { ...result, request, action };
}

export function createAgentFrameworkAdapter(
  client: HelmGovernanceClient,
  defaults: FrameworkAdapterDefaults,
) {
  return {
    buildRequest(
      action: AgentFrameworkAction,
      options: Partial<FrameworkAdapterOptions> = {},
    ) {
      return buildGovernedToolRequest(
        mergeDefaults(action, defaults),
        mergeOptions(defaults, options),
      );
    },
    submit(
      action: AgentFrameworkAction,
      options: Partial<FrameworkAdapterOptions> = {},
    ) {
      const mergedAction = mergeDefaults(action, defaults);
      return submitGovernedToolIntent(
        client,
        mergedAction,
        mergeOptions(defaults, options),
      );
    },
  };
}

function frameworkAction(
  framework: AgentFramework,
  toolName: string | undefined,
  args: unknown,
  optional: Omit<AgentFrameworkAction, "framework" | "toolName" | "arguments">,
): AgentFrameworkAction {
  if (!toolName?.trim()) {
    throw new TypeError(`${framework} adapter requires a tool name`);
  }
  return {
    framework,
    toolName,
    arguments: normalizeArguments(args),
    ...optional,
  };
}

function normalizeArguments(args: unknown): Record<string, unknown> {
  if (args == null) return {};
  if (typeof args === "string") {
    const trimmed = args.trim();
    if (!trimmed) return {};
    try {
      return normalizeArguments(JSON.parse(trimmed));
    } catch {
      return { value: args };
    }
  }
  if (Array.isArray(args)) {
    return { items: args };
  }
  if (typeof args === "object") {
    return args as Record<string, unknown>;
  }
  return { value: args };
}

function normalizeToolName(name: string): string {
  const normalized = name
    .trim()
    .replace(/[^A-Za-z0-9_-]/g, "_")
    .slice(0, 64);
  if (!normalized) {
    throw new TypeError(
      "tool name normalizes to an empty OpenAI function name",
    );
  }
  return normalized;
}

function mergeDefaults(
  action: AgentFrameworkAction,
  defaults: FrameworkAdapterDefaults,
): AgentFrameworkAction {
  return {
    ...action,
    metadata: {
      ...defaults.metadata,
      ...action.metadata,
    },
  };
}

function mergeOptions(
  defaults: FrameworkAdapterDefaults,
  options: Partial<FrameworkAdapterOptions>,
): FrameworkAdapterOptions {
  return {
    model: options.model ?? defaults.model,
    policyPrompt: options.policyPrompt ?? defaults.policyPrompt,
    temperature: options.temperature ?? defaults.temperature,
    maxTokens: options.maxTokens ?? defaults.maxTokens,
  };
}

function displayName(framework: AgentFramework): string {
  return (
    agentFrameworkAdapters.find((adapter) => adapter.framework === framework)
      ?.displayName ?? framework
  );
}
