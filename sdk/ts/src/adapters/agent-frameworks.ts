import type { ChatCompletionWithReceipt } from "../client.js";
import type {
  ChatCompletionRequest,
  ChatCompletionRequestToolsInner,
} from "../types.gen.js";

export type AgentFramework =
  | "langchain"
  | "langgraph"
  | "autogen"
  | "crewai"
  | "codex"
  | "claude-code"
  | "hermes"
  | "openai-agents"
  | "semantic-kernel"
  | "pydantic-ai"
  | "llamaindex"
  | "litellm"
  | "n8n"
  | "zapier-webhook"
  | "raw-mcp";

export interface AgentFrameworkAdapterMetadata {
  framework: AgentFramework;
  displayName: string;
  status: "compatible";
  source: string;
}

export const agentFrameworkAdapters: AgentFrameworkAdapterMetadata[] = [
  {
    framework: "langchain",
    displayName: "LangChain",
    status: "compatible",
    source: "TypeScript SDK",
  },
  {
    framework: "langgraph",
    displayName: "LangGraph",
    status: "compatible",
    source: "TypeScript SDK",
  },
  {
    framework: "autogen",
    displayName: "AutoGen",
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
    framework: "codex",
    displayName: "OpenAI Codex",
    status: "compatible",
    source: "TypeScript SDK",
  },
  {
    framework: "claude-code",
    displayName: "Claude Code",
    status: "compatible",
    source: "TypeScript SDK",
  },
  {
    framework: "hermes",
    displayName: "Hermes",
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
    framework: "semantic-kernel",
    displayName: "Semantic Kernel",
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
  {
    framework: "litellm",
    displayName: "LiteLLM",
    status: "compatible",
    source: "TypeScript SDK",
  },
  {
    framework: "n8n",
    displayName: "n8n",
    status: "compatible",
    source: "TypeScript SDK",
  },
  {
    framework: "zapier-webhook",
    displayName: "Zapier-style webhook",
    status: "compatible",
    source: "TypeScript SDK",
  },
  {
    framework: "raw-mcp",
    displayName: "Raw MCP client",
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

export interface LangChainToolCall extends LangGraphToolCall {
  runId?: string;
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

export interface CodexToolCall {
  id?: string;
  tool_name?: string;
  name?: string;
  recipient_name?: string;
  arguments?: unknown;
  parameters?: unknown;
  input?: unknown;
  payload?: unknown;
  session_id?: string;
  thread_id?: string;
  worktree?: string;
  metadata?: Record<string, unknown>;
}

export interface ClaudeToolCall {
  id?: string;
  tool_use_id?: string;
  tool_name?: string;
  name?: string;
  tool_input?: unknown;
  input?: unknown;
  arguments?: unknown;
  session_id?: string;
  transcript_path?: string;
  metadata?: Record<string, unknown>;
}

export interface HermesToolCall {
  id?: string;
  tool_name?: string;
  name?: string;
  arguments?: unknown;
  args?: unknown;
  profile?: string;
  task_id?: string;
  run_id?: string;
  metadata?: Record<string, unknown>;
}

export interface AutoGenToolCall {
  id?: string;
  name?: string;
  tool?: string;
  arguments?: unknown;
  args?: unknown;
  agent?: string;
  conversationId?: string;
  metadata?: Record<string, unknown>;
}

export interface SemanticKernelFunctionCall {
  id?: string;
  functionName?: string;
  pluginName?: string;
  arguments?: unknown;
  args?: unknown;
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

export interface LiteLLMToolCall extends OpenAIAgentsToolCall {
  model?: string;
}

export interface N8NNodeExecution {
  id?: string;
  node?: string;
  name?: string;
  parameters?: unknown;
  input?: unknown;
  workflowId?: string;
  metadata?: Record<string, unknown>;
}

export interface ZapierWebhookCall {
  id?: string;
  zapId?: string;
  action?: string;
  tool?: string;
  payload?: unknown;
  metadata?: Record<string, unknown>;
}

export interface RawMCPToolCall {
  id?: string;
  serverId?: string;
  name?: string;
  toolName?: string;
  arguments?: unknown;
  args?: unknown;
  scopes?: string[];
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

export function fromLangChainToolCall(
  call: LangChainToolCall,
): AgentFrameworkAction {
  return frameworkAction(
    "langchain",
    call.name ?? call.tool,
    call.args ?? call.arguments,
    {
      toolCallId: call.id,
      runId: call.runId,
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

export function fromCodexToolCall(call: CodexToolCall): AgentFrameworkAction {
  const toolName = requireCanonicalToolName(
    "codex",
    "recipient_name",
    call.recipient_name,
  );
  rejectConflictingAliasToolName("codex", "recipient_name", toolName, {
    tool_name: call.tool_name,
    name: call.name,
  });
  const args = requireCanonicalArguments("codex", "parameters", call.parameters, {
    arguments: call.arguments,
    input: call.input,
    payload: call.payload,
  });
  return frameworkAction(
    "codex",
    toolName,
    args,
    {
      toolCallId: call.id,
      runId: call.thread_id ?? call.session_id,
      metadata: {
        ...call.metadata,
        session_id: call.session_id,
        worktree: call.worktree,
      },
    },
  );
}

export function fromClaudeToolCall(call: ClaudeToolCall): AgentFrameworkAction {
  const toolName = requireCanonicalToolName(
    "claude-code",
    "tool_name",
    call.tool_name,
  );
  rejectConflictingAliasToolName("claude-code", "tool_name", toolName, {
    name: call.name,
  });
  const args = requireCanonicalArguments(
    "claude-code",
    "tool_input",
    call.tool_input,
    {
      input: call.input,
      arguments: call.arguments,
    },
  );
  return frameworkAction(
    "claude-code",
    toolName,
    args,
    {
      toolCallId: call.tool_use_id ?? call.id,
      runId: call.session_id,
      metadata: {
        ...call.metadata,
        transcript_path: call.transcript_path,
      },
    },
  );
}

export function fromHermesToolCall(call: HermesToolCall): AgentFrameworkAction {
  const toolName = requireCanonicalToolName(
    "hermes",
    "tool_name",
    call.tool_name,
  );
  rejectConflictingAliasToolName("hermes", "tool_name", toolName, {
    name: call.name,
  });
  const args = requireCanonicalArguments(
    "hermes",
    "arguments",
    call.arguments,
    {
      args: call.args,
    },
  );
  return frameworkAction(
    "hermes",
    toolName,
    args,
    {
      toolCallId: call.id,
      agentId: call.profile,
      taskId: call.task_id,
      runId: call.run_id,
      metadata: call.metadata,
    },
  );
}

export function fromAutoGenToolCall(call: AutoGenToolCall): AgentFrameworkAction {
  return frameworkAction(
    "autogen",
    call.name ?? call.tool,
    call.arguments ?? call.args,
    {
      toolCallId: call.id,
      agentId: call.agent,
      runId: call.conversationId,
      metadata: call.metadata,
    },
  );
}

export function fromSemanticKernelFunctionCall(
  call: SemanticKernelFunctionCall,
): AgentFrameworkAction {
  const toolName =
    call.pluginName && call.functionName
      ? `${call.pluginName}.${call.functionName}`
      : call.functionName;
  return frameworkAction("semantic-kernel", toolName, call.arguments ?? call.args, {
    toolCallId: call.id,
    metadata: call.metadata,
  });
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

export function fromLiteLLMToolCall(call: LiteLLMToolCall): AgentFrameworkAction {
  const action = fromOpenAIAgentsToolCall(call);
  return {
    ...action,
    framework: "litellm",
    metadata: { model: call.model, ...action.metadata },
  };
}

export function fromN8NNodeExecution(call: N8NNodeExecution): AgentFrameworkAction {
  return frameworkAction(
    "n8n",
    call.node ?? call.name,
    call.parameters ?? call.input,
    {
      toolCallId: call.id,
      runId: call.workflowId,
      metadata: call.metadata,
    },
  );
}

export function fromZapierWebhookCall(
  call: ZapierWebhookCall,
): AgentFrameworkAction {
  return frameworkAction(
    "zapier-webhook",
    call.action ?? call.tool,
    call.payload,
    {
      toolCallId: call.id,
      runId: call.zapId,
      metadata: call.metadata,
    },
  );
}

export function fromRawMCPToolCall(call: RawMCPToolCall): AgentFrameworkAction {
  return frameworkAction(
    "raw-mcp",
    call.toolName ?? call.name,
    call.arguments ?? call.args,
    {
      toolCallId: call.id,
      agentId: call.serverId,
      metadata: { scopes: call.scopes, ...call.metadata },
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

function requireCanonicalToolName(
  framework: "codex" | "claude-code" | "hermes",
  field: string,
  value: unknown,
): string {
  if (typeof value !== "string" || !value.trim()) {
    throw new TypeError(`${framework} adapter requires canonical ${field}`);
  }
  return value.trim();
}

function rejectConflictingAliasToolName(
  framework: "codex" | "claude-code" | "hermes",
  canonicalField: string,
  canonicalValue: string,
  aliases: Record<string, unknown>,
): void {
  for (const [field, value] of Object.entries(aliases)) {
    if (value == null) continue;
    if (typeof value !== "string" || !value.trim()) {
      throw new TypeError(
        `${framework} adapter rejects blank alias ${field}; use canonical ${canonicalField}`,
      );
    }
    if (value.trim() !== canonicalValue) {
      throw new TypeError(
        `${framework} adapter rejects conflicting ${field}; use canonical ${canonicalField}`,
      );
    }
  }
}

function requireCanonicalArguments(
  framework: "codex" | "claude-code" | "hermes",
  canonicalField: string,
  canonicalValue: unknown,
  aliases: Record<string, unknown>,
): unknown {
  if (canonicalValue === undefined) {
    throw new TypeError(`${framework} adapter requires canonical ${canonicalField}`);
  }
  for (const [field, value] of Object.entries(aliases)) {
    if (value === undefined) continue;
    if (!sameNormalizedArguments(canonicalValue, value)) {
      throw new TypeError(
        `${framework} adapter rejects conflicting ${field}; use canonical ${canonicalField}`,
      );
    }
  }
  return canonicalValue;
}

function sameNormalizedArguments(left: unknown, right: unknown): boolean {
  return stableSerialize(normalizeArguments(left)) === stableSerialize(normalizeArguments(right));
}

function stableSerialize(value: unknown): string {
  if (Array.isArray(value)) {
    return `[${value.map((item) => stableSerialize(item)).join(",")}]`;
  }
  if (value && typeof value === "object") {
    const object = value as Record<string, unknown>;
    return `{${Object.keys(object)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${stableSerialize(object[key])}`)
      .join(",")}}`;
  }
  return JSON.stringify(value);
}
