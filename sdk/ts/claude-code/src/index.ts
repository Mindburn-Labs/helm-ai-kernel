/**
 * @mindburn/helm-claude-code
 *
 * Drop-in governance adapter for Anthropic Claude Code and MCP tool servers.
 * Wraps tool execution through HELM's governance plane so every tool call
 * is policy-evaluated, receipt-producing, and fail-closed by default.
 *
 * Usage:
 * ```ts
 * import { HelmToolProxy } from '@mindburn/helm-claude-code';
 *
 * const proxy = new HelmToolProxy({ baseUrl: 'http://localhost:8080' });
 *
 * // Wrap MCP tool definitions before passing to Claude
 * const governedTools = proxy.wrapTools(mcpTools);
 *
 * // Or wrap individual tool execution
 * const result = await proxy.executeGoverned('file_write', { path, content });
 * ```
 */

import { createHash } from 'node:crypto';
import { HelmClient, HelmApiError } from '@mindburn/helm';
import type { HelmClientConfig, Receipt } from '@mindburn/helm';

// ── Types ───────────────────────────────────────────────────────

/** Configuration for the HELM tool proxy. */
export interface HelmToolProxyConfig extends HelmClientConfig {
  /** If true, deny tool execution on HELM API errors (fail-closed). Default: true. */
  failClosed?: boolean;

  /** If true, collect receipts for every tool call. Default: true. */
  collectReceipts?: boolean;

  /** Optional callback invoked after each tool call with its receipt. */
  onReceipt?: (receipt: ToolCallReceipt) => void;

  /** Optional callback invoked when a tool call is denied. */
  onDeny?: (denial: ToolCallDenial) => void;
}

/** A receipt for a governed tool call. */
export interface ToolCallReceipt {
  toolName: string;
  args: Record<string, unknown>;
  receipt: Receipt;
  durationMs: number;
}

/** Details of a denied tool call. */
export interface ToolCallDenial {
  toolName: string;
  args: Record<string, unknown>;
  reasonCode: string;
  message: string;
}

/**
 * MCP-compatible tool definition.
 * Adapts to Anthropic's tool_use format and MCP ToolDefinition.
 */
export interface MCPToolDefinition {
  name: string;
  description?: string;
  input_schema?: Record<string, unknown>;
  run?: (args: Record<string, unknown>) => Promise<unknown>;
}

/**
 * Anthropic tool_use block format for Claude messages API.
 */
export interface AnthropicToolDefinition {
  type: 'function';
  function: {
    name: string;
    description?: string;
    parameters?: Record<string, unknown>;
  };
}

/** A wrapped tool that routes execution through HELM governance. */
export interface GovernedTool extends MCPToolDefinition {
  run: (args: Record<string, unknown>) => Promise<unknown>;
  _original: MCPToolDefinition;
}

// ── Tool Proxy ──────────────────────────────────────────────────

/**
 * HelmToolProxy wraps Claude Code / MCP tool calls with HELM governance.
 *
 * Every tool call is routed through HELM's chat completions API
 * (the OpenAI-compatible proxy) so that:
 * 1. The kernel evaluates policy before execution
 * 2. A receipt is produced for every tool call
 * 3. Denied calls never reach the underlying tool
 *
 * Supports both MCP ToolDefinition format and Anthropic tool_use format.
 */
export class HelmToolProxy {
  private readonly client: HelmClient;
  private readonly failClosed: boolean;
  private readonly collectReceipts: boolean;
  private readonly onReceipt?: (receipt: ToolCallReceipt) => void;
  private readonly onDeny?: (denial: ToolCallDenial) => void;
  private readonly receipts: ToolCallReceipt[] = [];
  private lastLamportClock = -1;

  constructor(config: HelmToolProxyConfig) {
    this.client = new HelmClient(config);
    this.failClosed = config.failClosed ?? true;
    this.collectReceipts = config.collectReceipts ?? true;
    this.onReceipt = config.onReceipt;
    this.onDeny = config.onDeny;
  }

  /**
   * Wrap an array of MCP tools with HELM governance.
   * Returns new tool objects with `run` methods that go through HELM.
   */
  wrapTools(tools: MCPToolDefinition[]): GovernedTool[] {
    return tools.map((tool) => this.wrapTool(tool));
  }

  /**
   * Wrap a single MCP tool with HELM governance.
   */
  wrapTool(tool: MCPToolDefinition): GovernedTool {
    return {
      ...tool,
      _original: tool,
      run: async (args: Record<string, unknown>) => {
        return this._executeGoverned(tool, args);
      },
    };
  }

  /**
   * Convert MCP tools to Anthropic tool_use format for Claude messages API,
   * with HELM governance applied.
   */
  toAnthropicTools(tools: MCPToolDefinition[]): AnthropicToolDefinition[] {
    return tools.map((tool) => ({
      type: 'function' as const,
      function: {
        name: tool.name,
        description: tool.description,
        parameters: tool.input_schema,
      },
    }));
  }

  /**
   * Execute a tool call through HELM governance without wrapping.
   * Use this when you have direct control over tool execution flow.
   */
  async executeGoverned(
    toolName: string,
    args: Record<string, unknown>,
    executor?: (args: Record<string, unknown>) => Promise<unknown>,
  ): Promise<unknown> {
    const tool: MCPToolDefinition = {
      name: toolName,
      run: executor,
    };
    return this._executeGoverned(tool, args);
  }

  /**
   * Get all collected receipts.
   */
  getReceipts(): ReadonlyArray<ToolCallReceipt> {
    return this.receipts;
  }

  /**
   * Clear collected receipts.
   */
  clearReceipts(): void {
    this.receipts.length = 0;
  }

  // ── Internal ──────────────────────────────────────

  private async _executeGoverned(
    tool: MCPToolDefinition,
    args: Record<string, unknown>,
  ): Promise<unknown> {
    const startMs = Date.now();
    const toolName = tool.name;

    try {
      // Step 1: Send tool call intent through HELM's OpenAI proxy.
      const { response, governance } = await this.client.chatCompletionsWithReceipt({
        model: 'helm-governance',
        messages: [
          {
            role: 'user',
            content: JSON.stringify({
              type: 'tool_call_intent',
              tool: toolName,
              arguments: args,
            }),
          },
        ],
        tools: [
          {
            type: 'function',
            function: {
              name: toolName,
              description: tool.description,
              parameters: tool.input_schema,
            },
          },
        ],
      });

      // Step 2: Check if the kernel approved the call.
      const choice = response.choices?.[0];
      const kernelDenied = governance.status === 'DENIED' || governance.status === 'PEP_VALIDATION_FAILED';

      if (kernelDenied || (!choice || choice.finish_reason === 'stop')) {
        const denial: ToolCallDenial = {
          toolName,
          args,
          reasonCode: governance.reasonCode || 'DENY_POLICY_VIOLATION',
          message: choice?.message?.content ?? 'Tool call denied by HELM governance',
        };
        this.onDeny?.(denial);
        throw new HelmToolDenyError(denial);
      }

      // Step 3: Execute the actual tool.
      if (!tool.run) {
        throw new Error(`Tool ${toolName} has no run implementation`);
      }
      const result = await tool.run(args);
      const receiptStatus = HelmToolProxy.resolveReceiptStatus(governance.status);
      const lamportClock = this.nextLamportClock(governance.lamportClock);
      const receiptToken = `${toolName}-${lamportClock}`;

      // Step 4: Collect kernel-issued receipt.
      if (this.collectReceipts) {
        const receipt: ToolCallReceipt = {
          toolName,
          args,
          receipt: {
            receipt_id: governance.receiptId || `local-${receiptToken}`,
            decision_id: governance.decisionId || `decision-${receiptToken}`,
            effect_id: governance.proofGraphNode || `effect-${receiptToken}`,
            status: receiptStatus,
            reason_code: governance.reasonCode || 'ALLOW',
            output_hash: governance.outputHash || HelmToolProxy.computeOutputHash(result),
            blob_hash: '',
            prev_hash: '',
            lamport_clock: lamportClock,
            signature: governance.signature || '',
            timestamp: new Date().toISOString(),
            principal: 'helm-kernel',
          },
          durationMs: Date.now() - startMs,
        };
        this.receipts.push(receipt);
        this.onReceipt?.(receipt);
      }

      return result;
    } catch (error) {
      if (error instanceof HelmToolDenyError) throw error;

      if (error instanceof HelmApiError) {
        const denial: ToolCallDenial = {
          toolName,
          args,
          reasonCode: error.reasonCode,
          message: error.message,
        };
        this.onDeny?.(denial);

        if (this.failClosed) {
          throw new HelmToolDenyError(denial);
        }
      }

      if (!this.failClosed && tool.run) {
        return tool.run(args);
      }

      throw error;
    }
  }

  private static computeOutputHash(result: unknown): string {
    const serialized = HelmToolProxy.serializeResult(result);
    return `sha256:${createHash('sha256').update(serialized).digest('hex')}`;
  }

  private static serializeResult(result: unknown): string {
    if (typeof result === 'string') return result;
    try {
      return JSON.stringify(result) ?? String(result);
    } catch {
      return String(result);
    }
  }

  private static resolveReceiptStatus(governanceStatus: string): Receipt['status'] {
    if (governanceStatus === 'DENIED' || governanceStatus === 'PEP_VALIDATION_FAILED') return 'DENIED';
    if (governanceStatus === 'PENDING') return 'PENDING';
    return 'APPROVED';
  }

  private nextLamportClock(kernelLamportClock: number): number {
    const next = kernelLamportClock > this.lastLamportClock
      ? kernelLamportClock
      : this.lastLamportClock + 1;
    this.lastLamportClock = next;
    return next;
  }
}

/**
 * Error thrown when HELM denies a tool call.
 */
export class HelmToolDenyError extends Error {
  readonly denial: ToolCallDenial;

  constructor(denial: ToolCallDenial) {
    super(`HELM denied tool call "${denial.toolName}": ${denial.reasonCode} — ${denial.message}`);
    this.name = 'HelmToolDenyError';
    this.denial = denial;
  }
}

export default HelmToolProxy;
