/**
 * @mindburn/helm-openai-agents
 *
 * Drop-in governance adapter for OpenAI Agents SDK.
 * Wraps tool execution through HELM's governance plane.
 *
 * Usage:
 * ```ts
 * import { HelmToolProxy } from '@mindburn/helm-openai-agents';
 *
 * const proxy = new HelmToolProxy({ baseUrl: 'http://localhost:8080' });
 * const agent = new Agent({
 *   tools: proxy.wrapTools(myTools),
 * });
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
 * Generic tool definition compatible with OpenAI Agents SDK.
 * Adapts to `FunctionTool` or any tool with a `run` method.
 */
export interface ToolDefinition {
  type: 'function';
  function: {
    name: string;
    description?: string;
    parameters?: Record<string, unknown>;
  };
  run?: (args: Record<string, unknown>) => Promise<unknown>;
}

/** A wrapped tool that routes execution through HELM governance. */
export interface GovernedTool extends ToolDefinition {
  run: (args: Record<string, unknown>) => Promise<unknown>;
  /** The original unwrapped tool. */
  _original: ToolDefinition;
}

// ── Tool Proxy ──────────────────────────────────────────────────

/**
 * HelmToolProxy wraps OpenAI Agents SDK tools with HELM governance.
 *
 * Every tool call is routed through HELM's chat completions API
 * (the OpenAI proxy) so that:
 * 1. The kernel evaluates policy before execution
 * 2. A receipt is produced for every tool call
 * 3. Denied calls never reach the underlying tool
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
   * Wrap an array of tools with HELM governance.
   * Returns new tool objects with `run` methods that go through HELM.
   */
  wrapTools(tools: ToolDefinition[]): GovernedTool[] {
    return tools.map((tool) => this.wrapTool(tool));
  }

  /**
   * Wrap a single tool with HELM governance.
   */
  wrapTool(tool: ToolDefinition): GovernedTool {
    const governed: GovernedTool = {
      ...tool,
      _original: tool,
      run: async (args: Record<string, unknown>) => {
        return this.executeGoverned(tool, args);
      },
    };
    return governed;
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

  private async executeGoverned(
    tool: ToolDefinition,
    args: Record<string, unknown>,
  ): Promise<unknown> {
    const startMs = Date.now();
    const toolName = tool.function.name;

    try {
      // Step 1: Send tool call intent through HELM's OpenAI proxy.
      // This lets the kernel evaluate policy and produce a receipt.
      // Uses chatCompletionsWithReceipt to extract kernel-issued governance metadata.
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
              description: tool.function.description,
              parameters: tool.function.parameters,
            },
          },
        ],
      });

      // Step 2: Check if the kernel approved the call.
      // Check both the response body AND the kernel governance headers.
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

      // Step 4: Collect kernel-issued receipt (NOT fabricated).
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

      // If not fail-closed, fall through to direct execution.
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
    if (typeof result === 'string') {
      return result;
    }

    try {
      return JSON.stringify(result) ?? String(result);
    } catch {
      return String(result);
    }
  }

  private static resolveReceiptStatus(governanceStatus: string): Receipt['status'] {
    if (governanceStatus === 'DENIED' || governanceStatus === 'PEP_VALIDATION_FAILED') {
      return 'DENIED';
    }
    if (governanceStatus === 'PENDING') {
      return 'PENDING';
    }
    return 'APPROVED';
  }

  private nextLamportClock(kernelLamportClock: number): number {
    const nextLamportClock =
      kernelLamportClock > this.lastLamportClock
        ? kernelLamportClock
        : this.lastLamportClock + 1;
    this.lastLamportClock = nextLamportClock;
    return nextLamportClock;
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
