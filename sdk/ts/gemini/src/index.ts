/**
 * @mindburn/helm-gemini
 *
 * Drop-in governance adapter for Google Gemini function calling.
 * Wraps tool execution through HELM's governance plane so every function call
 * is policy-evaluated, receipt-producing, and fail-closed by default.
 *
 * Usage:
 * ```ts
 * import { HelmToolProxy } from '@mindburn/helm-gemini';
 *
 * const proxy = new HelmToolProxy({ baseUrl: 'http://localhost:8080' });
 *
 * // Wrap Gemini function declarations
 * const governedTools = proxy.wrapTools(myTools);
 *
 * // Or govern individual calls
 * const result = await proxy.executeGoverned('search', { query }, searchFn);
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
 * Gemini-compatible function declaration.
 * Matches the `@google/genai` FunctionDeclaration type.
 */
export interface GeminiFunctionDeclaration {
  name: string;
  description?: string;
  parameters?: {
    type: string;
    properties?: Record<string, unknown>;
    required?: string[];
  };
  run?: (args: Record<string, unknown>) => Promise<unknown>;
}

/** A wrapped tool that routes execution through HELM governance. */
export interface GovernedTool extends GeminiFunctionDeclaration {
  run: (args: Record<string, unknown>) => Promise<unknown>;
  _original: GeminiFunctionDeclaration;
}

// ── Tool Proxy ──────────────────────────────────────────────────

/**
 * HelmToolProxy wraps Google Gemini function calls with HELM governance.
 *
 * Every function call is routed through HELM's chat completions API
 * (the OpenAI-compatible proxy) so that:
 * 1. The kernel evaluates policy before execution
 * 2. A receipt is produced for every function call
 * 3. Denied calls never reach the underlying function
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
   * Wrap an array of Gemini function declarations with HELM governance.
   */
  wrapTools(tools: GeminiFunctionDeclaration[]): GovernedTool[] {
    return tools.map((tool) => this.wrapTool(tool));
  }

  /**
   * Wrap a single Gemini function declaration with HELM governance.
   */
  wrapTool(tool: GeminiFunctionDeclaration): GovernedTool {
    return {
      ...tool,
      _original: tool,
      run: async (args: Record<string, unknown>) => {
        return this._executeGoverned(tool, args);
      },
    };
  }

  /**
   * Convert Gemini function declarations to OpenAI-compatible format
   * for direct use with HELM's proxy endpoint.
   */
  toOpenAITools(tools: GeminiFunctionDeclaration[]): Array<{
    type: 'function';
    function: { name: string; description?: string; parameters?: Record<string, unknown> };
  }> {
    return tools.map((tool) => ({
      type: 'function' as const,
      function: {
        name: tool.name,
        description: tool.description,
        parameters: tool.parameters,
      },
    }));
  }

  /**
   * Execute a function call through HELM governance without wrapping.
   */
  async executeGoverned(
    toolName: string,
    args: Record<string, unknown>,
    executor?: (args: Record<string, unknown>) => Promise<unknown>,
  ): Promise<unknown> {
    const tool: GeminiFunctionDeclaration = {
      name: toolName,
      run: executor,
    };
    return this._executeGoverned(tool, args);
  }

  /**
   * Process a Gemini function call response through HELM governance.
   * Use this when Gemini returns a function_call and you want to govern
   * the execution before responding.
   */
  async governFunctionCall(
    functionCall: { name: string; args: Record<string, unknown> },
    executor: (args: Record<string, unknown>) => Promise<unknown>,
  ): Promise<unknown> {
    return this.executeGoverned(functionCall.name, functionCall.args, executor);
  }

  /** Get all collected receipts. */
  getReceipts(): ReadonlyArray<ToolCallReceipt> {
    return this.receipts;
  }

  /** Clear collected receipts. */
  clearReceipts(): void {
    this.receipts.length = 0;
  }

  // ── Internal ──────────────────────────────────────

  private async _executeGoverned(
    tool: GeminiFunctionDeclaration,
    args: Record<string, unknown>,
  ): Promise<unknown> {
    const startMs = Date.now();
    const toolName = tool.name;

    try {
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
              parameters: tool.parameters,
            },
          },
        ],
      });

      const choice = response.choices?.[0];
      const kernelDenied = governance.status === 'DENIED' || governance.status === 'PEP_VALIDATION_FAILED';

      if (kernelDenied || (!choice || choice.finish_reason === 'stop')) {
        const denial: ToolCallDenial = {
          toolName,
          args,
          reasonCode: governance.reasonCode || 'DENY_POLICY_VIOLATION',
          message: choice?.message?.content ?? 'Function call denied by HELM governance',
        };
        this.onDeny?.(denial);
        throw new HelmToolDenyError(denial);
      }

      if (!tool.run) {
        throw new Error(`Function ${toolName} has no run implementation`);
      }
      const result = await tool.run(args);
      const receiptStatus = HelmToolProxy.resolveReceiptStatus(governance.status);
      const lamportClock = this.nextLamportClock(governance.lamportClock);
      const receiptToken = `${toolName}-${lamportClock}`;

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
        if (this.failClosed) throw new HelmToolDenyError(denial);
      }

      if (!this.failClosed && tool.run) return tool.run(args);
      throw error;
    }
  }

  private static computeOutputHash(result: unknown): string {
    const serialized = typeof result === 'string' ? result : JSON.stringify(result) ?? String(result);
    return `sha256:${createHash('sha256').update(serialized).digest('hex')}`;
  }

  private static resolveReceiptStatus(governanceStatus: string): Receipt['status'] {
    if (governanceStatus === 'DENIED' || governanceStatus === 'PEP_VALIDATION_FAILED') return 'DENIED';
    if (governanceStatus === 'PENDING') return 'PENDING';
    return 'APPROVED';
  }

  private nextLamportClock(kernelLamportClock: number): number {
    const next = kernelLamportClock > this.lastLamportClock ? kernelLamportClock : this.lastLamportClock + 1;
    this.lastLamportClock = next;
    return next;
  }
}

/**
 * Error thrown when HELM denies a function call.
 */
export class HelmToolDenyError extends Error {
  readonly denial: ToolCallDenial;

  constructor(denial: ToolCallDenial) {
    super(`HELM denied function call "${denial.toolName}": ${denial.reasonCode} — ${denial.message}`);
    this.name = 'HelmToolDenyError';
    this.denial = denial;
  }
}

export default HelmToolProxy;
