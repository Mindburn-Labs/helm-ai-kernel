/**
 * @mindburn/helm-vercel-ai
 *
 * HELM governance adapter for the Vercel AI SDK (ai package).
 * Provides a governor that intercepts Vercel AI SDK tool calls through HELM.
 * Every tool invocation is evaluated by the Guardian pipeline before execution.
 *
 * Architecture:
 *   Vercel AI SDK generateText/streamText -> tool execute -> HelmVercelAIGovernor -> HELM governance -> tool
 *
 * Usage:
 * ```ts
 * import { HelmVercelAIGovernor } from '@mindburn/helm-vercel-ai';
 * import { tool } from 'ai';
 *
 * const governor = new HelmVercelAIGovernor({
 *   baseUrl: 'http://localhost:8080',
 *   principal: 'my-nextjs-agent',
 * });
 *
 * const weatherTool = tool({
 *   description: 'Get weather',
 *   parameters: z.object({ city: z.string() }),
 *   execute: governor.governTool('weather', async ({ city }) => {
 *     return `Weather in ${city}: sunny`;
 *   }),
 * });
 * ```
 */

import { HelmClient, HelmApiError } from '@mindburn/helm';
import type { HelmClientConfig, Receipt } from '@mindburn/helm';

// ── Types ───────────────────────────────────────────────────────

/** Configuration for the HELM Vercel AI SDK governor. */
export interface HelmVercelAIConfig extends HelmClientConfig {
  /** Principal identity for governance evaluation. Default: 'vercel-ai-agent'. */
  principal?: string;

  /** If true, deny tool execution on HELM API errors (fail-closed). Default: true. */
  failClosed?: boolean;

  /** If true, collect receipts for every tool call. Default: true. */
  collectReceipts?: boolean;

  /** Optional callback invoked after each governed tool call with its receipt. */
  onReceipt?: (receipt: ToolCallReceipt) => void;

  /** Optional callback invoked when a tool call is denied. */
  onDeny?: (denial: ToolCallDenial) => void;
}

/** A Vercel AI SDK tool call to be governed. */
export interface VercelToolCall {
  /** Tool name. */
  toolName: string;
  /** Tool call ID from the AI SDK. */
  toolCallId?: string;
  /** Tool arguments. */
  args: Record<string, unknown>;
}

/** A receipt for a governed tool call. */
export interface ToolCallReceipt {
  toolName: string;
  receipt: Receipt;
  durationMs: number;
}

/** Details of a denied tool call. */
export interface ToolCallDenial {
  toolName: string;
  input: string;
  reasonCode: string;
  message: string;
}

// ── Errors ──────────────────────────────────────────────────────

/** Error thrown when HELM denies a tool call. */
export class HelmToolDenyError extends Error {
  readonly denial: ToolCallDenial;

  constructor(denial: ToolCallDenial) {
    super(`HELM denied tool "${denial.toolName}": ${denial.reasonCode} — ${denial.message}`);
    this.name = 'HelmToolDenyError';
    this.denial = denial;
  }
}

// ── Governor ────────────────────────────────────────────────────

/**
 * HelmVercelAIGovernor governs Vercel AI SDK tool calls through HELM.
 *
 * Intercepts tool execute functions from the AI SDK and evaluates them
 * through the Guardian pipeline before allowing execution.
 *
 * The governor is fail-closed by default: if HELM denies the call or
 * the governance plane is unreachable, the tool call is blocked.
 */
export class HelmVercelAIGovernor {
  private readonly client: HelmClient;
  private readonly principal: string;
  private readonly failClosed: boolean;
  private readonly collectReceipts: boolean;
  private readonly onReceipt?: (receipt: ToolCallReceipt) => void;
  private readonly onDeny?: (denial: ToolCallDenial) => void;
  private readonly receipts: ToolCallReceipt[] = [];
  private lastLamportClock = -1;

  constructor(config: HelmVercelAIConfig) {
    this.client = new HelmClient(config);
    this.principal = config.principal ?? 'vercel-ai-agent';
    this.failClosed = config.failClosed ?? true;
    this.collectReceipts = config.collectReceipts ?? true;
    this.onReceipt = config.onReceipt;
    this.onDeny = config.onDeny;
  }

  /**
   * Govern a Vercel AI SDK tool call through HELM.
   * Must be called before executing the tool. Throws HelmToolDenyError if denied.
   *
   * @param call - The tool call to govern
   * @returns The tool call receipt if approved
   */
  async governToolCall(call: VercelToolCall): Promise<ToolCallReceipt | null> {
    const startMs = Date.now();

    try {
      const { response, governance } = await this.client.chatCompletionsWithReceipt({
        model: 'helm-governance',
        messages: [
          {
            role: 'user',
            content: JSON.stringify({
              type: 'tool_call_intent',
              tool: call.toolName,
              principal: this.principal,
              arguments: call.args,
              metadata: { tool_call_id: call.toolCallId },
            }),
          },
        ],
        tools: [
          {
            type: 'function',
            function: {
              name: call.toolName,
              parameters: { type: 'object', properties: { input: { type: 'string' } } },
            },
          },
        ],
      });

      const choice = response.choices?.[0];
      const kernelDenied =
        governance.status === 'DENIED' || governance.status === 'PEP_VALIDATION_FAILED';

      if (
        kernelDenied ||
        !choice ||
        (choice.finish_reason === 'stop' && !choice.message?.tool_calls?.length)
      ) {
        const denial: ToolCallDenial = {
          toolName: call.toolName,
          input: JSON.stringify(call.args),
          reasonCode: governance.reasonCode || 'DENY_POLICY_VIOLATION',
          message: choice?.message?.content ?? 'Tool call denied by HELM governance',
        };
        this.onDeny?.(denial);
        throw new HelmToolDenyError(denial);
      }

      if (!this.collectReceipts) return null;

      const lamportClock = this.nextLamportClock(governance.lamportClock);
      const receiptToken = `${call.toolName}-${lamportClock}`;
      const receiptStatus = HelmVercelAIGovernor.resolveReceiptStatus(governance.status);

      const receipt: ToolCallReceipt = {
        toolName: call.toolName,
        receipt: {
          receipt_id: governance.receiptId || `vercel-ai-${receiptToken}`,
          decision_id: governance.decisionId || `decision-${receiptToken}`,
          effect_id: governance.proofGraphNode || `effect-${receiptToken}`,
          status: receiptStatus,
          reason_code: governance.reasonCode || 'ALLOW',
          output_hash: governance.outputHash || '',
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
      return receipt;
    } catch (error) {
      if (error instanceof HelmToolDenyError) throw error;

      if (error instanceof HelmApiError) {
        const denial: ToolCallDenial = {
          toolName: call.toolName,
          input: JSON.stringify(call.args),
          reasonCode: error.reasonCode,
          message: error.message,
        };
        this.onDeny?.(denial);
        if (this.failClosed) throw new HelmToolDenyError(denial);
      }

      if (this.failClosed) {
        throw new HelmToolDenyError({
          toolName: call.toolName,
          input: JSON.stringify(call.args),
          reasonCode: 'ERROR_INTERNAL',
          message: String(error),
        });
      }

      return null;
    }
  }

  /**
   * Wrap a Vercel AI SDK tool execute function with HELM governance.
   * The returned function evaluates the call through HELM before executing.
   *
   * Usage with the `tool()` helper:
   * ```ts
   * const myTool = tool({
   *   description: 'My tool',
   *   parameters: z.object({ query: z.string() }),
   *   execute: governor.governTool('my-tool', async ({ query }) => {
   *     return `Result for: ${query}`;
   *   }),
   * });
   * ```
   */
  governTool<T extends (...args: any[]) => any>(toolName: string, fn: T): T {
    const governor = this;
    const governed = async function (...args: any[]) {
      const input = args[0] && typeof args[0] === 'object' ? args[0] : { input: args[0] };
      const startMs = Date.now();

      try {
        const { response, governance } = await governor.client.chatCompletionsWithReceipt({
          model: 'helm-governance',
          messages: [
            {
              role: 'user',
              content: JSON.stringify({
                type: 'tool_call_intent',
                tool: toolName,
                principal: governor.principal,
                arguments: input,
              }),
            },
          ],
          tools: [
            {
              type: 'function',
              function: { name: toolName },
            },
          ],
        });

        const choice = response.choices?.[0];
        const kernelDenied =
          governance.status === 'DENIED' || governance.status === 'PEP_VALIDATION_FAILED';

        if (
          kernelDenied ||
          !choice ||
          (choice.finish_reason === 'stop' && !choice.message?.tool_calls?.length)
        ) {
          const denial: ToolCallDenial = {
            toolName,
            input: String(args[0] ?? ''),
            reasonCode: governance.reasonCode || 'DENY_POLICY_VIOLATION',
            message: choice?.message?.content ?? 'Tool call denied by HELM governance',
          };
          governor.onDeny?.(denial);
          throw new HelmToolDenyError(denial);
        }

        const result = await fn(...args);
        const durationMs = Date.now() - startMs;

        if (governor.collectReceipts) {
          const lamportClock = governor.nextLamportClock(governance.lamportClock);
          const receiptToken = `${toolName}-${lamportClock}`;
          const receiptStatus = HelmVercelAIGovernor.resolveReceiptStatus(governance.status);

          const receipt: ToolCallReceipt = {
            toolName,
            receipt: {
              receipt_id: governance.receiptId || `vercel-ai-${receiptToken}`,
              decision_id: governance.decisionId || `decision-${receiptToken}`,
              effect_id: governance.proofGraphNode || `effect-${receiptToken}`,
              status: receiptStatus,
              reason_code: governance.reasonCode || 'ALLOW',
              output_hash: governance.outputHash || '',
              blob_hash: '',
              prev_hash: '',
              lamport_clock: lamportClock,
              signature: governance.signature || '',
              timestamp: new Date().toISOString(),
              principal: 'helm-kernel',
            },
            durationMs,
          };

          governor.receipts.push(receipt);
          governor.onReceipt?.(receipt);
        }

        return result;
      } catch (error) {
        if (error instanceof HelmToolDenyError) throw error;

        if (error instanceof HelmApiError) {
          const denial: ToolCallDenial = {
            toolName,
            input: String(args[0] ?? ''),
            reasonCode: error.reasonCode,
            message: error.message,
          };
          governor.onDeny?.(denial);
          if (governor.failClosed) throw new HelmToolDenyError(denial);
        }

        if (governor.failClosed) {
          throw new HelmToolDenyError({
            toolName,
            input: String(args[0] ?? ''),
            reasonCode: 'ERROR_INTERNAL',
            message: String(error),
          });
        }

        return fn(...args);
      }
    };
    return governed as unknown as T;
  }

  /**
   * Create a middleware-style interceptor for Vercel AI SDK.
   * Returns a function compatible with the AI SDK middleware pattern
   * that governs tool calls before they execute.
   */
  createMiddleware(): (params: { toolName: string; toolCallId?: string; args: Record<string, unknown> }) => Promise<void> {
    return async (params) => {
      await this.governToolCall({
        toolName: params.toolName,
        toolCallId: params.toolCallId,
        args: params.args,
      });
    };
  }

  /** Get all collected receipts. */
  getReceipts(): ReadonlyArray<ToolCallReceipt> {
    return this.receipts;
  }

  /** Clear collected receipts. */
  clearReceipts(): void {
    this.receipts.length = 0;
  }

  // ── Internal ──────────────────────────────────────────────────

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
    const next =
      kernelLamportClock > this.lastLamportClock
        ? kernelLamportClock
        : this.lastLamportClock + 1;
    this.lastLamportClock = next;
    return next;
  }
}

export default HelmVercelAIGovernor;
