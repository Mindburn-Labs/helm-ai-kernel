/**
 * @mindburn/helm-mistral
 *
 * HELM governance adapter for the Mistral AI TypeScript SDK.
 * Provides a governor that intercepts Mistral function calls through HELM.
 * Every tool invocation is evaluated by the Guardian pipeline before execution.
 *
 * Architecture:
 *   Mistral chat completion -> HelmMistralGovernor -> HELM governance -> function execution
 *
 * Usage:
 * ```ts
 * import { HelmMistralGovernor } from '@mindburn/helm-mistral';
 *
 * const governor = new HelmMistralGovernor({
 *   baseUrl: 'http://localhost:8080',
 *   principal: 'my-mistral-agent',
 * });
 *
 * // Govern a function call from a Mistral chat completion
 * await governor.governFunctionCall({
 *   name: 'search_web',
 *   arguments: '{"query": "example"}',
 * });
 * ```
 */

import { HelmClient, HelmApiError } from '@mindburn/helm';
import type { HelmClientConfig, Receipt } from '@mindburn/helm';

// ── Types ───────────────────────────────────────────────────────

/** Configuration for the HELM Mistral governor. */
export interface HelmMistralConfig extends HelmClientConfig {
  /** Principal identity for governance evaluation. Default: 'mistral-agent'. */
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

/** A Mistral function call to be governed. */
export interface MistralFunctionCall {
  /** Function name. */
  name: string;
  /** JSON-encoded arguments string. */
  arguments: string;
  /** Optional call ID from Mistral's response. */
  id?: string;
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
 * HelmMistralGovernor governs Mistral AI function calls through HELM.
 *
 * Intercepts function calls from Mistral chat completions and evaluates them
 * through the Guardian pipeline before allowing execution.
 *
 * The governor is fail-closed by default: if HELM denies the call or
 * the governance plane is unreachable, the function call is blocked.
 */
export class HelmMistralGovernor {
  private readonly client: HelmClient;
  private readonly principal: string;
  private readonly failClosed: boolean;
  private readonly collectReceipts: boolean;
  private readonly onReceipt?: (receipt: ToolCallReceipt) => void;
  private readonly onDeny?: (denial: ToolCallDenial) => void;
  private readonly receipts: ToolCallReceipt[] = [];
  private lastLamportClock = -1;

  constructor(config: HelmMistralConfig) {
    this.client = new HelmClient(config);
    this.principal = config.principal ?? 'mistral-agent';
    this.failClosed = config.failClosed ?? true;
    this.collectReceipts = config.collectReceipts ?? true;
    this.onReceipt = config.onReceipt;
    this.onDeny = config.onDeny;
  }

  /**
   * Govern a Mistral function call through HELM.
   * Must be called before executing the function. Throws HelmToolDenyError if denied.
   *
   * @param call - The Mistral function call to govern
   * @returns The tool call receipt if approved
   */
  async governFunctionCall(call: MistralFunctionCall): Promise<ToolCallReceipt | null> {
    const startMs = Date.now();

    try {
      const { response, governance } = await this.client.chatCompletionsWithReceipt({
        model: 'helm-governance',
        messages: [
          {
            role: 'user',
            content: JSON.stringify({
              type: 'tool_call_intent',
              tool: call.name,
              principal: this.principal,
              arguments: HelmMistralGovernor.safeParseArgs(call.arguments),
            }),
          },
        ],
        tools: [
          {
            type: 'function',
            function: {
              name: call.name,
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
          toolName: call.name,
          input: call.arguments,
          reasonCode: governance.reasonCode || 'DENY_POLICY_VIOLATION',
          message: choice?.message?.content ?? 'Tool call denied by HELM governance',
        };
        this.onDeny?.(denial);
        throw new HelmToolDenyError(denial);
      }

      if (!this.collectReceipts) return null;

      const lamportClock = this.nextLamportClock(governance.lamportClock);
      const receiptToken = `${call.name}-${lamportClock}`;
      const receiptStatus = HelmMistralGovernor.resolveReceiptStatus(governance.status);

      const receipt: ToolCallReceipt = {
        toolName: call.name,
        receipt: {
          receipt_id: governance.receiptId || `mistral-${receiptToken}`,
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
          toolName: call.name,
          input: call.arguments,
          reasonCode: error.reasonCode,
          message: error.message,
        };
        this.onDeny?.(denial);
        if (this.failClosed) throw new HelmToolDenyError(denial);
      }

      if (this.failClosed) {
        throw new HelmToolDenyError({
          toolName: call.name,
          input: call.arguments,
          reasonCode: 'ERROR_INTERNAL',
          message: String(error),
        });
      }

      return null;
    }
  }

  /**
   * Govern all function calls in a Mistral chat completion response.
   * Iterates tool_calls from the response and governs each one.
   *
   * @param toolCalls - Array of Mistral tool calls from a chat completion response
   * @returns Array of approved tool call receipts
   */
  async governToolCalls(
    toolCalls: ReadonlyArray<{ id?: string; function: MistralFunctionCall }>,
  ): Promise<ToolCallReceipt[]> {
    const results: ToolCallReceipt[] = [];
    for (const tc of toolCalls) {
      const receipt = await this.governFunctionCall({
        name: tc.function.name,
        arguments: tc.function.arguments,
        id: tc.id,
      });
      if (receipt) results.push(receipt);
    }
    return results;
  }

  /**
   * Wrap a function with HELM governance.
   * The returned function evaluates the call through HELM before executing.
   */
  governFunction<T extends (...args: any[]) => any>(toolName: string, fn: T): T {
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
          const receiptStatus = HelmMistralGovernor.resolveReceiptStatus(governance.status);

          const receipt: ToolCallReceipt = {
            toolName,
            receipt: {
              receipt_id: governance.receiptId || `mistral-${receiptToken}`,
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

  /** Get all collected receipts. */
  getReceipts(): ReadonlyArray<ToolCallReceipt> {
    return this.receipts;
  }

  /** Clear collected receipts. */
  clearReceipts(): void {
    this.receipts.length = 0;
  }

  // ── Internal ──────────────────────────────────────────────────

  private static safeParseArgs(args: string): Record<string, unknown> {
    try {
      return JSON.parse(args);
    } catch {
      return { raw: args };
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
    const next =
      kernelLamportClock > this.lastLamportClock
        ? kernelLamportClock
        : this.lastLamportClock + 1;
    this.lastLamportClock = next;
    return next;
  }
}

export default HelmMistralGovernor;
