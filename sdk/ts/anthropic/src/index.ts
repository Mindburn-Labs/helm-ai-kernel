/**
 * @mindburn/helm-anthropic
 *
 * HELM governance adapter for the Anthropic Claude TypeScript SDK.
 * Provides a governor that intercepts Claude tool_use content blocks through HELM.
 * Every tool invocation is evaluated by the Guardian pipeline before execution.
 *
 * Architecture:
 *   Claude messages.create -> tool_use blocks -> HelmAnthropicGovernor -> HELM governance -> tool execution
 *
 * Usage:
 * ```ts
 * import { HelmAnthropicGovernor } from '@mindburn/helm-anthropic';
 *
 * const governor = new HelmAnthropicGovernor({
 *   baseUrl: 'http://localhost:8080',
 *   principal: 'my-claude-agent',
 * });
 *
 * for (const block of response.content) {
 *   if (block.type === 'tool_use') {
 *     await governor.governToolUse(block);
 *   }
 * }
 * ```
 */

import { HelmClient, HelmApiError } from '@mindburn/helm';
import type { HelmClientConfig, Receipt } from '@mindburn/helm';

// ── Types ───────────────────────────────────────────────────────

/** Configuration for the HELM Anthropic governor. */
export interface HelmAnthropicConfig extends HelmClientConfig {
  /** Principal identity for governance evaluation. Default: 'anthropic-agent'. */
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

/** A Claude tool_use content block to be governed. */
export interface ClaudeToolUseBlock {
  /** Content block type — must be 'tool_use'. */
  type: 'tool_use';
  /** Unique tool use ID from Claude's response. */
  id: string;
  /** Tool name. */
  name: string;
  /** Tool input object. */
  input: Record<string, unknown>;
}

/** A receipt for a governed tool call. */
export interface ToolCallReceipt {
  toolName: string;
  toolUseId: string;
  receipt: Receipt;
  durationMs: number;
}

/** Details of a denied tool call. */
export interface ToolCallDenial {
  toolName: string;
  toolUseId: string;
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
 * HelmAnthropicGovernor governs Claude tool_use blocks through HELM.
 *
 * Intercepts tool_use content blocks from Claude messages and evaluates them
 * through the Guardian pipeline before allowing execution.
 *
 * The governor is fail-closed by default: if HELM denies the call or
 * the governance plane is unreachable, the tool call is blocked.
 */
export class HelmAnthropicGovernor {
  private readonly client: HelmClient;
  private readonly principal: string;
  private readonly failClosed: boolean;
  private readonly collectReceipts: boolean;
  private readonly onReceipt?: (receipt: ToolCallReceipt) => void;
  private readonly onDeny?: (denial: ToolCallDenial) => void;
  private readonly receipts: ToolCallReceipt[] = [];
  private lastLamportClock = -1;

  constructor(config: HelmAnthropicConfig) {
    this.client = new HelmClient(config);
    this.principal = config.principal ?? 'anthropic-agent';
    this.failClosed = config.failClosed ?? true;
    this.collectReceipts = config.collectReceipts ?? true;
    this.onReceipt = config.onReceipt;
    this.onDeny = config.onDeny;
  }

  /**
   * Govern a Claude tool_use content block through HELM.
   * Must be called before executing the tool. Throws HelmToolDenyError if denied.
   *
   * @param block - The Claude tool_use content block
   * @returns The tool call receipt if approved
   */
  async governToolUse(block: ClaudeToolUseBlock): Promise<ToolCallReceipt | null> {
    const startMs = Date.now();

    try {
      const { response, governance } = await this.client.chatCompletionsWithReceipt({
        model: 'helm-governance',
        messages: [
          {
            role: 'user',
            content: JSON.stringify({
              type: 'tool_call_intent',
              tool: block.name,
              principal: this.principal,
              arguments: block.input,
              metadata: { tool_use_id: block.id },
            }),
          },
        ],
        tools: [
          {
            type: 'function',
            function: {
              name: block.name,
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
          toolName: block.name,
          toolUseId: block.id,
          input: JSON.stringify(block.input),
          reasonCode: governance.reasonCode || 'DENY_POLICY_VIOLATION',
          message: choice?.message?.content ?? 'Tool call denied by HELM governance',
        };
        this.onDeny?.(denial);
        throw new HelmToolDenyError(denial);
      }

      if (!this.collectReceipts) return null;

      const lamportClock = this.nextLamportClock(governance.lamportClock);
      const receiptToken = `${block.name}-${lamportClock}`;
      const receiptStatus = HelmAnthropicGovernor.resolveReceiptStatus(governance.status);

      const receipt: ToolCallReceipt = {
        toolName: block.name,
        toolUseId: block.id,
        receipt: {
          receipt_id: governance.receiptId || `anthropic-${receiptToken}`,
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
          toolName: block.name,
          toolUseId: block.id,
          input: JSON.stringify(block.input),
          reasonCode: error.reasonCode,
          message: error.message,
        };
        this.onDeny?.(denial);
        if (this.failClosed) throw new HelmToolDenyError(denial);
      }

      if (this.failClosed) {
        throw new HelmToolDenyError({
          toolName: block.name,
          toolUseId: block.id,
          input: JSON.stringify(block.input),
          reasonCode: 'ERROR_INTERNAL',
          message: String(error),
        });
      }

      return null;
    }
  }

  /**
   * Govern all tool_use blocks in a Claude message response.
   * Filters content blocks for type === 'tool_use' and governs each one.
   *
   * @param contentBlocks - Array of content blocks from a Claude message response
   * @returns Array of approved tool call receipts
   */
  async governMessageContent(
    contentBlocks: ReadonlyArray<{ type: string; id?: string; name?: string; input?: Record<string, unknown> }>,
  ): Promise<ToolCallReceipt[]> {
    const results: ToolCallReceipt[] = [];
    for (const block of contentBlocks) {
      if (block.type === 'tool_use' && block.name && block.id) {
        const receipt = await this.governToolUse({
          type: 'tool_use',
          id: block.id,
          name: block.name,
          input: block.input ?? {},
        });
        if (receipt) results.push(receipt);
      }
    }
    return results;
  }

  /**
   * Wrap a tool function with HELM governance.
   * The returned function evaluates the call through HELM before executing.
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
            toolUseId: '',
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
          const receiptStatus = HelmAnthropicGovernor.resolveReceiptStatus(governance.status);

          const receipt: ToolCallReceipt = {
            toolName,
            toolUseId: '',
            receipt: {
              receipt_id: governance.receiptId || `anthropic-${receiptToken}`,
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
            toolUseId: '',
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
            toolUseId: '',
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

export default HelmAnthropicGovernor;
