/**
 * @mindburn/helm-langchain
 *
 * HELM governance adapter for LangChain.js.
 * Provides a callback handler that governs LangChain tool calls through HELM.
 * Every tool invocation is evaluated by the Guardian pipeline before execution.
 *
 * Architecture:
 *   LangChain chain/agent -> HelmCallbackHandler -> HELM governance -> tool
 *
 * Usage:
 * ```ts
 * import { HelmCallbackHandler } from '@mindburn/helm-langchain';
 *
 * const handler = new HelmCallbackHandler({
 *   baseUrl: 'http://localhost:8080',
 *   principal: 'my-langchain-agent',
 * });
 *
 * // Attach to any LangChain chain, agent, or model
 * const model = new ChatOpenAI({ callbacks: [handler] });
 * ```
 */

import { HelmClient, HelmApiError } from '@mindburn/helm';
import type { HelmClientConfig, Receipt } from '@mindburn/helm';

// ── Types ───────────────────────────────────────────────────────

/** Configuration for the HELM LangChain callback handler. */
export interface HelmLangChainConfig extends HelmClientConfig {
  /** Principal identity for governance evaluation. Default: 'langchain-agent'. */
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

// ── Callback Handler ────────────────────────────────────────────

/**
 * HelmCallbackHandler integrates HELM governance into LangChain.js chains.
 *
 * Implements the LangChain BaseCallbackHandler interface shape so it can be
 * passed to any chain, agent, or model via the `callbacks` option.
 *
 * Intercepts:
 * - handleToolStart: Evaluates tool call through Guardian before execution
 * - handleToolEnd: Captures output hash for receipt generation
 * - handleToolError: Records governance-relevant errors
 * - handleLLMStart: Records LLM invocation context (observability)
 * - handleChainError: Records chain-level errors
 *
 * The handler is fail-closed by default: if HELM denies the tool call or
 * the governance plane is unreachable, the tool call is blocked.
 */
export class HelmCallbackHandler {
  /** LangChain callback handler name — used for handler identification. */
  readonly name = 'HelmCallbackHandler';

  private readonly client: HelmClient;
  private readonly principal: string;
  private readonly failClosed: boolean;
  private readonly collectReceipts: boolean;
  private readonly onReceipt?: (receipt: ToolCallReceipt) => void;
  private readonly onDeny?: (denial: ToolCallDenial) => void;
  private readonly receipts: ToolCallReceipt[] = [];
  private lastLamportClock = -1;

  /** Pending tool evaluations keyed by run ID. */
  private readonly pendingTools = new Map<
    string,
    { toolName: string; startMs: number; governanceStatus: string; reasonCode: string; receiptId: string; decisionId: string; proofGraphNode: string; lamportClock: number; signature: string; outputHash: string }
  >();

  constructor(config: HelmLangChainConfig) {
    this.client = new HelmClient(config);
    this.principal = config.principal ?? 'langchain-agent';
    this.failClosed = config.failClosed ?? true;
    this.collectReceipts = config.collectReceipts ?? true;
    this.onReceipt = config.onReceipt;
    this.onDeny = config.onDeny;
  }

  /**
   * Called when a LangChain tool starts execution.
   * Evaluates the tool call through HELM governance before allowing it to proceed.
   *
   * @param tool - Tool metadata (name, description)
   * @param input - Serialized tool input
   * @param runId - Unique run identifier (from LangChain)
   * @param parentRunId - Parent run identifier (optional)
   */
  async handleToolStart(
    tool: { name: string; description?: string },
    input: string,
    runId?: string,
    parentRunId?: string,
  ): Promise<void> {
    const startMs = Date.now();
    const effectiveRunId = runId ?? `run-${startMs}`;

    try {
      const { response, governance } = await this.client.chatCompletionsWithReceipt({
        model: 'helm-governance',
        messages: [
          {
            role: 'user',
            content: JSON.stringify({
              type: 'tool_call_intent',
              tool: tool.name,
              principal: this.principal,
              arguments: { input, parent_run_id: parentRunId },
            }),
          },
        ],
        tools: [
          {
            type: 'function',
            function: {
              name: tool.name,
              description: tool.description,
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
          toolName: tool.name,
          input,
          reasonCode: governance.reasonCode || 'DENY_POLICY_VIOLATION',
          message: choice?.message?.content ?? 'Tool call denied by HELM governance',
        };
        this.onDeny?.(denial);
        throw new HelmToolDenyError(denial);
      }

      // Store pending governance data for receipt generation in handleToolEnd
      this.pendingTools.set(effectiveRunId, {
        toolName: tool.name,
        startMs,
        governanceStatus: governance.status,
        reasonCode: governance.reasonCode,
        receiptId: governance.receiptId,
        decisionId: governance.decisionId,
        proofGraphNode: governance.proofGraphNode,
        lamportClock: governance.lamportClock,
        signature: governance.signature,
        outputHash: governance.outputHash,
      });
    } catch (error) {
      if (error instanceof HelmToolDenyError) throw error;

      if (error instanceof HelmApiError) {
        const denial: ToolCallDenial = {
          toolName: tool.name,
          input,
          reasonCode: error.reasonCode,
          message: error.message,
        };
        this.onDeny?.(denial);
        if (this.failClosed) throw new HelmToolDenyError(denial);
      }

      if (this.failClosed) {
        throw new HelmToolDenyError({
          toolName: tool.name,
          input,
          reasonCode: 'ERROR_INTERNAL',
          message: String(error),
        });
      }
    }
  }

  /**
   * Called when a LangChain tool finishes execution.
   * Finalizes the receipt for the governed tool call.
   *
   * @param output - Tool output string
   * @param runId - Unique run identifier (from LangChain)
   */
  async handleToolEnd(output: string, runId?: string): Promise<void> {
    const effectiveRunId = runId ?? '';
    const pending = this.pendingTools.get(effectiveRunId);
    if (!pending) return;

    this.pendingTools.delete(effectiveRunId);

    if (!this.collectReceipts) return;

    const lamportClock = this.nextLamportClock(pending.lamportClock);
    const receiptToken = `${pending.toolName}-${lamportClock}`;
    const receiptStatus = HelmCallbackHandler.resolveReceiptStatus(pending.governanceStatus);

    const receipt: ToolCallReceipt = {
      toolName: pending.toolName,
      receipt: {
        receipt_id: pending.receiptId || `langchain-${receiptToken}`,
        decision_id: pending.decisionId || `decision-${receiptToken}`,
        effect_id: pending.proofGraphNode || `effect-${receiptToken}`,
        status: receiptStatus,
        reason_code: pending.reasonCode || 'ALLOW',
        output_hash: pending.outputHash || '',
        blob_hash: '',
        prev_hash: '',
        lamport_clock: lamportClock,
        signature: pending.signature || '',
        timestamp: new Date().toISOString(),
        principal: 'helm-kernel',
      },
      durationMs: Date.now() - pending.startMs,
    };

    this.receipts.push(receipt);
    this.onReceipt?.(receipt);
  }

  /**
   * Called when a LangChain tool encounters an error.
   *
   * @param error - The error that occurred
   * @param runId - Unique run identifier (from LangChain)
   */
  async handleToolError(error: Error, runId?: string): Promise<void> {
    const effectiveRunId = runId ?? '';
    this.pendingTools.delete(effectiveRunId);
  }

  /**
   * Called when an LLM starts generating.
   * Records the invocation for observability (not a governance gate).
   *
   * @param llm - LLM metadata (name, model)
   * @param prompts - Array of prompt strings
   * @param runId - Unique run identifier
   */
  async handleLLMStart(
    llm: { name?: string },
    prompts: string[],
    runId?: string,
  ): Promise<void> {
    // Observability hook — no governance gate on LLM invocation itself.
    // Override in subclass for custom telemetry.
  }

  /**
   * Called when a chain encounters an error.
   *
   * @param error - The error that occurred
   * @param runId - Unique run identifier
   */
  async handleChainError(error: Error, runId?: string): Promise<void> {
    // Observability hook — subclass for custom error handling.
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

// ── Tool Governor ───────────────────────────────────────────────

/**
 * HelmToolGovernor provides an imperative API for governing LangChain tools.
 *
 * Use this when you need direct control over tool governance rather than
 * the callback-based approach.
 *
 * ```ts
 * import { HelmToolGovernor } from '@mindburn/helm-langchain';
 *
 * const governor = new HelmToolGovernor({ baseUrl: 'http://localhost:8080' });
 *
 * // Wrap a LangChain DynamicTool's func
 * const governedFunc = governor.governTool('my-tool', originalFunc);
 * ```
 */
export class HelmToolGovernor {
  private readonly client: HelmClient;
  private readonly principal: string;
  private readonly failClosed: boolean;
  private readonly collectReceipts: boolean;
  private readonly onReceipt?: (receipt: ToolCallReceipt) => void;
  private readonly onDeny?: (denial: ToolCallDenial) => void;
  private readonly receipts: ToolCallReceipt[] = [];
  private lastLamportClock = -1;

  constructor(config: HelmLangChainConfig) {
    this.client = new HelmClient(config);
    this.principal = config.principal ?? 'langchain-agent';
    this.failClosed = config.failClosed ?? true;
    this.collectReceipts = config.collectReceipts ?? true;
    this.onReceipt = config.onReceipt;
    this.onDeny = config.onDeny;
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
          const receiptStatus = HelmToolGovernor.resolveReceiptStatus(governance.status);

          const receipt: ToolCallReceipt = {
            toolName,
            receipt: {
              receipt_id: governance.receiptId || `langchain-${receiptToken}`,
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

export default HelmCallbackHandler;
