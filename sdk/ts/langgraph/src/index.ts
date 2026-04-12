/**
 * @mindburn/helm-langgraph
 *
 * HELM governance adapter for LangGraph.js.
 * Provides a governor that intercepts LangGraph node executions through HELM.
 * Every node invocation is evaluated by the Guardian pipeline before execution.
 *
 * Architecture:
 *   LangGraph StateGraph -> node function -> HelmLangGraphGovernor -> HELM governance -> node execution
 *
 * Usage:
 * ```ts
 * import { HelmLangGraphGovernor } from '@mindburn/helm-langgraph';
 * import { StateGraph } from '@langchain/langgraph';
 *
 * const governor = new HelmLangGraphGovernor({
 *   baseUrl: 'http://localhost:8080',
 *   principal: 'my-langgraph-agent',
 * });
 *
 * graph.addNode('search', governor.governNode('search', async (state) => {
 *   return { messages: [...state.messages, 'result'] };
 * }));
 * ```
 */

import { HelmClient, HelmApiError } from '@mindburn/helm';
import type { HelmClientConfig, Receipt } from '@mindburn/helm';

// ── Types ───────────────────────────────────────────────────────

/** Configuration for the HELM LangGraph governor. */
export interface HelmLangGraphConfig extends HelmClientConfig {
  /** Principal identity for governance evaluation. Default: 'langgraph-agent'. */
  principal?: string;

  /** If true, deny node execution on HELM API errors (fail-closed). Default: true. */
  failClosed?: boolean;

  /** If true, collect receipts for every node execution. Default: true. */
  collectReceipts?: boolean;

  /** Optional callback invoked after each governed node execution with its receipt. */
  onReceipt?: (receipt: NodeExecutionReceipt) => void;

  /** Optional callback invoked when a node execution is denied. */
  onDeny?: (denial: NodeExecutionDenial) => void;
}

/** A LangGraph node execution to be governed. */
export interface LangGraphNodeCall {
  /** Node name. */
  nodeName: string;
  /** State snapshot summary (serializable keys, not full state). */
  stateKeys?: string[];
  /** Optional graph ID. */
  graphId?: string;
  /** Optional thread ID for checkpointing. */
  threadId?: string;
}

/** A receipt for a governed node execution. */
export interface NodeExecutionReceipt {
  nodeName: string;
  receipt: Receipt;
  durationMs: number;
}

/** Details of a denied node execution. */
export interface NodeExecutionDenial {
  nodeName: string;
  input: string;
  reasonCode: string;
  message: string;
}

// ── Errors ──────────────────────────────────────────────────────

/** Error thrown when HELM denies a node execution. */
export class HelmNodeDenyError extends Error {
  readonly denial: NodeExecutionDenial;

  constructor(denial: NodeExecutionDenial) {
    super(`HELM denied node "${denial.nodeName}": ${denial.reasonCode} — ${denial.message}`);
    this.name = 'HelmNodeDenyError';
    this.denial = denial;
  }
}

// ── Governor ────────────────────────────────────────────────────

/**
 * HelmLangGraphGovernor governs LangGraph.js node executions through HELM.
 *
 * Wraps graph node functions so that each invocation is evaluated by the
 * Guardian pipeline before allowing execution.
 *
 * The governor is fail-closed by default: if HELM denies the call or
 * the governance plane is unreachable, the node execution is blocked.
 */
export class HelmLangGraphGovernor {
  private readonly client: HelmClient;
  private readonly principal: string;
  private readonly failClosed: boolean;
  private readonly collectReceipts: boolean;
  private readonly onReceipt?: (receipt: NodeExecutionReceipt) => void;
  private readonly onDeny?: (denial: NodeExecutionDenial) => void;
  private readonly receipts: NodeExecutionReceipt[] = [];
  private lastLamportClock = -1;

  constructor(config: HelmLangGraphConfig) {
    this.client = new HelmClient(config);
    this.principal = config.principal ?? 'langgraph-agent';
    this.failClosed = config.failClosed ?? true;
    this.collectReceipts = config.collectReceipts ?? true;
    this.onReceipt = config.onReceipt;
    this.onDeny = config.onDeny;
  }

  /**
   * Govern a LangGraph node execution through HELM.
   * Must be called before executing the node. Throws HelmNodeDenyError if denied.
   *
   * @param call - The node execution to govern
   * @returns The node execution receipt if approved
   */
  async governNodeCall(call: LangGraphNodeCall): Promise<NodeExecutionReceipt | null> {
    const startMs = Date.now();

    try {
      const { response, governance } = await this.client.chatCompletionsWithReceipt({
        model: 'helm-governance',
        messages: [
          {
            role: 'user',
            content: JSON.stringify({
              type: 'tool_call_intent',
              tool: call.nodeName,
              principal: this.principal,
              arguments: {
                state_keys: call.stateKeys,
                graph_id: call.graphId,
                thread_id: call.threadId,
              },
            }),
          },
        ],
        tools: [
          {
            type: 'function',
            function: {
              name: call.nodeName,
              description: `LangGraph node: ${call.nodeName}`,
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
        const denial: NodeExecutionDenial = {
          nodeName: call.nodeName,
          input: JSON.stringify(call.stateKeys ?? []),
          reasonCode: governance.reasonCode || 'DENY_POLICY_VIOLATION',
          message: choice?.message?.content ?? 'Node execution denied by HELM governance',
        };
        this.onDeny?.(denial);
        throw new HelmNodeDenyError(denial);
      }

      if (!this.collectReceipts) return null;

      const lamportClock = this.nextLamportClock(governance.lamportClock);
      const receiptToken = `${call.nodeName}-${lamportClock}`;
      const receiptStatus = HelmLangGraphGovernor.resolveReceiptStatus(governance.status);

      const receipt: NodeExecutionReceipt = {
        nodeName: call.nodeName,
        receipt: {
          receipt_id: governance.receiptId || `langgraph-${receiptToken}`,
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
      if (error instanceof HelmNodeDenyError) throw error;

      if (error instanceof HelmApiError) {
        const denial: NodeExecutionDenial = {
          nodeName: call.nodeName,
          input: JSON.stringify(call.stateKeys ?? []),
          reasonCode: error.reasonCode,
          message: error.message,
        };
        this.onDeny?.(denial);
        if (this.failClosed) throw new HelmNodeDenyError(denial);
      }

      if (this.failClosed) {
        throw new HelmNodeDenyError({
          nodeName: call.nodeName,
          input: JSON.stringify(call.stateKeys ?? []),
          reasonCode: 'ERROR_INTERNAL',
          message: String(error),
        });
      }

      return null;
    }
  }

  /**
   * Wrap a LangGraph node function with HELM governance.
   * The returned function evaluates the node through HELM before executing.
   *
   * Usage with StateGraph:
   * ```ts
   * graph.addNode('search', governor.governNode('search', async (state) => {
   *   return { messages: [...state.messages, 'result'] };
   * }));
   * ```
   */
  governNode<T extends (...args: any[]) => any>(nodeName: string, fn: T): T {
    const governor = this;
    const governed = async function (...args: any[]) {
      const state = args[0] && typeof args[0] === 'object' ? args[0] : {};
      const stateKeys = Object.keys(state);
      const startMs = Date.now();

      try {
        const { response, governance } = await governor.client.chatCompletionsWithReceipt({
          model: 'helm-governance',
          messages: [
            {
              role: 'user',
              content: JSON.stringify({
                type: 'tool_call_intent',
                tool: nodeName,
                principal: governor.principal,
                arguments: { state_keys: stateKeys },
              }),
            },
          ],
          tools: [
            {
              type: 'function',
              function: { name: nodeName },
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
          const denial: NodeExecutionDenial = {
            nodeName,
            input: JSON.stringify(stateKeys),
            reasonCode: governance.reasonCode || 'DENY_POLICY_VIOLATION',
            message: choice?.message?.content ?? 'Node execution denied by HELM governance',
          };
          governor.onDeny?.(denial);
          throw new HelmNodeDenyError(denial);
        }

        const result = await fn(...args);
        const durationMs = Date.now() - startMs;

        if (governor.collectReceipts) {
          const lamportClock = governor.nextLamportClock(governance.lamportClock);
          const receiptToken = `${nodeName}-${lamportClock}`;
          const receiptStatus = HelmLangGraphGovernor.resolveReceiptStatus(governance.status);

          const receipt: NodeExecutionReceipt = {
            nodeName,
            receipt: {
              receipt_id: governance.receiptId || `langgraph-${receiptToken}`,
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
        if (error instanceof HelmNodeDenyError) throw error;

        if (error instanceof HelmApiError) {
          const denial: NodeExecutionDenial = {
            nodeName,
            input: JSON.stringify(stateKeys),
            reasonCode: error.reasonCode,
            message: error.message,
          };
          governor.onDeny?.(denial);
          if (governor.failClosed) throw new HelmNodeDenyError(denial);
        }

        if (governor.failClosed) {
          throw new HelmNodeDenyError({
            nodeName,
            input: JSON.stringify(stateKeys),
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
   * Wrap a tool function with HELM governance (for tools used within graph nodes).
   * Alias for governNode with tool-oriented semantics.
   */
  governTool<T extends (...args: any[]) => any>(toolName: string, fn: T): T {
    return this.governNode(toolName, fn);
  }

  /** Get all collected receipts. */
  getReceipts(): ReadonlyArray<NodeExecutionReceipt> {
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

export default HelmLangGraphGovernor;
