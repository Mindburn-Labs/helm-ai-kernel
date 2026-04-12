/**
 * @mindburn/helm-crewai-js
 *
 * HELM governance adapter for CrewAI JavaScript/TypeScript.
 * Wraps CrewAI task execution with HELM governance, providing policy
 * enforcement, receipt chains, and fail-closed semantics.
 *
 * Architecture:
 *   CrewAI task/tool -> HelmCrewGovernor -> HELM governance -> execution
 *
 * Usage:
 * ```ts
 * import { HelmCrewGovernor } from '@mindburn/helm-crewai-js';
 *
 * const governor = new HelmCrewGovernor({
 *   baseUrl: 'http://localhost:8080',
 *   principal: 'my-crew',
 * });
 *
 * // Govern a task execution
 * const result = await governor.governTask('research', async () => {
 *   return await myResearchTool.execute(query);
 * });
 *
 * // Or wrap a tool function
 * const governed = governor.governTool('search', searchFn);
 * ```
 */

import { HelmClient, HelmApiError } from '@mindburn/helm';
import type { HelmClientConfig, Receipt } from '@mindburn/helm';

// ── Types ───────────────────────────────────────────────────────

/** Configuration for the HELM CrewAI governor. */
export interface HelmCrewConfig extends HelmClientConfig {
  /** Principal identity for governance evaluation. Default: 'crewai-agent'. */
  principal?: string;

  /** If true, deny execution on HELM API errors (fail-closed). Default: true. */
  failClosed?: boolean;

  /** If true, collect receipts for every task/tool call. Default: true. */
  collectReceipts?: boolean;

  /** Optional callback invoked after each governed execution with its receipt. */
  onReceipt?: (receipt: TaskReceipt) => void;

  /** Optional callback invoked when a task/tool is denied. */
  onDeny?: (denial: TaskDenial) => void;
}

/** A receipt for a governed task or tool execution. */
export interface TaskReceipt {
  taskName: string;
  receipt: Receipt;
  durationMs: number;
}

/** Details of a denied task or tool execution. */
export interface TaskDenial {
  taskName: string;
  reasonCode: string;
  message: string;
}

// ── Errors ──────────────────────────────────────────────────────

/** Error thrown when HELM denies a task or tool. */
export class HelmTaskDenyError extends Error {
  readonly denial: TaskDenial;

  constructor(denial: TaskDenial) {
    super(`HELM denied task "${denial.taskName}": ${denial.reasonCode} — ${denial.message}`);
    this.name = 'HelmTaskDenyError';
    this.denial = denial;
  }
}

// ── Governor ────────────────────────────────────────────────────

/**
 * HelmCrewGovernor wraps CrewAI task and tool executions with HELM governance.
 *
 * Every task/tool execution is routed through HELM's governance plane:
 * 1. The kernel evaluates policy before execution
 * 2. If approved, the task/tool executes
 * 3. A receipt is produced for the execution
 * 4. If denied, a HelmTaskDenyError is thrown (fail-closed)
 */
export class HelmCrewGovernor {
  private readonly client: HelmClient;
  private readonly principal: string;
  private readonly failClosed: boolean;
  private readonly collectReceipts: boolean;
  private readonly onReceipt?: (receipt: TaskReceipt) => void;
  private readonly onDeny?: (denial: TaskDenial) => void;
  private readonly receipts: TaskReceipt[] = [];
  private lastLamportClock = -1;

  constructor(config: HelmCrewConfig) {
    this.client = new HelmClient(config);
    this.principal = config.principal ?? 'crewai-agent';
    this.failClosed = config.failClosed ?? true;
    this.collectReceipts = config.collectReceipts ?? true;
    this.onReceipt = config.onReceipt;
    this.onDeny = config.onDeny;
  }

  /**
   * Govern a CrewAI task execution.
   * Evaluates the task through HELM governance before calling the executor.
   *
   * @param taskName - Name of the task being executed
   * @param execute - Async function that performs the actual task work
   * @param context - Optional context passed to the governance evaluation
   * @returns The result of the executor function
   */
  async governTask<T>(
    taskName: string,
    execute: () => Promise<T>,
    context?: Record<string, unknown>,
  ): Promise<T> {
    const startMs = Date.now();

    try {
      const { response, governance } = await this.client.chatCompletionsWithReceipt({
        model: 'helm-governance',
        messages: [
          {
            role: 'user',
            content: JSON.stringify({
              type: 'task_execution_intent',
              task: taskName,
              principal: this.principal,
              context: context ?? {},
            }),
          },
        ],
        tools: [
          {
            type: 'function',
            function: {
              name: taskName,
              description: `CrewAI task: ${taskName}`,
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
        const denial: TaskDenial = {
          taskName,
          reasonCode: governance.reasonCode || 'DENY_POLICY_VIOLATION',
          message: choice?.message?.content ?? 'Task denied by HELM governance',
        };
        this.onDeny?.(denial);
        throw new HelmTaskDenyError(denial);
      }

      // Governance approved — execute the task
      const result = await execute();
      const durationMs = Date.now() - startMs;

      if (this.collectReceipts) {
        const lamportClock = this.nextLamportClock(governance.lamportClock);
        const receiptToken = `${taskName}-${lamportClock}`;
        const receiptStatus = HelmCrewGovernor.resolveReceiptStatus(governance.status);

        const receipt: TaskReceipt = {
          taskName,
          receipt: {
            receipt_id: governance.receiptId || `crewai-${receiptToken}`,
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

        this.receipts.push(receipt);
        this.onReceipt?.(receipt);
      }

      return result;
    } catch (error) {
      if (error instanceof HelmTaskDenyError) throw error;

      if (error instanceof HelmApiError) {
        const denial: TaskDenial = {
          taskName,
          reasonCode: error.reasonCode,
          message: error.message,
        };
        this.onDeny?.(denial);
        if (this.failClosed) throw new HelmTaskDenyError(denial);
      }

      if (this.failClosed) {
        throw new HelmTaskDenyError({
          taskName,
          reasonCode: 'ERROR_INTERNAL',
          message: String(error),
        });
      }

      // Fail-open: execute without governance
      return execute();
    }
  }

  /**
   * Wrap a tool function with HELM governance.
   * Returns a governed version of the function that evaluates through HELM first.
   *
   * @param toolName - Name of the tool
   * @param fn - The original tool function
   * @returns A governed version of the function
   */
  governTool<T extends (...args: any[]) => any>(toolName: string, fn: T): T {
    const governor = this;
    const governed = async function (...args: any[]) {
      return governor.governTask(
        toolName,
        () => fn(...args),
        { arguments: args[0] && typeof args[0] === 'object' ? args[0] : { input: args[0] } },
      );
    };
    return governed as unknown as T;
  }

  /**
   * Govern an entire crew's tool set.
   * Wraps each tool's function with HELM governance.
   *
   * @param tools - Array of tool definitions with name and function
   * @returns Governed tool array
   */
  governTools(
    tools: Array<{ name: string; fn: (...args: any[]) => any }>,
  ): Array<{ name: string; fn: (...args: any[]) => any }> {
    return tools.map((t) => ({ name: t.name, fn: this.governTool(t.name, t.fn) }));
  }

  /** Get all collected receipts. */
  getReceipts(): ReadonlyArray<TaskReceipt> {
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

export default HelmCrewGovernor;
