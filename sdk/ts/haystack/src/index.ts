/**
 * @mindburn/helm-haystack
 *
 * HELM governance adapter for the Haystack Node.js client.
 * Provides a governor that intercepts Haystack pipeline component calls through HELM.
 * Every component invocation is evaluated by the Guardian pipeline before execution.
 *
 * Architecture:
 *   Haystack pipeline -> component run -> HelmHaystackGovernor -> HELM governance -> component execution
 *
 * Usage:
 * ```ts
 * import { HelmHaystackGovernor } from '@mindburn/helm-haystack';
 *
 * const governor = new HelmHaystackGovernor({
 *   baseUrl: 'http://localhost:8080',
 *   principal: 'my-haystack-pipeline',
 * });
 *
 * await governor.governComponentCall({
 *   componentName: 'retriever',
 *   componentType: 'InMemoryBM25Retriever',
 *   inputs: { query: 'example' },
 * });
 * ```
 */

import { HelmClient, HelmApiError } from '@mindburn/helm';
import type { HelmClientConfig, Receipt } from '@mindburn/helm';

// ── Types ───────────────────────────────────────────────────────

/** Configuration for the HELM Haystack governor. */
export interface HelmHaystackConfig extends HelmClientConfig {
  /** Principal identity for governance evaluation. Default: 'haystack-pipeline'. */
  principal?: string;

  /** If true, deny component execution on HELM API errors (fail-closed). Default: true. */
  failClosed?: boolean;

  /** If true, collect receipts for every component call. Default: true. */
  collectReceipts?: boolean;

  /** Optional callback invoked after each governed component call with its receipt. */
  onReceipt?: (receipt: ComponentCallReceipt) => void;

  /** Optional callback invoked when a component call is denied. */
  onDeny?: (denial: ComponentCallDenial) => void;
}

/** A Haystack component call to be governed. */
export interface HaystackComponentCall {
  /** Component name within the pipeline. */
  componentName: string;
  /** Component type (e.g., 'InMemoryBM25Retriever', 'OpenAIGenerator'). */
  componentType?: string;
  /** Component input parameters. */
  inputs: Record<string, unknown>;
  /** Optional pipeline name. */
  pipelineName?: string;
}

/** A Haystack pipeline execution to be governed. */
export interface HaystackPipelineExecution {
  /** Pipeline name. */
  pipelineName: string;
  /** Pipeline input data. */
  inputs: Record<string, Record<string, unknown>>;
}

/** A receipt for a governed component call. */
export interface ComponentCallReceipt {
  componentName: string;
  receipt: Receipt;
  durationMs: number;
}

/** Details of a denied component call. */
export interface ComponentCallDenial {
  componentName: string;
  input: string;
  reasonCode: string;
  message: string;
}

// ── Errors ──────────────────────────────────────────────────────

/** Error thrown when HELM denies a component call. */
export class HelmComponentDenyError extends Error {
  readonly denial: ComponentCallDenial;

  constructor(denial: ComponentCallDenial) {
    super(`HELM denied component "${denial.componentName}": ${denial.reasonCode} — ${denial.message}`);
    this.name = 'HelmComponentDenyError';
    this.denial = denial;
  }
}

// ── Governor ────────────────────────────────────────────────────

/**
 * HelmHaystackGovernor governs Haystack pipeline component calls through HELM.
 *
 * Intercepts component invocations and pipeline executions from the Haystack
 * client and evaluates them through the Guardian pipeline before allowing execution.
 *
 * The governor is fail-closed by default: if HELM denies the call or
 * the governance plane is unreachable, the component call is blocked.
 */
export class HelmHaystackGovernor {
  private readonly client: HelmClient;
  private readonly principal: string;
  private readonly failClosed: boolean;
  private readonly collectReceipts: boolean;
  private readonly onReceipt?: (receipt: ComponentCallReceipt) => void;
  private readonly onDeny?: (denial: ComponentCallDenial) => void;
  private readonly receipts: ComponentCallReceipt[] = [];
  private lastLamportClock = -1;

  constructor(config: HelmHaystackConfig) {
    this.client = new HelmClient(config);
    this.principal = config.principal ?? 'haystack-pipeline';
    this.failClosed = config.failClosed ?? true;
    this.collectReceipts = config.collectReceipts ?? true;
    this.onReceipt = config.onReceipt;
    this.onDeny = config.onDeny;
  }

  /**
   * Govern a Haystack component call through HELM.
   * Must be called before executing the component. Throws HelmComponentDenyError if denied.
   *
   * @param call - The component call to govern
   * @returns The component call receipt if approved
   */
  async governComponentCall(call: HaystackComponentCall): Promise<ComponentCallReceipt | null> {
    const startMs = Date.now();
    const toolName = call.componentType
      ? `${call.componentName}:${call.componentType}`
      : call.componentName;

    try {
      const { response, governance } = await this.client.chatCompletionsWithReceipt({
        model: 'helm-governance',
        messages: [
          {
            role: 'user',
            content: JSON.stringify({
              type: 'tool_call_intent',
              tool: toolName,
              principal: this.principal,
              arguments: call.inputs,
              metadata: {
                component_name: call.componentName,
                component_type: call.componentType,
                pipeline_name: call.pipelineName,
              },
            }),
          },
        ],
        tools: [
          {
            type: 'function',
            function: {
              name: toolName,
              description: `Haystack component: ${call.componentType ?? call.componentName}`,
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
        const denial: ComponentCallDenial = {
          componentName: call.componentName,
          input: JSON.stringify(call.inputs),
          reasonCode: governance.reasonCode || 'DENY_POLICY_VIOLATION',
          message: choice?.message?.content ?? 'Component call denied by HELM governance',
        };
        this.onDeny?.(denial);
        throw new HelmComponentDenyError(denial);
      }

      if (!this.collectReceipts) return null;

      const lamportClock = this.nextLamportClock(governance.lamportClock);
      const receiptToken = `${call.componentName}-${lamportClock}`;
      const receiptStatus = HelmHaystackGovernor.resolveReceiptStatus(governance.status);

      const receipt: ComponentCallReceipt = {
        componentName: call.componentName,
        receipt: {
          receipt_id: governance.receiptId || `haystack-${receiptToken}`,
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
      if (error instanceof HelmComponentDenyError) throw error;

      if (error instanceof HelmApiError) {
        const denial: ComponentCallDenial = {
          componentName: call.componentName,
          input: JSON.stringify(call.inputs),
          reasonCode: error.reasonCode,
          message: error.message,
        };
        this.onDeny?.(denial);
        if (this.failClosed) throw new HelmComponentDenyError(denial);
      }

      if (this.failClosed) {
        throw new HelmComponentDenyError({
          componentName: call.componentName,
          input: JSON.stringify(call.inputs),
          reasonCode: 'ERROR_INTERNAL',
          message: String(error),
        });
      }

      return null;
    }
  }

  /**
   * Govern a full Haystack pipeline execution through HELM.
   * Each component in the input map is governed individually.
   *
   * @param execution - The pipeline execution to govern
   * @returns Array of component call receipts
   */
  async governPipeline(execution: HaystackPipelineExecution): Promise<ComponentCallReceipt[]> {
    const results: ComponentCallReceipt[] = [];
    for (const [componentName, inputs] of Object.entries(execution.inputs)) {
      const receipt = await this.governComponentCall({
        componentName,
        inputs,
        pipelineName: execution.pipelineName,
      });
      if (receipt) results.push(receipt);
    }
    return results;
  }

  /**
   * Wrap a component function with HELM governance.
   * The returned function evaluates the call through HELM before executing.
   */
  governComponent<T extends (...args: any[]) => any>(componentName: string, fn: T, componentType?: string): T {
    const governor = this;
    const governed = async function (...args: any[]) {
      const input = args[0] && typeof args[0] === 'object' ? args[0] : { input: args[0] };
      const startMs = Date.now();

      try {
        const toolName = componentType ? `${componentName}:${componentType}` : componentName;

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
          const denial: ComponentCallDenial = {
            componentName,
            input: String(args[0] ?? ''),
            reasonCode: governance.reasonCode || 'DENY_POLICY_VIOLATION',
            message: choice?.message?.content ?? 'Component call denied by HELM governance',
          };
          governor.onDeny?.(denial);
          throw new HelmComponentDenyError(denial);
        }

        const result = await fn(...args);
        const durationMs = Date.now() - startMs;

        if (governor.collectReceipts) {
          const lamportClock = governor.nextLamportClock(governance.lamportClock);
          const receiptToken = `${componentName}-${lamportClock}`;
          const receiptStatus = HelmHaystackGovernor.resolveReceiptStatus(governance.status);

          const receipt: ComponentCallReceipt = {
            componentName,
            receipt: {
              receipt_id: governance.receiptId || `haystack-${receiptToken}`,
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
        if (error instanceof HelmComponentDenyError) throw error;

        if (error instanceof HelmApiError) {
          const denial: ComponentCallDenial = {
            componentName,
            input: String(args[0] ?? ''),
            reasonCode: error.reasonCode,
            message: error.message,
          };
          governor.onDeny?.(denial);
          if (governor.failClosed) throw new HelmComponentDenyError(denial);
        }

        if (governor.failClosed) {
          throw new HelmComponentDenyError({
            componentName,
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
  getReceipts(): ReadonlyArray<ComponentCallReceipt> {
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

export default HelmHaystackGovernor;
