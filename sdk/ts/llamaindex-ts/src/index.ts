/**
 * @mindburn/helm-llamaindex-ts
 *
 * HELM governance adapter for LlamaIndex TypeScript.
 * Wraps LlamaIndex query engines and tool executions with HELM governance,
 * providing policy enforcement, receipt chains, and fail-closed semantics.
 *
 * Architecture:
 *   LlamaIndex query/tool -> HelmQueryEngineWrapper / HelmToolSpec -> HELM governance -> execution
 *
 * Usage:
 * ```ts
 * import { HelmQueryEngineWrapper, HelmToolSpec } from '@mindburn/helm-llamaindex-ts';
 *
 * // Govern query engine calls
 * const wrapper = new HelmQueryEngineWrapper({ baseUrl: 'http://localhost:8080' });
 * const response = await wrapper.governedQuery(queryEngine, 'What is HELM?');
 *
 * // Govern tool calls
 * const toolSpec = new HelmToolSpec({ baseUrl: 'http://localhost:8080' });
 * const governedTool = toolSpec.governTool('search', searchFn);
 * ```
 */

import { HelmClient, HelmApiError } from '@mindburn/helm';
import type { HelmClientConfig, Receipt } from '@mindburn/helm';

// ── Types ───────────────────────────────────────────────────────

/** Configuration for the HELM LlamaIndex adapter. */
export interface HelmLlamaConfig extends HelmClientConfig {
  /** Principal identity for governance evaluation. Default: 'llamaindex-agent'. */
  principal?: string;

  /** If true, deny execution on HELM API errors (fail-closed). Default: true. */
  failClosed?: boolean;

  /** If true, collect receipts for every query/tool call. Default: true. */
  collectReceipts?: boolean;

  /** Optional callback invoked after each governed execution with its receipt. */
  onReceipt?: (receipt: QueryReceipt) => void;

  /** Optional callback invoked when a query/tool is denied. */
  onDeny?: (denial: QueryDenial) => void;
}

/** A receipt for a governed query or tool execution. */
export interface QueryReceipt {
  operationName: string;
  operationType: 'query' | 'tool' | 'retrieve';
  receipt: Receipt;
  durationMs: number;
}

/** Details of a denied query or tool execution. */
export interface QueryDenial {
  operationName: string;
  operationType: 'query' | 'tool' | 'retrieve';
  reasonCode: string;
  message: string;
}

/**
 * Minimal query engine interface.
 * Compatible with LlamaIndex's BaseQueryEngine without importing it.
 */
export interface QueryEngine {
  query(query: string): Promise<{ response: string; sourceNodes?: unknown[] }>;
}

/**
 * Minimal retriever interface.
 * Compatible with LlamaIndex's BaseRetriever without importing it.
 */
export interface Retriever {
  retrieve(query: string): Promise<Array<{ node: { text: string }; score?: number }>>;
}

// ── Errors ──────────────────────────────────────────────────────

/** Error thrown when HELM denies a query or tool. */
export class HelmQueryDenyError extends Error {
  readonly denial: QueryDenial;

  constructor(denial: QueryDenial) {
    super(
      `HELM denied ${denial.operationType} "${denial.operationName}": ${denial.reasonCode} — ${denial.message}`,
    );
    this.name = 'HelmQueryDenyError';
    this.denial = denial;
  }
}

// ── Query Engine Wrapper ────────────────────────────────────────

/**
 * HelmQueryEngineWrapper wraps LlamaIndex query engines with HELM governance.
 *
 * Every query is routed through HELM's governance plane:
 * 1. The kernel evaluates policy before the query executes
 * 2. If approved, the query engine runs
 * 3. A receipt is produced for the query execution
 * 4. If denied, a HelmQueryDenyError is thrown (fail-closed)
 */
export class HelmQueryEngineWrapper {
  private readonly client: HelmClient;
  private readonly principal: string;
  private readonly failClosed: boolean;
  private readonly collectReceipts: boolean;
  private readonly onReceipt?: (receipt: QueryReceipt) => void;
  private readonly onDeny?: (denial: QueryDenial) => void;
  private readonly receipts: QueryReceipt[] = [];
  private lastLamportClock = -1;

  constructor(config: HelmLlamaConfig) {
    this.client = new HelmClient(config);
    this.principal = config.principal ?? 'llamaindex-agent';
    this.failClosed = config.failClosed ?? true;
    this.collectReceipts = config.collectReceipts ?? true;
    this.onReceipt = config.onReceipt;
    this.onDeny = config.onDeny;
  }

  /**
   * Execute a governed query against a LlamaIndex query engine.
   *
   * @param engine - A LlamaIndex query engine (or any object with a query method)
   * @param query - The query string
   * @param engineName - Optional name for the engine (used in receipts). Default: 'query-engine'.
   * @returns The query engine response
   */
  async governedQuery(
    engine: QueryEngine,
    query: string,
    engineName?: string,
  ): Promise<{ response: string; sourceNodes?: unknown[] }> {
    const opName = engineName ?? 'query-engine';
    return this.executeGoverned(opName, 'query', { query }, () => engine.query(query));
  }

  /**
   * Execute a governed retrieval against a LlamaIndex retriever.
   *
   * @param retriever - A LlamaIndex retriever (or any object with a retrieve method)
   * @param query - The query string
   * @param retrieverName - Optional name for the retriever. Default: 'retriever'.
   * @returns The retriever results
   */
  async governedRetrieve(
    retriever: Retriever,
    query: string,
    retrieverName?: string,
  ): Promise<Array<{ node: { text: string }; score?: number }>> {
    const opName = retrieverName ?? 'retriever';
    return this.executeGoverned(opName, 'retrieve', { query }, () => retriever.retrieve(query));
  }

  /** Get all collected receipts. */
  getReceipts(): ReadonlyArray<QueryReceipt> {
    return this.receipts;
  }

  /** Clear collected receipts. */
  clearReceipts(): void {
    this.receipts.length = 0;
  }

  // ── Internal ──────────────────────────────────────────────────

  /** @internal Execute a governed operation. Used by HelmToolSpec. */
  async executeGoverned<T>(
    operationName: string,
    operationType: 'query' | 'tool' | 'retrieve',
    context: Record<string, unknown>,
    execute: () => Promise<T>,
  ): Promise<T> {
    const startMs = Date.now();

    try {
      const { response, governance } = await this.client.chatCompletionsWithReceipt({
        model: 'helm-governance',
        messages: [
          {
            role: 'user',
            content: JSON.stringify({
              type: `${operationType}_intent`,
              operation: operationName,
              principal: this.principal,
              context,
            }),
          },
        ],
        tools: [
          {
            type: 'function',
            function: {
              name: operationName,
              description: `LlamaIndex ${operationType}: ${operationName}`,
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
        const denial: QueryDenial = {
          operationName,
          operationType,
          reasonCode: governance.reasonCode || 'DENY_POLICY_VIOLATION',
          message: choice?.message?.content ?? `${operationType} denied by HELM governance`,
        };
        this.onDeny?.(denial);
        throw new HelmQueryDenyError(denial);
      }

      // Governance approved — execute
      const result = await execute();
      const durationMs = Date.now() - startMs;

      if (this.collectReceipts) {
        const lamportClock = this.nextLamportClock(governance.lamportClock);
        const receiptToken = `${operationName}-${lamportClock}`;
        const receiptStatus = HelmQueryEngineWrapper.resolveReceiptStatus(governance.status);

        const receipt: QueryReceipt = {
          operationName,
          operationType,
          receipt: {
            receipt_id: governance.receiptId || `llamaindex-${receiptToken}`,
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
      if (error instanceof HelmQueryDenyError) throw error;

      if (error instanceof HelmApiError) {
        const denial: QueryDenial = {
          operationName,
          operationType,
          reasonCode: error.reasonCode,
          message: error.message,
        };
        this.onDeny?.(denial);
        if (this.failClosed) throw new HelmQueryDenyError(denial);
      }

      if (this.failClosed) {
        throw new HelmQueryDenyError({
          operationName,
          operationType,
          reasonCode: 'ERROR_INTERNAL',
          message: String(error),
        });
      }

      // Fail-open: execute without governance
      return execute();
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

// ── Tool Spec ───────────────────────────────────────────────────

/**
 * HelmToolSpec wraps LlamaIndex tool functions with HELM governance.
 *
 * Use this to govern tools used with LlamaIndex agents (OpenAIAgent,
 * ReActAgent, etc.).
 *
 * ```ts
 * const spec = new HelmToolSpec({ baseUrl: 'http://localhost:8080' });
 * const governed = spec.governTool('calculator', async (input: string) => {
 *   return eval(input);
 * });
 * ```
 */
export class HelmToolSpec {
  private readonly wrapper: HelmQueryEngineWrapper;

  constructor(config: HelmLlamaConfig) {
    this.wrapper = new HelmQueryEngineWrapper(config);
  }

  /**
   * Wrap a tool function with HELM governance.
   *
   * @param toolName - Name of the tool
   * @param fn - The original tool function
   * @returns A governed version of the function
   */
  governTool<T extends (...args: any[]) => any>(toolName: string, fn: T): T {
    const spec = this;
    const governed = async function (...args: any[]) {
      const input = args[0] && typeof args[0] === 'object' ? args[0] : { input: args[0] };
      return spec.wrapper.executeGoverned(
        toolName,
        'tool',
        { arguments: input },
        () => fn(...args),
      );
    };
    return governed as unknown as T;
  }

  /**
   * Govern an array of tools.
   *
   * @param tools - Array of tool definitions
   * @returns Governed tool array
   */
  governTools(
    tools: Array<{ name: string; fn: (...args: any[]) => any }>,
  ): Array<{ name: string; fn: (...args: any[]) => any }> {
    return tools.map((t) => ({ name: t.name, fn: this.governTool(t.name, t.fn) }));
  }

  /** Get all collected receipts. */
  getReceipts(): ReadonlyArray<QueryReceipt> {
    return this.wrapper.getReceipts();
  }

  /** Clear collected receipts. */
  clearReceipts(): void {
    this.wrapper.clearReceipts();
  }
}

export default HelmQueryEngineWrapper;
