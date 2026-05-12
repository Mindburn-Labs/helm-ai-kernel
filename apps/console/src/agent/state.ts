import type { ConsoleBootstrap, Receipt } from "../api/client";

export interface HelmOssAgentState {
  workspace: ConsoleBootstrap["workspace"] | null;
  surface: string;
  selectedReceiptId: string | null;
  query: string;
  conformance: ConsoleBootstrap["conformance"] | null;
  mcp: ConsoleBootstrap["mcp"] | null;
  receipts: readonly Receipt[];
  receiptCount: number;
  demoAction: string;
  replayStatus: string;
  buildProfile: "oss";
}

export function buildOssAgentState(input: {
  bootstrap: ConsoleBootstrap | null;
  active: string;
  selectedReceipt: Receipt | null;
  query: string;
  receipts: readonly Receipt[];
  demoAction: string;
  replayStatus: string;
}): HelmOssAgentState {
  return {
    workspace: input.bootstrap?.workspace ?? null,
    surface: input.active,
    selectedReceiptId: input.selectedReceipt?.receipt_id ?? null,
    query: input.query,
    conformance: input.bootstrap?.conformance ?? null,
    mcp: input.bootstrap?.mcp ?? null,
    receipts: input.receipts.slice(0, 25),
    receiptCount: input.receipts.length,
    demoAction: input.demoAction,
    replayStatus: input.replayStatus,
    buildProfile: "oss",
  };
}

export interface OssAgentToolResult {
  status: "complete" | "error" | "denied";
  summary: string;
  data?: Record<string, unknown>;
  receipt_refs?: string[];
  proof_refs?: string[];
  next_actions?: string[];
}
