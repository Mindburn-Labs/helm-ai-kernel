import { describe, expect, it } from "vitest";
import { buildOssAgentState } from "./state";

describe("HELM OSS agent state", () => {
  it("keeps OSS state read-only and excludes commercial concepts", () => {
    const state = buildOssAgentState({
      bootstrap: null,
      active: "command",
      selectedReceipt: {
        receipt_id: "receipt-1",
        decision_id: "decision-1",
        status: "DENY",
      },
      query: "deny",
      receipts: [{ receipt_id: "receipt-1" }],
      demoAction: "read_ticket",
      replayStatus: "not checked",
    });

    expect(state.buildProfile).toBe("oss");
    expect(state.selectedReceiptId).toBe("receipt-1");
    expect(state.receiptCount).toBe(1);
    expect("companyArtifactGraph" in state).toBe(false);
    expect("generatedSpecs" in state).toBe(false);
  });
});
