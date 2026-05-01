import { describe, expect, it } from "vitest";
import {
  ASSISTANT_RUN_SEMANTICS,
  TOOL_CALL_SEMANTICS,
  VERDICT_SEMANTICS,
  VERIFICATION_SEMANTICS,
  labelForState,
  railForState,
} from "./semantics";

describe("canonical HELM state semantics", () => {
  it("maps verdicts to rails and labels", () => {
    expect(railForState("allow")).toBe("allow");
    expect(railForState("deny")).toBe("deny");
    expect(railForState("escalate")).toBe("escalate");
    expect(labelForState("deny")).toBe("DENY");
  });

  it("covers verification, assistant, and tool-call states", () => {
    expect(VERIFICATION_SEMANTICS.verified.rail).toBe("verified");
    expect(ASSISTANT_RUN_SEMANTICS.permission_limited.rail).toBe("escalate");
    expect(TOOL_CALL_SEMANTICS.denied_by_policy.rail).toBe("deny");
  });

  it("keeps active verdict vocabulary explicit", () => {
    expect(Object.keys(VERDICT_SEMANTICS)).toEqual(["allow", "deny", "escalate", "pending"]);
  });
});
