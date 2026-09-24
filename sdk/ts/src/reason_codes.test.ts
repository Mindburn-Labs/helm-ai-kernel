import { describe, expect, it } from "vitest";
import { ReasonCodes, isRegisteredReasonCode } from "./index.js";

describe("reason codes", () => {
  it("names every registry code as its wire string", () => {
    expect(Object.keys(ReasonCodes)).toHaveLength(104);
    expect(ReasonCodes.EMERGENCY_STOP_FENCED).toBe("EMERGENCY_STOP_FENCED");
    expect(isRegisteredReasonCode("EMERGENCY_STOP_FENCED")).toBe(true);
    expect(isRegisteredReasonCode("NOT_A_REGISTERED_CODE")).toBe(false);
  });
});
