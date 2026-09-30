import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { HelmApiError } from "./index.js";

// The kernel pins this body in core/pkg/httperr (TestErrorModelVector).
const vector = JSON.parse(
  readFileSync(new URL("../../../protocols/specs/errors/error-model-503.json", import.meta.url), "utf8"),
);

describe("HelmApiError", () => {
  it("reads the HELM error model", () => {
    const err = new HelmApiError(503, vector);
    expect(err.message).toBe("emergency-stop fence active");
    expect(err.reasonCode).toBe("EMERGENCY_STOP_FENCED");
    expect(err.code).toBe("unavailable");
    expect(err.retryable).toBe(true);
  });
});
