import { afterEach, describe, expect, it, vi } from "vitest";
import { assertRailPresent } from "./rail-guard";

afterEach(() => {
  vi.restoreAllMocks();
});

describe("assertRailPresent", () => {
  it("warns when a verdict-bearing state lacks a rail", () => {
    const spy = vi.spyOn(console, "warn").mockImplementation(() => {});
    assertRailPresent("deny", false, "ApprovalQueueItem");
    expect(spy).toHaveBeenCalledTimes(1);
    expect(spy.mock.calls[0]?.[0]).toMatch(/deny/);
    expect(spy.mock.calls[0]?.[0]).toMatch(/ApprovalQueueItem/);
  });

  it("stays silent when the rail is present", () => {
    const spy = vi.spyOn(console, "warn").mockImplementation(() => {});
    assertRailPresent("deny", true, "ApprovalQueueItem");
    expect(spy).not.toHaveBeenCalled();
  });

  it("stays silent for states that don't require a rail", () => {
    const spy = vi.spyOn(console, "warn").mockImplementation(() => {});
    assertRailPresent("pending", false, "MetricTile");
    expect(spy).not.toHaveBeenCalled();
  });

  it("warns for failed verification when rail missing", () => {
    const spy = vi.spyOn(console, "warn").mockImplementation(() => {});
    assertRailPresent("failed", false, "VerificationStatus");
    expect(spy).toHaveBeenCalledTimes(1);
    expect(spy.mock.calls[0]?.[0]).toMatch(/failed/);
  });
});
