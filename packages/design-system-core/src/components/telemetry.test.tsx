import { act, render, renderHook } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { TelemetryProvider, useTelemetry, useTelemetryMount } from "./telemetry";

describe("TelemetryProvider", () => {
  beforeEach(() => {
    vi.spyOn(console, "debug").mockImplementation(() => {});
    vi.spyOn(console, "error").mockImplementation(() => {});
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("emit() calls the sink with { name, props, ts }", () => {
    const sink = vi.fn();
    function Probe() {
      const { emit } = useTelemetry();
      return (
        <button type="button" onClick={() => emit("button.click", { variant: "primary" })}>
          push
        </button>
      );
    }
    const { getByRole } = render(
      <TelemetryProvider sink={sink}>
        <Probe />
      </TelemetryProvider>,
    );
    act(() => getByRole("button").click());
    expect(sink).toHaveBeenCalledTimes(1);
    const event = sink.mock.calls[0]?.[0];
    expect(event.name).toBe("button.click");
    expect(event.props).toEqual({ variant: "primary" });
    expect(typeof event.ts).toBe("number");
  });

  it("sink errors do not propagate to consumers (debug logs them)", () => {
    const failingSink = vi.fn(() => {
      throw new Error("sink boom");
    });
    function Probe() {
      const { emit } = useTelemetry();
      return (
        <button type="button" onClick={() => emit("test.event")}>
          push
        </button>
      );
    }
    const { getByRole } = render(
      <TelemetryProvider sink={failingSink} debug>
        <Probe />
      </TelemetryProvider>,
    );
    expect(() => act(() => getByRole("button").click())).not.toThrow();
    expect(failingSink).toHaveBeenCalled();
    expect(console.error).toHaveBeenCalled();
  });

  it("debug=true console.debugs every event", () => {
    const sink = vi.fn();
    function Probe() {
      const { emit } = useTelemetry();
      return (
        <button type="button" onClick={() => emit("test.event")}>
          push
        </button>
      );
    }
    const { getByRole } = render(
      <TelemetryProvider sink={sink} debug>
        <Probe />
      </TelemetryProvider>,
    );
    act(() => getByRole("button").click());
    expect(console.debug).toHaveBeenCalledWith(
      "[helm-telemetry]",
      expect.objectContaining({ name: "test.event" }),
    );
  });

  it("useTelemetry outside provider returns a NOOP emit (no throw)", () => {
    const { result } = renderHook(() => useTelemetry());
    expect(typeof result.current.emit).toBe("function");
    expect(() => result.current.emit("noop.event")).not.toThrow();
  });

  it("useTelemetryMount fires once on mount via rAF", () => {
    const sink = vi.fn();
    let rafCb: FrameRequestCallback | null = null;
    vi.spyOn(window, "requestAnimationFrame").mockImplementation((cb) => {
      rafCb = cb;
      return 1;
    });
    vi.spyOn(window, "cancelAnimationFrame").mockImplementation(() => {});
    function Probe() {
      useTelemetryMount("Probe", { foo: "bar" });
      return <span data-testid="probe" />;
    }
    render(
      <TelemetryProvider sink={sink}>
        <Probe />
      </TelemetryProvider>,
    );
    act(() => {
      rafCb?.(0);
    });
    expect(sink).toHaveBeenCalledTimes(1);
    const event = sink.mock.calls[0]?.[0];
    expect(event.name).toBe("Probe.mount");
    expect(event.props).toEqual({ foo: "bar" });
  });
});
