import { act, render, renderHook, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { AnnounceProvider, useAnnounce } from "./announce";

describe("AnnounceProvider", () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("renders polite + assertive live regions wrapping children", () => {
    render(
      <AnnounceProvider>
        <span data-testid="child">child</span>
      </AnnounceProvider>,
    );
    expect(screen.getByTestId("child")).toBeInTheDocument();
    const polite = document.querySelector('[aria-live="polite"]');
    const assertive = document.querySelector('[aria-live="assertive"]');
    expect(polite).not.toBeNull();
    expect(assertive).not.toBeNull();
  });

  it("announce() pushes to the polite region and auto-clears after 1.5s", () => {
    function Probe() {
      const ann = useAnnounce();
      return (
        <button type="button" onClick={() => ann?.announce("Filter applied, 3 results")}>
          push
        </button>
      );
    }
    const { container } = render(
      <AnnounceProvider>
        <Probe />
      </AnnounceProvider>,
    );
    act(() => screen.getByRole("button").click());
    const polite = container.querySelector('[aria-live="polite"]');
    expect(polite?.textContent).toBe("Filter applied, 3 results");
    act(() => {
      vi.advanceTimersByTime(1500);
    });
    expect(polite?.textContent).toBe("");
  });

  it("announceUrgent() pushes to the assertive region", () => {
    function Probe() {
      const ann = useAnnounce();
      return (
        <button type="button" onClick={() => ann?.announceUrgent("Action denied")}>
          push
        </button>
      );
    }
    const { container } = render(
      <AnnounceProvider>
        <Probe />
      </AnnounceProvider>,
    );
    act(() => screen.getByRole("button").click());
    const assertive = container.querySelector('[aria-live="assertive"]');
    expect(assertive?.textContent).toBe("Action denied");
  });

  it("identical message re-announces by bumping the data-nonce", () => {
    function Probe() {
      const ann = useAnnounce();
      return (
        <button type="button" onClick={() => ann?.announce("Saved")}>
          push
        </button>
      );
    }
    const { container } = render(
      <AnnounceProvider>
        <Probe />
      </AnnounceProvider>,
    );
    const polite = container.querySelector('[aria-live="polite"]');
    act(() => screen.getByRole("button").click());
    const firstNonce = polite?.getAttribute("data-nonce");
    act(() => {
      vi.advanceTimersByTime(1500);
    });
    act(() => screen.getByRole("button").click());
    const secondNonce = polite?.getAttribute("data-nonce");
    expect(secondNonce).not.toBe(firstNonce);
  });

  it("ignores empty messages", () => {
    function Probe() {
      const ann = useAnnounce();
      return (
        <button type="button" onClick={() => ann?.announce("")}>
          push
        </button>
      );
    }
    const { container } = render(
      <AnnounceProvider>
        <Probe />
      </AnnounceProvider>,
    );
    act(() => screen.getByRole("button").click());
    const polite = container.querySelector('[aria-live="polite"]');
    expect(polite?.textContent).toBe("");
  });

  it("useAnnounce returns null outside AnnounceProvider", () => {
    const { result } = renderHook(() => useAnnounce());
    expect(result.current).toBeNull();
  });
});
