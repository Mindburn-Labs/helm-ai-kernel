import { act, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { HoverCard } from "./hover-card";

describe("HoverCard", () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });
  afterEach(() => {
    vi.useRealTimers();
  });

  it("opens after the configured openDelay on mouseenter", () => {
    render(
      <HoverCard openDelay={300} closeDelay={200} trigger={<a href="#x">@ada</a>}>
        <p>Profile preview</p>
      </HoverCard>,
    );
    expect(screen.queryByText("Profile preview")).toBeNull();
    fireEvent.mouseEnter(screen.getByText("@ada"));
    expect(screen.queryByText("Profile preview")).toBeNull();
    act(() => {
      vi.advanceTimersByTime(300);
    });
    expect(screen.getByText("Profile preview")).toBeInTheDocument();
  });

  it("closes after the configured closeDelay on mouseleave", () => {
    render(
      <HoverCard defaultOpen openDelay={300} closeDelay={200} trigger={<a href="#x">@ada</a>}>
        <p>Profile preview</p>
      </HoverCard>,
    );
    expect(screen.getByText("Profile preview")).toBeInTheDocument();
    fireEvent.mouseLeave(screen.getByText("@ada"));
    act(() => {
      vi.advanceTimersByTime(199);
    });
    expect(screen.getByText("Profile preview")).toBeInTheDocument();
    act(() => {
      vi.advanceTimersByTime(1);
    });
    expect(screen.queryByText("Profile preview")).toBeNull();
  });

  it("pointer entering content cancels the close timer (no flicker across the gap)", () => {
    render(
      <HoverCard defaultOpen openDelay={300} closeDelay={200} trigger={<a href="#x">@ada</a>}>
        <p>Profile preview</p>
      </HoverCard>,
    );
    fireEvent.mouseLeave(screen.getByText("@ada"));
    act(() => {
      vi.advanceTimersByTime(100);
    });
    fireEvent.mouseEnter(screen.getByText("Profile preview"));
    act(() => {
      vi.advanceTimersByTime(500);
    });
    expect(screen.getByText("Profile preview")).toBeInTheDocument();
  });

  it("focusing the trigger opens the card; Escape closes and returns focus", () => {
    render(
      <HoverCard openDelay={100} closeDelay={100} trigger={<button>@ada</button>}>
        <p>Profile preview</p>
      </HoverCard>,
    );
    const trigger = screen.getByText("@ada").closest(".hover-card-trigger") as HTMLElement;
    trigger.focus();
    fireEvent.focus(trigger);
    act(() => {
      vi.advanceTimersByTime(100);
    });
    expect(screen.getByText("Profile preview")).toBeInTheDocument();
    fireEvent.keyDown(document, { key: "Escape" });
    expect(screen.queryByText("Profile preview")).toBeNull();
  });

  it("controlled mode honors the open prop and emits onOpenChange", () => {
    const onOpenChange = vi.fn();
    const { rerender } = render(
      <HoverCard
        open={false}
        openDelay={100}
        closeDelay={100}
        onOpenChange={onOpenChange}
        trigger={<a href="#x">@ada</a>}
      >
        <p>Profile preview</p>
      </HoverCard>,
    );
    expect(screen.queryByText("Profile preview")).toBeNull();
    fireEvent.mouseEnter(screen.getByText("@ada"));
    act(() => {
      vi.advanceTimersByTime(100);
    });
    expect(screen.queryByText("Profile preview")).toBeNull();
    expect(onOpenChange).toHaveBeenCalledWith(true);
    rerender(
      <HoverCard
        open
        openDelay={100}
        closeDelay={100}
        onOpenChange={onOpenChange}
        trigger={<a href="#x">@ada</a>}
      >
        <p>Profile preview</p>
      </HoverCard>,
    );
    expect(screen.getByText("Profile preview")).toBeInTheDocument();
  });

  it("renders data-side and data-align attributes on the root", () => {
    const { container } = render(
      <HoverCard defaultOpen side="end" align="center" trigger={<a href="#">x</a>}>
        <p>content</p>
      </HoverCard>,
    );
    const root = container.querySelector(".hover-card-root") as HTMLElement;
    expect(root.getAttribute("data-side")).toBe("end");
    expect(root.getAttribute("data-align")).toBe("center");
    expect(root.getAttribute("data-open")).toBe("true");
  });
});
