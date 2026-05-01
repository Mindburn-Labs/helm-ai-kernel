import { act, fireEvent, render, screen, within } from "@testing-library/react";
import { useState } from "react";
import { describe, expect, it, vi } from "vitest";
import {
  ActionRecordTable,
  AlertDialog,
  Badge,
  Button,
  CommandPalette,
  Dialog,
  ErrorBoundary,
  StatusRow,
  ToastProvider,
  Toaster,
  VerdictBadge,
  useToast,
  type ActionRecord,
  type CommandPaletteItem,
} from "./core";
import { actionRecords } from "../test/records";

describe("core components", () => {
  it("renders verdicts with text and rail semantics", () => {
    render(<VerdictBadge state="deny" />);
    expect(screen.getByText("DENY")).toBeInTheDocument();
    expect(screen.getByLabelText(/Verdict DENY/i)).toBeInTheDocument();
  });

  it("renders all canonical action columns", () => {
    render(<ActionRecordTable records={actionRecords.slice(0, 1)} />);
    for (const heading of ["Timestamp", "Agent", "Action", "Target", "Environment", "Risk", "Policy", "Verdict", "Receipt", "Verification", "Actions"]) {
      expect(screen.getByRole("columnheader", { name: heading })).toBeInTheDocument();
    }
  });

  it("keeps long operational copy outside the semantic badge", () => {
    render(<StatusRow state="verified" label="No hard-coded colors outside token definitions." detail="CI gate" />);

    expect(screen.getByText("VERIFIED")).toHaveClass("helm-badge");
    expect(screen.getByText("No hard-coded colors outside token definitions.")).toHaveClass("status-label");
  });
});

describe("ActionRecordTable virtualization", () => {
  function makeRecords(count: number): readonly ActionRecord[] {
    const seed = actionRecords[0];
    if (!seed) throw new Error("actionRecords fixture is empty");
    return Array.from({ length: count }, (_, index) => ({ ...seed, id: `record-${index}` }));
  }

  it("renders all rows when below virtualization threshold", () => {
    render(<ActionRecordTable records={makeRecords(20)} />);
    expect(screen.getAllByRole("row")).toHaveLength(20 + 1);
    expect(screen.queryByRole("button", { name: /Show all/i })).not.toBeInTheDocument();
  });

  it("renders sentinel and Show all when over threshold", () => {
    render(<ActionRecordTable records={makeRecords(150)} />);
    expect(screen.getAllByRole("row").length).toBeLessThan(150 + 1);
    expect(screen.getByRole("button", { name: /Show all/i })).toBeInTheDocument();
    expect(screen.getByText(/Showing 100 of 150 records/)).toBeInTheDocument();
  });

  it("Show all expands to the full list", () => {
    render(<ActionRecordTable records={makeRecords(120)} />);
    fireEvent.click(screen.getByRole("button", { name: /Show all/i }));
    expect(screen.getAllByRole("row")).toHaveLength(120 + 1);
    expect(screen.queryByRole("button", { name: /Show all/i })).not.toBeInTheDocument();
  });
});

describe("CommandPalette filter", () => {
  const items: readonly CommandPaletteItem[] = [
    { id: "policy-1", kind: "policy", label: "finance.transfer.threshold.v3" },
    { id: "agent-1", kind: "agent", label: "agent.finance.reconcile" },
  ];

  it("trims whitespace before filtering", () => {
    render(<CommandPalette open items={items} onClose={() => {}} onSelect={() => {}} />);
    const input = screen.getByRole("combobox") as HTMLInputElement;
    fireEvent.change(input, { target: { value: "  policy  " } });
    expect(screen.getByRole("option", { name: /finance\.transfer\.threshold/i })).toBeInTheDocument();
    expect(screen.queryByRole("option", { name: /agent\.finance\.reconcile/i })).not.toBeInTheDocument();
  });

  it("returns the full set on whitespace-only query", () => {
    render(<CommandPalette open items={items} onClose={() => {}} onSelect={() => {}} />);
    const input = screen.getByRole("combobox") as HTMLInputElement;
    fireEvent.change(input, { target: { value: "   " } });
    expect(screen.getAllByRole("option")).toHaveLength(items.length);
  });
});

describe("ErrorBoundary", () => {
  function Throw(): React.JSX.Element {
    throw new Error("boom");
  }

  it("renders fallback on render error and resets when triggered", () => {
    const errorSpy = vi.spyOn(console, "error").mockImplementation(() => {});
    function Harness() {
      const [throwing, setThrowing] = useState(true);
      return (
        <ErrorBoundary
          fallback={(error, reset) => (
            <div>
              <p>caught: {error.message}</p>
              <button
                type="button"
                onClick={() => {
                  setThrowing(false);
                  reset();
                }}
              >
                recover
              </button>
            </div>
          )}
        >
          {throwing ? <Throw /> : <span>recovered</span>}
        </ErrorBoundary>
      );
    }
    render(<Harness />);
    expect(screen.getByText(/caught: boom/)).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "recover" }));
    expect(screen.getByText("recovered")).toBeInTheDocument();
    errorSpy.mockRestore();
  });
});

describe("ToastProvider + useToast + Toaster", () => {
  function Harness() {
    const toast = useToast();
    return (
      <button type="button" onClick={() => toast.push({ title: "Verified", detail: "Receipt sealed" })}>
        push
      </button>
    );
  }

  it("renders pushed toasts inside the aria-live region", () => {
    render(
      <ToastProvider>
        <Harness />
        <Toaster />
      </ToastProvider>,
    );
    const region = screen.getByRole("region", { name: "Notifications" });
    expect(region).toHaveAttribute("aria-live", "polite");
    expect(within(region).queryByText("Verified")).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "push" }));
    expect(within(region).getByText("Verified")).toBeInTheDocument();
    expect(within(region).getByText("Receipt sealed")).toBeInTheDocument();
  });

  it("dismiss button removes the toast", () => {
    render(
      <ToastProvider>
        <Harness />
        <Toaster />
      </ToastProvider>,
    );
    fireEvent.click(screen.getByRole("button", { name: "push" }));
    fireEvent.click(screen.getByRole("button", { name: /Dismiss notification/i }));
    expect(screen.queryByText("Verified")).not.toBeInTheDocument();
  });

  it("auto-dismisses after the configured duration", () => {
    vi.useFakeTimers();
    function Pusher() {
      const toast = useToast();
      return (
        <button type="button" onClick={() => toast.push({ title: "Quick", duration: 100 })}>
          push
        </button>
      );
    }
    render(
      <ToastProvider>
        <Pusher />
        <Toaster />
      </ToastProvider>,
    );
    fireEvent.click(screen.getByRole("button", { name: "push" }));
    expect(screen.getByText("Quick")).toBeInTheDocument();
    act(() => {
      vi.advanceTimersByTime(150);
    });
    expect(screen.queryByText("Quick")).not.toBeInTheDocument();
    vi.useRealTimers();
  });
});

describe("Dialog", () => {
  it("renders title + description with aria wiring and labels the dialog", () => {
    render(
      <Dialog open title="Confirm rollout" description="The change ships to production." onClose={() => {}}>
        <p>Body content.</p>
      </Dialog>,
    );
    const dialog = screen.getByRole("dialog", { name: "Confirm rollout" });
    expect(dialog).toHaveAttribute("aria-modal", "true");
    expect(dialog).toHaveAccessibleDescription("The change ships to production.");
  });

  it("dismisses on Escape", () => {
    const onClose = vi.fn();
    render(
      <Dialog open title="Confirm rollout" onClose={onClose}>
        <p>Body</p>
      </Dialog>,
    );
    fireEvent.keyDown(document, { key: "Escape" });
    expect(onClose).toHaveBeenCalledTimes(1);
  });

  it("dismisses on backdrop click by default and ignores it when closeOnBackdrop is false", () => {
    const onCloseDefault = vi.fn();
    const { unmount } = render(
      <Dialog open title="Default" onClose={onCloseDefault}>
        <p>Body</p>
      </Dialog>,
    );
    fireEvent.mouseDown(document.querySelector(".dialog-backdrop") as HTMLElement);
    expect(onCloseDefault).toHaveBeenCalledTimes(1);
    unmount();

    const onCloseLocked = vi.fn();
    render(
      <Dialog open title="Locked" onClose={onCloseLocked} closeOnBackdrop={false}>
        <p>Body</p>
      </Dialog>,
    );
    fireEvent.mouseDown(document.querySelector(".dialog-backdrop") as HTMLElement);
    expect(onCloseLocked).not.toHaveBeenCalled();
  });
});

describe("AlertDialog", () => {
  it("uses role=alertdialog and routes the explicit buttons", () => {
    const onConfirm = vi.fn();
    const onCancel = vi.fn();
    render(
      <AlertDialog
        open
        title="Permanently revoke?"
        description="This cannot be undone."
        confirmLabel="Revoke"
        intent="deny"
        onConfirm={onConfirm}
        onCancel={onCancel}
      />,
    );
    expect(screen.getByRole("alertdialog", { name: /Permanently revoke/ })).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: /Cancel/ }));
    expect(onCancel).toHaveBeenCalledTimes(1);
    fireEvent.click(screen.getByRole("button", { name: /Revoke/ }));
    expect(onConfirm).toHaveBeenCalledTimes(1);
  });

  it("disables both buttons when busy", () => {
    render(
      <AlertDialog
        open
        title="Submitting"
        description="Please wait."
        confirmLabel="Confirm"
        onConfirm={() => {}}
        onCancel={() => {}}
        busy
      />,
    );
    expect(screen.getByRole("button", { name: /Cancel/ })).toBeDisabled();
    expect(screen.getByRole("button", { name: /Confirm/ })).toBeDisabled();
  });
});

describe("Button asChild composition", () => {
  it("renders the child element with merged className + handlers when asChild", () => {
    const onClick = vi.fn();
    render(
      <Button asChild variant="primary" size="md" onClick={onClick}>
        <a href="/policies" className="custom-link">
          Open policies
        </a>
      </Button>,
    );
    const link = screen.getByRole("link", { name: "Open policies" });
    expect(link).toHaveAttribute("href", "/policies");
    expect(link.className).toMatch(/helm-button/);
    expect(link.className).toMatch(/helm-button--primary/);
    expect(link.className).toMatch(/custom-link/);
    fireEvent.click(link);
    expect(onClick).toHaveBeenCalledTimes(1);
  });

  it("composes onClick — slot handler runs and child handler runs too", () => {
    const slotClick = vi.fn();
    const childClick = vi.fn();
    render(
      <Button asChild onClick={slotClick}>
        <a href="#policy" onClick={childClick}>
          Composed
        </a>
      </Button>,
    );
    fireEvent.click(screen.getByRole("link", { name: "Composed" }));
    expect(slotClick).toHaveBeenCalledTimes(1);
    expect(childClick).toHaveBeenCalledTimes(1);
  });

  it("passes aria-disabled (not the disabled attribute) when disabled + asChild", () => {
    render(
      <Button asChild disabled>
        <a href="/x">Disabled link</a>
      </Button>,
    );
    const link = screen.getByRole("link", { name: "Disabled link" });
    expect(link).toHaveAttribute("aria-disabled", "true");
    expect(link).toHaveAttribute("data-disabled", "true");
    expect(link).not.toHaveAttribute("disabled");
  });
});

describe("Badge asChild composition", () => {
  it("renders the child element with helm-badge classes when asChild", () => {
    render(
      <Badge asChild state="allow" tone="proof">
        <a href="/policies">view policy</a>
      </Badge>,
    );
    const link = screen.getByRole("link", { name: "view policy" });
    expect(link).toHaveAttribute("href", "/policies");
    expect(link.className).toMatch(/helm-badge/);
    expect(link.className).toMatch(/badge-tone--proof/);
    expect(link.className).toMatch(/rail-text--allow/);
  });
});
