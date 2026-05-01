import { fireEvent, render, screen, within } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { CodeBlock, DiffViewer, Tree, type DiffHunk, type TreeNode } from "./inspect";
import { ToastProvider, Toaster } from "./core";

describe("DiffViewer", () => {
  const hunks: readonly DiffHunk[] = [
    { kind: "context", content: "agent.ops.release", oldLine: 1, newLine: 1 },
    { kind: "remove", content: "old.value: false", oldLine: 2 },
    { kind: "add", content: "cloudflare.zone.routing.enabled", newLine: 2 },
  ];

  it("renders rows with kind-specific classes and prefix markers", () => {
    const { container } = render(<DiffViewer hunks={hunks} ariaLabel="Test diff" />);
    const rows = container.querySelectorAll(".diff-row");
    expect(rows).toHaveLength(3);
    expect(rows[0]).toHaveClass("diff-row--context");
    expect(rows[1]).toHaveClass("diff-row--remove");
    expect(rows[2]).toHaveClass("diff-row--add");
    const markers = container.querySelectorAll(".diff-marker");
    expect(markers[1]).toHaveTextContent("-");
    expect(markers[2]).toHaveTextContent("+");
  });

  it("exposes the aria-label as figure caption", () => {
    render(<DiffViewer hunks={hunks} ariaLabel="Payload diff" />);
    expect(screen.getByText("Payload diff")).toBeInTheDocument();
  });
});

describe("CodeBlock", () => {
  it("renders code with line numbers when showLineNumbers is true", () => {
    const { container } = render(
      <ToastProvider>
        <CodeBlock code={"alpha\nbeta"} showLineNumbers language="json" ariaLabel="snippet" />
        <Toaster />
      </ToastProvider>,
    );
    const gutters = container.querySelectorAll(".code-gutter");
    expect(gutters).toHaveLength(2);
    expect(gutters[0]).toHaveTextContent("1");
    expect(gutters[1]).toHaveTextContent("2");
  });

  it("toggles label to 'Code copied' after a successful copy", async () => {
    const writeText = vi.fn().mockResolvedValue(undefined);
    Object.defineProperty(navigator, "clipboard", { configurable: true, value: { writeText } });
    render(
      <ToastProvider>
        <CodeBlock code={"hi"} />
        <Toaster />
      </ToastProvider>,
    );
    fireEvent.click(screen.getByRole("button", { name: /Copy code/i }));
    await screen.findByRole("button", { name: /Code copied/i });
    expect(writeText).toHaveBeenCalledWith("hi");
  });

  it("surfaces a failure toast when clipboard rejects", async () => {
    const writeText = vi.fn().mockRejectedValue(new Error("denied by browser"));
    Object.defineProperty(navigator, "clipboard", { configurable: true, value: { writeText } });
    render(
      <ToastProvider>
        <CodeBlock code={"hi"} />
        <Toaster />
      </ToastProvider>,
    );
    fireEvent.click(screen.getByRole("button", { name: /Copy code/i }));
    expect(await screen.findByText("Could not copy code")).toBeInTheDocument();
    expect(screen.getByText("denied by browser")).toBeInTheDocument();
  });
});

describe("Tree", () => {
  const nodes: readonly TreeNode[] = [
    {
      id: "root",
      label: "ep_9f82c31a",
      defaultExpanded: true,
      children: [
        { id: "leaf-a", label: "intent.json" },
        { id: "leaf-b", label: "policy-eval.json" },
      ],
    },
    {
      id: "root-2",
      label: "ep_collapsed",
      children: [{ id: "leaf-c", label: "trace.log" }],
    },
  ];

  it("renders treeitems with aria-level for hierarchy", () => {
    render(<Tree nodes={nodes} ariaLabel="receipts" />);
    const tree = screen.getByRole("tree", { name: "receipts" });
    const items = within(tree).getAllByRole("treeitem");
    expect(items).toHaveLength(4);
    expect(items[0]).toHaveAttribute("aria-level", "1");
    expect(items[1]).toHaveAttribute("aria-level", "2");
    expect(items[2]).toHaveAttribute("aria-level", "2");
    expect(items[3]).toHaveAttribute("aria-level", "1");
  });

  it("calls onSelect when a leaf is clicked", () => {
    const onSelect = vi.fn();
    render(<Tree nodes={nodes} onSelect={onSelect} ariaLabel="receipts" />);
    fireEvent.click(screen.getByRole("treeitem", { name: /intent\.json/ }));
    expect(onSelect).toHaveBeenCalledWith("leaf-a");
  });

  it("expands and collapses with ArrowRight/ArrowLeft", () => {
    render(<Tree nodes={nodes} ariaLabel="receipts" />);
    const collapsedRoot = screen.getByRole("treeitem", { name: /ep_collapsed/ });
    expect(collapsedRoot).toHaveAttribute("aria-expanded", "false");
    fireEvent.keyDown(collapsedRoot, { key: "ArrowRight" });
    expect(collapsedRoot).toHaveAttribute("aria-expanded", "true");
    fireEvent.keyDown(collapsedRoot, { key: "ArrowLeft" });
    expect(collapsedRoot).toHaveAttribute("aria-expanded", "false");
  });

  it("moves focus down with ArrowDown and up with ArrowUp", () => {
    render(<Tree nodes={nodes} ariaLabel="receipts" />);
    const items = screen.getAllByRole("treeitem");
    items[0]?.focus();
    fireEvent.keyDown(items[0]!, { key: "ArrowDown" });
    expect(document.activeElement).toBe(items[1]);
    fireEvent.keyDown(items[1]!, { key: "ArrowUp" });
    expect(document.activeElement).toBe(items[0]);
  });
});
