import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { ContextMenu } from "./context-menu";
import type { MenuItem } from "./primitives";

function buildItems(handlers?: { copy?: () => void; rename?: () => void }) {
  return [
    { id: "copy", label: "Copy", onSelect: handlers?.copy },
    { id: "rename", label: "Rename", onSelect: handlers?.rename },
    { id: "archive", label: "Archive", disabled: true },
    { id: "delete", label: "Delete" },
  ] as readonly MenuItem[];
}

describe("ContextMenu", () => {
  it("opens at cursor coordinates on contextmenu and renders menuitems", () => {
    render(
      <ContextMenu items={buildItems()}>
        <div data-testid="region">right-click me</div>
      </ContextMenu>,
    );
    expect(screen.queryByRole("menu")).toBeNull();
    fireEvent.contextMenu(screen.getByTestId("region"), { clientX: 150, clientY: 80 });
    const menu = screen.getByRole("menu") as HTMLElement;
    expect(menu).toBeInTheDocument();
    expect(menu.style.insetInlineStart).toBe("150px");
    expect(menu.style.insetBlockStart).toBe("80px");
    expect(screen.getAllByRole("menuitem")).toHaveLength(4);
  });

  it("Shift+F10 opens at the trigger element rect", () => {
    render(
      <ContextMenu items={buildItems()}>
        <div data-testid="region">trigger</div>
      </ContextMenu>,
    );
    const region = screen.getByTestId("region").parentElement!;
    fireEvent.keyDown(region, { key: "F10", shiftKey: true });
    expect(screen.getByRole("menu")).toBeInTheDocument();
  });

  it("ArrowDown / ArrowUp / Home / End cycle the active item", () => {
    render(
      <ContextMenu items={buildItems()}>
        <div data-testid="region">trigger</div>
      </ContextMenu>,
    );
    fireEvent.contextMenu(screen.getByTestId("region"));
    fireEvent.keyDown(document, { key: "ArrowDown" });
    fireEvent.keyDown(document, { key: "ArrowDown" });
    let items = screen.getAllByRole("menuitem");
    expect(items[2]).toHaveAttribute("data-active", "true");
    fireEvent.keyDown(document, { key: "Home" });
    items = screen.getAllByRole("menuitem");
    expect(items[0]).toHaveAttribute("data-active", "true");
    fireEvent.keyDown(document, { key: "End" });
    items = screen.getAllByRole("menuitem");
    expect(items[3]).toHaveAttribute("data-active", "true");
    fireEvent.keyDown(document, { key: "ArrowUp" });
    items = screen.getAllByRole("menuitem");
    expect(items[2]).toHaveAttribute("data-active", "true");
  });

  it("Enter activates the active item and closes the menu", () => {
    const onCopy = vi.fn();
    render(
      <ContextMenu items={buildItems({ copy: onCopy })}>
        <div data-testid="region">trigger</div>
      </ContextMenu>,
    );
    fireEvent.contextMenu(screen.getByTestId("region"));
    fireEvent.keyDown(document, { key: "Enter" });
    expect(onCopy).toHaveBeenCalledTimes(1);
    expect(screen.queryByRole("menu")).toBeNull();
  });

  it("Escape closes the menu without activating", () => {
    const onCopy = vi.fn();
    render(
      <ContextMenu items={buildItems({ copy: onCopy })}>
        <div data-testid="region">trigger</div>
      </ContextMenu>,
    );
    fireEvent.contextMenu(screen.getByTestId("region"));
    fireEvent.keyDown(document, { key: "Escape" });
    expect(onCopy).not.toHaveBeenCalled();
    expect(screen.queryByRole("menu")).toBeNull();
  });

  it("clicking outside the menu closes it", () => {
    render(
      <div>
        <ContextMenu items={buildItems()}>
          <div data-testid="region">trigger</div>
        </ContextMenu>
        <button type="button" data-testid="outside">
          outside
        </button>
      </div>,
    );
    fireEvent.contextMenu(screen.getByTestId("region"));
    expect(screen.getByRole("menu")).toBeInTheDocument();
    fireEvent.mouseDown(screen.getByTestId("outside"));
    expect(screen.queryByRole("menu")).toBeNull();
  });

  it("disabled items are aria-disabled and do not close the menu when clicked", () => {
    render(
      <ContextMenu items={buildItems()}>
        <div data-testid="region">trigger</div>
      </ContextMenu>,
    );
    fireEvent.contextMenu(screen.getByTestId("region"));
    const archive = screen.getByRole("menuitem", { name: "Archive" });
    expect(archive).toHaveAttribute("aria-disabled", "true");
    fireEvent.click(archive);
    expect(screen.getByRole("menu")).toBeInTheDocument();
  });

  it("does not open when disabled prop is set", () => {
    render(
      <ContextMenu items={buildItems()} disabled>
        <div data-testid="region">trigger</div>
      </ContextMenu>,
    );
    fireEvent.contextMenu(screen.getByTestId("region"));
    expect(screen.queryByRole("menu")).toBeNull();
  });

  it("invokes onOpenChange on open and close", () => {
    const onOpenChange = vi.fn();
    render(
      <ContextMenu items={buildItems()} onOpenChange={onOpenChange}>
        <div data-testid="region">trigger</div>
      </ContextMenu>,
    );
    fireEvent.contextMenu(screen.getByTestId("region"));
    fireEvent.keyDown(document, { key: "Escape" });
    expect(onOpenChange).toHaveBeenNthCalledWith(1, true);
    expect(onOpenChange).toHaveBeenNthCalledWith(2, false);
  });
});
