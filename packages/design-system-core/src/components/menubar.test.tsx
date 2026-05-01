import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { MenuBar, type MenuBarMenu } from "./menubar";

function buildMenus(handlers?: {
  newDoc?: () => void;
  openDoc?: () => void;
  exportPdf?: () => void;
}): readonly MenuBarMenu[] {
  return [
    {
      id: "file",
      label: "File",
      items: [
        { id: "new", label: "New", onSelect: handlers?.newDoc, shortcut: "⌘N" },
        { id: "open", label: "Open…", onSelect: handlers?.openDoc, shortcut: "⌘O" },
        {
          id: "export",
          label: "Export",
          submenu: [
            { id: "pdf", label: "as PDF", onSelect: handlers?.exportPdf },
            { id: "csv", label: "as CSV" },
          ],
        },
        { id: "close", label: "Close window", disabled: true },
      ],
    },
    {
      id: "edit",
      label: "Edit",
      items: [
        { id: "undo", label: "Undo", shortcut: "⌘Z" },
        { id: "redo", label: "Redo", shortcut: "⇧⌘Z" },
      ],
    },
    {
      id: "view",
      label: "View",
      items: [
        { id: "zoom-in", label: "Zoom in" },
        { id: "delete-doc", label: "Delete document", destructive: true },
      ],
    },
  ];
}

describe("MenuBar", () => {
  it("renders all top-level triggers as menuitems with aria-haspopup", () => {
    render(<MenuBar label="App menu" menus={buildMenus()} />);
    const triggers = screen.getAllByRole("menuitem");
    expect(triggers).toHaveLength(3);
    triggers.forEach((trigger) => {
      expect(trigger).toHaveAttribute("aria-haspopup", "menu");
      expect(trigger).toHaveAttribute("aria-expanded", "false");
    });
  });

  it("clicking a top trigger opens its panel and reflects aria-expanded", () => {
    render(<MenuBar label="App menu" menus={buildMenus()} />);
    fireEvent.click(screen.getByText("File"));
    expect(screen.getByText("File")).toHaveAttribute("aria-expanded", "true");
    expect(screen.getByText("New")).toBeInTheDocument();
  });

  it("activates a leaf item via Enter and closes the menu", () => {
    const onNew = vi.fn();
    render(<MenuBar label="App menu" menus={buildMenus({ newDoc: onNew })} />);
    fireEvent.click(screen.getByText("File"));
    const panel = screen.getAllByRole("menu")[0]!;
    fireEvent.keyDown(panel, { key: "Enter" });
    expect(onNew).toHaveBeenCalledTimes(1);
    expect(screen.queryByText("New")).toBeNull();
  });

  it("ArrowDown / ArrowUp / Home / End cycle the active item", () => {
    render(<MenuBar label="App menu" menus={buildMenus()} />);
    fireEvent.click(screen.getByText("File"));
    const panel = screen.getAllByRole("menu")[0]!;
    fireEvent.keyDown(panel, { key: "ArrowDown" });
    fireEvent.keyDown(panel, { key: "ArrowDown" });
    let items = screen.getAllByRole("menuitem").filter((el) => el.closest(".menubar-panel"));
    expect(items[2]).toHaveAttribute("data-active", "true");
    fireEvent.keyDown(panel, { key: "Home" });
    items = screen.getAllByRole("menuitem").filter((el) => el.closest(".menubar-panel"));
    expect(items[0]).toHaveAttribute("data-active", "true");
    fireEvent.keyDown(panel, { key: "End" });
    items = screen.getAllByRole("menuitem").filter((el) => el.closest(".menubar-panel"));
    expect(items[items.length - 1]).toHaveAttribute("data-active", "true");
  });

  it("clicking an item with a submenu opens the submenu", () => {
    render(<MenuBar label="App menu" menus={buildMenus()} />);
    fireEvent.click(screen.getByText("File"));
    fireEvent.click(screen.getByText("Export"));
    expect(screen.getByText("as PDF")).toBeInTheDocument();
  });

  it("ArrowLeft inside a submenu closes the submenu", () => {
    render(<MenuBar label="App menu" menus={buildMenus()} />);
    fireEvent.click(screen.getByText("File"));
    fireEvent.click(screen.getByText("Export"));
    const submenu = screen.getAllByRole("menu")[1]!;
    fireEvent.keyDown(submenu, { key: "ArrowLeft" });
    expect(screen.queryByText("as PDF")).toBeNull();
  });

  it("clicking a submenu item activates it and closes the menubar", () => {
    const onExport = vi.fn();
    render(<MenuBar label="App menu" menus={buildMenus({ exportPdf: onExport })} />);
    fireEvent.click(screen.getByText("File"));
    fireEvent.click(screen.getByText("Export"));
    fireEvent.click(screen.getByText("as PDF"));
    expect(onExport).toHaveBeenCalledTimes(1);
    expect(screen.queryByRole("menu")).toBeNull();
  });

  it("Escape closes the entire menubar", () => {
    render(<MenuBar label="App menu" menus={buildMenus()} />);
    fireEvent.click(screen.getByText("File"));
    const panel = screen.getAllByRole("menu")[0]!;
    fireEvent.keyDown(panel, { key: "Escape" });
    expect(screen.queryByRole("menu")).toBeNull();
  });

  it("clicking outside closes the menubar", () => {
    render(
      <div>
        <MenuBar label="App menu" menus={buildMenus()} />
        <button data-testid="outside" type="button">
          outside
        </button>
      </div>,
    );
    fireEvent.click(screen.getByText("File"));
    expect(screen.getByText("New")).toBeInTheDocument();
    fireEvent.mouseDown(screen.getByTestId("outside"));
    expect(screen.queryByText("New")).toBeNull();
  });

  it("disabled items expose aria-disabled and ignore click activation", () => {
    const onSelect = vi.fn();
    const menus = [
      {
        id: "file",
        label: "File",
        items: [{ id: "close", label: "Close window", disabled: true, onSelect }],
      },
    ] as const;
    render(<MenuBar label="App menu" menus={menus} />);
    fireEvent.click(screen.getByText("File"));
    const closeItem = screen.getByRole("menuitem", { name: /Close window/ });
    expect(closeItem).toHaveAttribute("aria-disabled", "true");
    fireEvent.click(closeItem);
    expect(onSelect).not.toHaveBeenCalled();
  });

  it("emits onOpenChange on open and close", () => {
    const onOpenChange = vi.fn();
    render(<MenuBar label="App menu" menus={buildMenus()} onOpenChange={onOpenChange} />);
    fireEvent.click(screen.getByText("File"));
    fireEvent.click(screen.getByText("File"));
    expect(onOpenChange).toHaveBeenNthCalledWith(1, "file");
    expect(onOpenChange).toHaveBeenNthCalledWith(2, null);
  });
});
