import type { Story, StoryDefault } from "@ladle/react";
import { useState } from "react";
import { MenuBar, Panel, type MenuBarMenu } from "@mindburn/ui-core";

export default {
  title: "Primitives / MenuBar",
} satisfies StoryDefault;

function buildBaseMenus(onPick: (action: string) => void): readonly MenuBarMenu[] {
  return [
    {
      id: "file",
      label: "File",
      items: [
        { id: "new", label: "New policy", shortcut: "⌘N", onSelect: () => onPick("File ▸ New") },
        { id: "open", label: "Open…", shortcut: "⌘O", onSelect: () => onPick("File ▸ Open") },
        { id: "save", label: "Save", shortcut: "⌘S", onSelect: () => onPick("File ▸ Save") },
        { id: "close", label: "Close window", disabled: true },
      ],
    },
    {
      id: "edit",
      label: "Edit",
      items: [
        { id: "undo", label: "Undo", shortcut: "⌘Z", onSelect: () => onPick("Edit ▸ Undo") },
        { id: "redo", label: "Redo", shortcut: "⇧⌘Z", onSelect: () => onPick("Edit ▸ Redo") },
        { id: "find", label: "Find…", shortcut: "⌘F", onSelect: () => onPick("Edit ▸ Find") },
      ],
    },
    {
      id: "view",
      label: "View",
      items: [
        { id: "compact", label: "Compact density", onSelect: () => onPick("View ▸ Compact") },
        { id: "comfy", label: "Comfortable density", onSelect: () => onPick("View ▸ Comfortable") },
      ],
    },
  ];
}

function buildMenusWithSubmenu(onPick: (action: string) => void): readonly MenuBarMenu[] {
  return [
    {
      id: "file",
      label: "File",
      items: [
        { id: "new", label: "New policy", shortcut: "⌘N", onSelect: () => onPick("File ▸ New") },
        {
          id: "export",
          label: "Export",
          submenu: [
            { id: "pdf", label: "as PDF", onSelect: () => onPick("Export ▸ PDF") },
            { id: "csv", label: "as CSV", onSelect: () => onPick("Export ▸ CSV") },
            { id: "json", label: "as JSON", onSelect: () => onPick("Export ▸ JSON") },
          ],
        },
        {
          id: "share",
          label: "Share",
          submenu: [
            { id: "link", label: "Copy link", onSelect: () => onPick("Share ▸ Link") },
            { id: "email", label: "Email policy", onSelect: () => onPick("Share ▸ Email") },
          ],
        },
        {
          id: "delete",
          label: "Delete policy",
          destructive: true,
          onSelect: () => onPick("File ▸ Delete"),
        },
      ],
    },
  ];
}

export const FileEditView: Story = () => {
  const [last, setLast] = useState<string | null>(null);
  return (
    <Panel title="MenuBar" kicker={last ? `Last action: ${last}` : "Click a menu to open."}>
      <MenuBar label="App menu" menus={buildBaseMenus(setLast)} />
    </Panel>
  );
};

export const WithShortcuts: Story = () => (
  <Panel title="MenuBar" kicker="Each item exposes its keyboard shortcut as a <kbd>.">
    <MenuBar label="App menu" menus={buildBaseMenus(() => {})} />
  </Panel>
);

export const NestedSubmenu: Story = () => {
  const [last, setLast] = useState<string | null>(null);
  return (
    <Panel
      title="MenuBar with submenus"
      kicker={last ? `Last action: ${last}` : "Hover or arrow into Export to see the nested submenu."}
    >
      <MenuBar label="Document menu" menus={buildMenusWithSubmenu(setLast)} />
    </Panel>
  );
};
