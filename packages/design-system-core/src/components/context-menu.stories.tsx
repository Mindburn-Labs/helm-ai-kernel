import type { Story, StoryDefault } from "@ladle/react";
import { useState } from "react";
import { ContextMenu, Panel, type MenuItem } from "@mindburn/ui-core";

export default {
  title: "Primitives / ContextMenu",
} satisfies StoryDefault;

function buildItems(onPick: (action: string) => void): readonly MenuItem[] {
  return [
    { id: "copy", label: "Copy id", onSelect: () => onPick("copy") },
    { id: "open", label: "Open in proof view", onSelect: () => onPick("open") },
    { id: "archive", label: "Archive", disabled: true, onSelect: () => onPick("archive") },
    { id: "revoke", label: "Revoke access", onSelect: () => onPick("revoke") },
    { id: "delete", label: "Delete", onSelect: () => onPick("delete") },
  ];
}

function Demo({ disabled = false }: { readonly disabled?: boolean }) {
  const [last, setLast] = useState<string | null>(null);
  return (
    <Panel
      title="Right-click anywhere in the panel"
      kicker="Or focus and press Shift+F10 to open at the trigger rect."
    >
      <ContextMenu items={buildItems(setLast)} disabled={disabled}>
        <div
          tabIndex={0}
          style={{
            border: "1px dashed var(--helm-border-strong)",
            borderRadius: 8,
            padding: 24,
            minBlockSize: 120,
            display: "grid",
            placeItems: "center",
            outline: "none",
          }}
        >
          {last ? `Last action: ${last}` : "Right-click here"}
        </div>
      </ContextMenu>
    </Panel>
  );
}

export const Default: Story = () => <Demo />;

export const Disabled: Story = () => <Demo disabled />;
