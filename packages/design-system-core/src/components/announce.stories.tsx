import type { Story, StoryDefault } from "@ladle/react";
import { useState } from "react";
import { AnnounceProvider, Button, Panel, useAnnounce } from "@mindburn/ui-core";

export default {
  title: "Providers / AnnounceProvider",
} satisfies StoryDefault;

interface LogEntry {
  readonly id: number;
  readonly politeness: "polite" | "assertive";
  readonly message: string;
}

function AnnounceDemo() {
  const ann = useAnnounce();
  const [log, setLog] = useState<LogEntry[]>([]);
  const [next, setNext] = useState(1);

  const fire = (politeness: "polite" | "assertive", message: string) => {
    if (!ann) return;
    if (politeness === "assertive") ann.announceUrgent(message);
    else ann.announce(message);
    setLog((entries) => [{ id: next, politeness, message }, ...entries].slice(0, 8));
    setNext((n) => n + 1);
  };

  return (
    <Panel
      title="Live announcements"
      kicker="Click to push to a polite or assertive aria-live region."
    >
      <div style={{ display: "flex", gap: 8, flexWrap: "wrap", marginBlockEnd: 12 }}>
        <Button size="sm" onClick={() => fire("polite", "Filter applied — 3 matching policies")}>
          Polite: filter applied
        </Button>
        <Button size="sm" variant="secondary" onClick={() => fire("polite", "Saved")}>
          Polite: saved
        </Button>
        <Button size="sm" variant="danger" onClick={() => fire("assertive", "Action denied")}>
          Assertive: denied
        </Button>
      </div>
      <ul style={{ margin: 0, paddingInlineStart: 18, fontFamily: "var(--helm-font-mono)" }}>
        {log.map((entry) => (
          <li key={entry.id}>
            <strong>{entry.politeness}</strong> · {entry.message}
          </li>
        ))}
      </ul>
    </Panel>
  );
}

export const Default: Story = () => (
  <AnnounceProvider>
    <AnnounceDemo />
  </AnnounceProvider>
);

export const NotWrapped: Story = () => <AnnounceDemo />;
