import type { Story, StoryDefault } from "@ladle/react";
import { useState } from "react";
import {
  Button,
  Panel,
  TelemetryProvider,
  useTelemetry,
  useTelemetryMount,
  type TelemetryEvent,
} from "@helm/design-system-core";

export default {
  title: "Providers / TelemetryProvider",
} satisfies StoryDefault;

function TelemetryConsumer() {
  const { emit } = useTelemetry();
  useTelemetryMount("TelemetryDemo", { route: "stories/telemetry" });
  return (
    <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
      <Button size="sm" onClick={() => emit("policy.approved", { id: "P-104" })}>
        Approve P-104
      </Button>
      <Button
        size="sm"
        variant="danger"
        onClick={() => emit("policy.denied", { id: "P-105", reason: "missing-evidence" })}
      >
        Deny P-105
      </Button>
      <Button
        size="sm"
        variant="ghost"
        onClick={() => emit("filter.applied", { count: 12, query: "owner=core" })}
      >
        Apply filter
      </Button>
    </div>
  );
}

function VisibleSinkDemo() {
  const [events, setEvents] = useState<TelemetryEvent[]>([]);
  const sink = (event: TelemetryEvent) => setEvents((es) => [event, ...es].slice(0, 12));
  return (
    <TelemetryProvider sink={sink} debug>
      <Panel title="Telemetry log" kicker="Click any button below; the sink streams events here.">
        <div style={{ display: "grid", gap: 12 }}>
          <TelemetryConsumer />
          <ul
            style={{
              margin: 0,
              paddingInlineStart: 18,
              fontFamily: "var(--helm-font-mono)",
              fontSize: 12,
            }}
          >
            {events.map((event) => (
              <li key={event.ts}>
                <strong>{event.name}</strong> @ {new Date(event.ts).toISOString().slice(11, 19)} ·{" "}
                {JSON.stringify(event.props ?? {})}
              </li>
            ))}
          </ul>
        </div>
      </Panel>
    </TelemetryProvider>
  );
}

export const Default: Story = () => <VisibleSinkDemo />;

export const NoOpOutsideProvider: Story = () => (
  <Panel title="Outside provider" kicker="emit() is a no-op; nothing is logged.">
    <TelemetryConsumer />
  </Panel>
);
